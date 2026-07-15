import Testing
import Foundation
import SallyportKit
@testable import SallyportVault

/// Drives a real VaultHost over its Unix socket — proving the whole transport
/// spine: accept → peer pid (LOCAL_PEERPID) → provenance → engine ladder → reply.
@Suite("VaultHost — control socket end to end", .serialized)
struct VaultHostTests {
    private struct AutoApprove: Approver {
        func requestApproval(_ req: EngineApproval) async -> ApprovalOutcome { .approved }
    }

    /// A tiny synchronous line-JSON client (the test analog of the sp shim).
    private func request(_ path: String, _ obj: [String: Any]) -> [String: Any]? {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var noSigPipe: Int32 = 1
        _ = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe,
                       socklen_t(MemoryLayout<Int32>.size))
        var addr = sockaddr_un(); addr.sun_family = sa_family_t(AF_UNIX)
        _ = path.withCString { src in
            withUnsafeMutablePointer(to: &addr.sun_path) {
                $0.withMemoryRebound(to: CChar.self, capacity: 104) { strncpy($0, src, 103) }
            }
        }
        let len = socklen_t(MemoryLayout<sockaddr_un>.size)
        let ok = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, len) }
        }
        guard ok == 0 else { return nil }
        var data = try! JSONSerialization.data(withJSONObject: obj); data.append(0x0A)
        _ = data.withUnsafeBytes { write(fd, $0.baseAddress, data.count) }
        var buf = [UInt8](repeating: 0, count: 65536); var acc = Data()
        while true {
            let n = read(fd, &buf, buf.count)
            if n <= 0 { return nil }
            acc.append(contentsOf: buf[0..<n])
            if let nl = acc.firstIndex(of: 0x0A) {
                return try? JSONSerialization.jsonObject(with: acc[acc.startIndex..<nl]) as? [String: Any]
            }
        }
    }

    private func buildHost(locked: Bool) async throws -> (VaultHost, String) {
        // sockaddr_un.sun_path is only 104 bytes on Darwin. The system temp
        // directory can itself be long enough that appending a UUID silently
        // exceeded that boundary (the production server now correctly rejects
        // it instead of binding a truncated alias).
        let home = URL(fileURLWithPath: "/tmp/sph-\(UUID().uuidString.prefix(8))", isDirectory: true)
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: home.path)
        let store = try VaultStore(creatingAt: home.appendingPathComponent("vault.db"),
                                   keystore: FileAgeKeystore())
        _ = try await store.set(SecretMeta(name: "cf", kind: "bearer", bindHosts: ["api.example.com"],
                                           inject: Inject(adapter: "bearer", header: "Authorization", format: "Bearer {secret}")),
                                value: Data("sk_live_1".utf8))
        if locked { await store.lock() }
        let sock = home.appendingPathComponent("sallyport.sock").path
        let paths = VaultHost.Paths(socket: sock,
                                    auditDir: home.appendingPathComponent("audit").path,
                                    knownHosts: home.appendingPathComponent("known_hosts").path,
                                    recordDir: home.appendingPathComponent("rec").path, sshHelper: "/usr/bin/false")
        let hosts = HostsStore()
        let host = try await VaultHost(store: store, hosts: hosts, paths: paths,
                                       approver: AutoApprove())
        if !locked { await host.onVaultUnlocked() }
        try host.start()
        return (host, sock)
    }

    @Test("list_tools returns the built-in catalog over the socket")
    func listTools() async throws {
        let (host, sock) = try await buildHost(locked: false)
        defer { host.stop() }
        let reply = request(sock, ["type": "list_tools", "id": "1"])
        let tools = reply?["tools"] as? [Any]
        #expect(tools?.count == 3)
        let names = (tools ?? []).compactMap { ($0 as? [String: Any])?["name"] as? String }
        #expect(Set(names) == ["http.request", "ssh.exec", "sallyport.request_credential"])
        // Unlocked: the http.request hint names the bound host.
        let httpDesc = (tools ?? []).compactMap { $0 as? [String: Any] }
            .first { ($0["name"] as? String) == "http.request" }?["description"] as? String
        #expect(httpDesc?.contains("api.example.com") == true)
    }

    @Test("a LOCKED vault serves only the static catalog — no metadata-derived hints")
    func lockedToolsHaveNoHints() async throws {
        let (host, sock) = try await buildHost(locked: true)
        defer { host.stop() }
        let reply = request(sock, ["type": "list_tools", "id": "1"])
        let tools = reply?["tools"] as? [Any]
        #expect(tools?.count == 3)   // the catalog itself is static, not secret
        let descs = (tools ?? []).compactMap { ($0 as? [String: Any])?["description"] as? String }
        #expect(descs.allSatisfy { !$0.contains("api.example.com") },
                "a locked vault must not leak bound hosts into tool hints")
    }

    @Test("a locked vault denies an invoke over the socket (ladder step 1, no network)")
    func lockedInvoke() async throws {
        let (host, sock) = try await buildHost(locked: true)
        defer { host.stop() }
        let reply = request(sock, [
            "type": "invoke", "id": "2", "identity": "agent://test",
            "action": ["tool": "http.request", "args": ["method": "GET", "url": "https://api.example.com/x"]],
        ])
        let result = reply?["result"] as? [String: Any]
        #expect((result?["error_code"] as? String) == "SALLYPORT_LOCKED")
        #expect((result?["rule"] as? String) == "vault.locked")
    }

    @Test("an OPENED vault whose signer root was deleted quarantines — never fresh-adopts (C2)")
    func openedVaultMissingRootQuarantines() async throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("spc2-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        let dbURL = home.appendingPathComponent("vault.db")
        let ks = FileAgeKeystore()                             // one instance → same wrap key on reopen
        let signer = SoftwareAuditSigner()                     // same signing key across both opens
        let anchorURL = home.appendingPathComponent("anchor.json")

        func makeHost(_ store: VaultStore) async throws -> VaultHost {
            let paths = VaultHost.Paths(socket: home.appendingPathComponent("s.sock").path,
                                        auditDir: home.appendingPathComponent("audit").path,
                                        knownHosts: home.appendingPathComponent("kh").path,
                                        recordDir: home.appendingPathComponent("rec").path, sshHelper: "")
            return try await VaultHost(
                store: store, hosts: HostsStore(), paths: paths, approver: AutoApprove(),
                signer: signer, anchorStore: FileAnchorStore(url: anchorURL))
        }

        // 1. Create + first unlock → the gate ADOPTS the signer root (createdThisLaunch).
        let created = try VaultStore(creatingAt: dbURL, keystore: ks)
        #expect(created.createdThisLaunch)
        let h1 = try await makeHost(created)
        await h1.onVaultUnlocked()
        #expect(await h1.runIntegrityGate().isEmpty, "a freshly-created vault adopts cleanly")
        #expect(await created.phaseNow() == .ready)
        h1.stop()
        await created.close()

        // 2. Reopen the SAME db (createdThisLaunch == false) and DELETE the root.
        let opened = try VaultStore(openingAt: dbURL, keystore: ks)
        #expect(!opened.createdThisLaunch)
        try await opened.unlock()
        try await opened.setBlob(key: VaultStore.auditSignerBlobKey, data: Data())   // simulate deletion
        let h2 = try await makeHost(opened)
        await h2.onVaultUnlocked()
        let issues = await h2.runIntegrityGate()
        // An OPENED vault with a missing root is tampering — quarantine, not adopt.
        #expect(issues.map(\.code).contains("signer-root-missing"))
        #expect(await opened.phaseNow() == .quarantined)

        // H7: with no usable signer key, reading the journal MUST refuse — never
        // fall back to nil enforcement (which would render fabricated unsigned
        // rows in the feed/export). The DEK is still present in quarantine, so
        // auditIdentity() succeeds; the read fails ONLY on the missing signer.
        await #expect(throws: AuditError.signerUnavailable) { _ = try await h2.readAuditEvents() }
        await opened.close()
    }

    @Test("an OPENED vault whose replay FLOOR was deleted quarantines — never defaults to 0 (C2)")
    func openedVaultMissingFloorQuarantines() async throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("spc2f-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        let dbURL = home.appendingPathComponent("vault.db")
        let ks = FileAgeKeystore()
        let signer = SoftwareAuditSigner()
        let anchorURL = home.appendingPathComponent("anchor.json")

        func makeHost(_ store: VaultStore) async throws -> VaultHost {
            let paths = VaultHost.Paths(socket: home.appendingPathComponent("s.sock").path,
                                        auditDir: home.appendingPathComponent("audit").path,
                                        knownHosts: home.appendingPathComponent("kh").path,
                                        recordDir: home.appendingPathComponent("rec").path, sshHelper: "")
            return try await VaultHost(
                store: store, hosts: HostsStore(), paths: paths, approver: AutoApprove(),
                signer: signer, anchorStore: FileAnchorStore(url: anchorURL))
        }

        // Create + first unlock: adopts the signer root AND writes the floor.
        let created = try VaultStore(creatingAt: dbURL, keystore: ks)
        let h1 = try await makeHost(created)
        await h1.onVaultUnlocked()
        #expect(await h1.runIntegrityGate().isEmpty)
        h1.stop()
        await created.close()

        // Reopen and delete ONLY the floor (the signer root is intact). Deleting
        // it must NOT silently collapse the replay check to 0 — it's tampering.
        let opened = try VaultStore(openingAt: dbURL, keystore: ks)
        try await opened.unlock()
        try await opened.setBlob(key: VaultStore.anchorFloorBlobKey, data: Data())
        let h2 = try await makeHost(opened)
        await h2.onVaultUnlocked()
        #expect(await h2.runIntegrityGate().map(\.code).contains("trust-state-unreadable"),
                "an authenticated but malformed floor is corruption, never generation zero")
        #expect(await opened.phaseNow() == .quarantined)
        await opened.close()
    }
}
