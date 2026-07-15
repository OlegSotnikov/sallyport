import Foundation
import Testing
import LocalAuthentication
@testable import SallyportKit
@testable import SallyportApp
import SallyportVault

/// The whole product, end to end, with NO daemon and NO mocks in the trust path:
/// a real AppModel hosting a real vault (file-age, temp home), a real Unix
/// socket, and a client connecting exactly like the `sp` shim. Proves:
///
///   agent socket → peer provenance → engine ladder → approval card in
///   `model.pending` → human approve → execution (NetGuard) → audited reply,
///
/// plus the `sallyport.request_credential` → add-key-sheet round trip, and the
/// config path (MgmtClient loopback → VaultMgmtDaemon → VaultStore).
@MainActor
@Suite("App end to end over the agent socket", .serialized)
struct AppEndToEndTests {

    /// A line-JSON client, same framing as `sp` (blocking; run off the main
    /// actor). Data in/out so the value crossing tasks is Sendable (Swift 6).
    private nonisolated static func requestRaw(_ path: String, _ payload: Data) -> Data? {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
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
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        var data = payload; data.append(0x0A)
        _ = data.withUnsafeBytes { write(fd, $0.baseAddress, data.count) }
        var buf = [UInt8](repeating: 0, count: 65536); var acc = Data()
        while true {
            let n = read(fd, &buf, buf.count)
            if n <= 0 { return nil }
            acc.append(contentsOf: buf[0..<n])
            if let nl = acc.firstIndex(of: 0x0A) {
                return acc[acc.startIndex..<nl]
            }
        }
    }

    /// `requestRaw` moved OFF the cooperative pool: its connect/read BLOCK the
    /// thread, and eight of them in flight starve an 8-core box's entire Swift
    /// Concurrency runtime — the server's own async work can never run and the
    /// test deadlocks (wider dev Macs hide it). GCD threads may block freely.
    private static func requestRawAsync(_ path: String, _ payload: Data) async -> Data? {
        await withCheckedContinuation { cont in
            DispatchQueue.global().async { cont.resume(returning: requestRaw(path, payload)) }
        }
    }

    /// Fire an invoke in the background; await + parse its `result` object.
    private func invokeAsync(_ sock: String, _ obj: [String: Any]) -> Task<Data?, Never> {
        let payload = try! JSONSerialization.data(withJSONObject: obj)
        return Task.detached { await Self.requestRawAsync(sock, payload) }
    }

    private func result(_ data: Data?) -> [String: Any]? {
        guard let data,
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        return obj["result"] as? [String: Any]
    }

    /// A model with a REAL vault in a short-path temp home (unix sockets cap at
    /// ~104 bytes). isDemo keeps AppKit surfaces + the user's real feed untouched
    /// while the pending/approve flow stays fully live.
    private func liveModel() async throws -> (AppModel, String, URL) {
        let root = URL(fileURLWithPath: "/tmp/spe2e-\(UUID().uuidString.prefix(8))", isDirectory: true)
        let paths = OnboardingPaths(home: root.appendingPathComponent("h").path)
        try FileManager.default.createDirectory(atPath: paths.sallyportHome, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o700],
                                              ofItemAtPath: paths.sallyportHome)
        let signer = SoftwareKeyCustodian()
        let model = AppModel(signer: signer, authenticator: DevAuthenticator(),
                             setup: SallyportSetup(paths: paths),
                             identityGate: IdentityGate(blobURL: root.appendingPathComponent("id.sealed")))
        model.isDemo = true
        try await model.runtime.createVault(hardwareGate: false, signer: signer, gate: nil)
        return (model, model.runtime.socketPath, root)
    }

    @Test("invoke → approval card → approve → execution (NetGuard) → audited reply")
    func fullApprovalLoop() async throws {
        let (model, sock, root) = try await liveModel()
        defer { model.runtime.host?.stop(); try? FileManager.default.removeItem(at: root) }

        // Add a key over the SAME MgmtClient the config screens use.
        try await model.mgmt.setSecret(SecretInput(
            name: "k1", kind: "bearer", value: "sk_live_e2e", bind: ["api.example.com"],
            format: "Bearer {secret}"))
        let listed = try await model.mgmt.listSecrets()
        #expect(listed.map(\.name) == ["k1"])

        // An "agent" invokes over the socket; the engine parks it on the card.
        let reply = invokeAsync(sock, [
            "type": "invoke", "id": "e2e-1", "identity": "agent://e2e",
            "action": ["tool": "http.request",
                       "args": ["method": "GET", "url": "https://127.0.0.1:9/x"]],
        ])
        // The card must appear (session gate), then the human approves.
        for _ in 0..<2000 where model.pending.isEmpty {
            await Task.yield()
            try? await Task.sleep(for: .milliseconds(5))
        }
        let card = try #require(model.pending.first)
        #expect(card.mode == "session")
        #expect(card.why.rule == "session.gate")
        await model.approve(card)

        // Approved → engine executes → NetGuard blocks the internal address —
        // proving the request ran the REAL executor, fail-closed.
        let res = try #require(result(await reply.value))
        #expect(res["error_code"] as? String == "SALLYPORT_BLOCKED")

        // The session is now live + approved, visible to the Sessions screen.
        let sessions = try await model.mgmt.listSessions()
        #expect(sessions.count == 1)
        #expect(sessions.first?.status == "approved")
        #expect(sessions.first?.pid == Int(getpid()))

        // The decision reached the activity feed via the audit sink.
        #expect(model.activity.rows.contains { $0.tool == "http.request" && $0.target == "127.0.0.1" })
    }

    @Test("request_credential → add-key sheet state → respond → agent gets the answer")
    func credentialRoundTrip() async throws {
        let (model, sock, root) = try await liveModel()
        defer { model.runtime.host?.stop(); try? FileManager.default.removeItem(at: root) }
        let initialSecretsRevision = model.secretsRevision

        let reply = invokeAsync(sock, [
            "type": "invoke", "id": "e2e-2", "identity": "agent://e2e",
            "action": ["tool": "sallyport.request_credential",
                       "args": ["host": "api.new.io", "hosts": ["api.new.io"],
                                "purpose": "list widgets", "name": "new_io_token"]],
        ])
        // TWO human moments, in order: first OPEN A SESSION (an unapproved process
        // must pass the session gate before it can push an add-key sheet at you),
        // then answer the ask in the sheet.
        for _ in 0..<2000 where model.pending.isEmpty {
            await Task.yield()
            try? await Task.sleep(for: .milliseconds(5))
        }
        let card = try #require(model.pending.first)
        #expect(card.mode == "session", "first contact opens a session — the credential ask rides the normal gate")
        #expect(card.action.tool == "sallyport.request_credential")
        // The SECOND request (the add-key sheet) must NOT appear until the human
        // has authorized the session — the agent can't push a sheet at you first.
        #expect(model.credentialRequest == nil, "no add-key sheet before the session is approved")
        await model.approve(card)

        for _ in 0..<2000 where model.credentialRequest == nil {
            await Task.yield()
            try? await Task.sleep(for: .milliseconds(5))
        }
        let req = try #require(model.credentialRequest)
        #expect(req.host == "api.new.io")
        #expect(req.suggestedName == "new_io_token")

        // The human saves a key through the sheet's callback.
        model.respondCredential(req, provisioned: true, name: "new_io_token")
        let res = try #require(result(await reply.value))
        #expect(res["ok"] as? Bool == true)
        let output = try #require(res["output"] as? [String: Any])
        #expect(output["provisioned"] as? Bool == true)
        #expect(output["name"] as? String == "new_io_token")
        #expect(model.credentialRequest == nil)
        // And the Keys screen is told the table went stale.
        #expect(model.secretsRevision != initialSecretsRevision)
        // Opening the session admitted the agent — its later calls need no new card.
        #expect(try await model.mgmt.listSessions().contains { $0.status == "approved" })
    }

    @Test("8 concurrent agents: no cross-blocking, every reply arrives")
    func concurrentInvokes() async throws {
        let (model, sock, root) = try await liveModel()
        defer { model.runtime.host?.stop(); try? FileManager.default.removeItem(at: root) }

        // Admit the session once (approve the first card), then hammer.
        let first = invokeAsync(sock, [
            "type": "invoke", "id": "warm", "identity": "agent://e2e",
            "action": ["tool": "http.request", "args": ["method": "GET", "url": "https://127.0.0.1:9/w"]],
        ])
        for _ in 0..<2000 where model.pending.isEmpty {
            await Task.yield(); try? await Task.sleep(for: .milliseconds(5))
        }
        await model.approve(try #require(model.pending.first))
        _ = await first.value

        // 8 parallel connections; each must get its own SALLYPORT_BLOCKED reply
        // (session already approved → no cards, engine actor must not serialize
        // them into a hang).
        let replies = await withTaskGroup(of: Data?.self, returning: [Data?].self) { group in
            for i in 0..<8 {
                let payload = try! JSONSerialization.data(withJSONObject: [
                    "type": "invoke", "id": "c\(i)", "identity": "agent://e2e",
                    "action": ["tool": "http.request",
                               "args": ["method": "GET", "url": "https://127.0.0.1:9/p\(i)"]],
                ])
                group.addTask { await Self.requestRawAsync(sock, payload) }
            }
            var all: [Data?] = []
            for await r in group { all.append(r) }
            return all
        }
        #expect(replies.count == 8)
        for r in replies {
            let res = try #require(result(r))
            #expect(res["error_code"] as? String == "SALLYPORT_BLOCKED")
        }
        #expect(model.pending.isEmpty)   // approved session → no extra cards
    }

    @Test("client disconnect mid-approval: app survives, card resolves cleanly")
    func disconnectMidApproval() async throws {
        let (model, sock, root) = try await liveModel()
        defer { model.runtime.host?.stop(); try? FileManager.default.removeItem(at: root) }

        // Open a raw connection, send an invoke, then slam it shut while the
        // engine is parked on the approval card.
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        var addr = sockaddr_un(); addr.sun_family = sa_family_t(AF_UNIX)
        _ = sock.withCString { src in
            withUnsafeMutablePointer(to: &addr.sun_path) {
                $0.withMemoryRebound(to: CChar.self, capacity: 104) { strncpy($0, src, 103) }
            }
        }
        let len = socklen_t(MemoryLayout<sockaddr_un>.size)
        _ = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, len) }
        }
        var line = try JSONSerialization.data(withJSONObject: [
            "type": "invoke", "id": "gone", "identity": "agent://e2e",
            "action": ["tool": "http.request", "args": ["method": "GET", "url": "https://127.0.0.1:9/x"]],
        ])
        line.append(0x0A)
        _ = line.withUnsafeBytes { write(fd, $0.baseAddress, line.count) }
        for _ in 0..<2000 where model.pending.isEmpty {
            await Task.yield(); try? await Task.sleep(for: .milliseconds(5))
        }
        close(fd)   // the agent dies while the human is deciding

        // The human still approves; the engine runs, the write to the dead
        // socket fails quietly, nothing crashes, the card is gone.
        await model.approve(try #require(model.pending.first))
        try? await Task.sleep(for: .milliseconds(200))
        #expect(model.pending.isEmpty)
        // The host is still fully alive for the next agent.
        let after = invokeAsync(sock, ["type": "list_tools", "id": "alive"])
        #expect(await after.value != nil)
    }

    @Test("a large multi-chunk frame reassembles and executes whole")
    func oversizedFrame() async throws {
        let (model, sock, root) = try await liveModel()
        defer { model.runtime.host?.stop(); try? FileManager.default.removeItem(at: root) }

        // A large-but-valid frame (a big args blob) must round-trip fine — the
        // reassembler handles multi-chunk lines. (The >8 MiB hard cap that closes
        // the connection is covered by LineFramer unit tests, without the slow
        // multi-MB blocking write here.)
        let big = String(repeating: "x", count: 200_000)
        let reply = invokeAsync(sock, [
            "type": "invoke", "id": "big", "identity": "agent://e2e",
            "action": ["tool": "http.request",
                       "args": ["method": "GET", "url": "https://127.0.0.1:9/x", "note": big]],
        ])
        // Session not yet approved → a card appears; approve it and the big frame
        // executes (NetGuard blocks the address), proving the frame parsed whole.
        for _ in 0..<2000 where model.pending.isEmpty {
            await Task.yield(); try? await Task.sleep(for: .milliseconds(5))
        }
        await model.approve(try #require(model.pending.first))
        let res = try #require(result(await reply.value))
        #expect(res["error_code"] as? String == "SALLYPORT_BLOCKED")

        // The listener still accepts after handling the large frame.
        let after = invokeAsync(sock, ["type": "list_tools", "id": "still-alive"])
        #expect(await after.value != nil)
    }

    @Test("deny resolves the socket reply as a structured denial")
    func denyLoop() async throws {
        let (model, sock, root) = try await liveModel()
        defer { model.runtime.host?.stop(); try? FileManager.default.removeItem(at: root) }

        let reply = invokeAsync(sock, [
            "type": "invoke", "id": "e2e-3", "identity": "agent://e2e",
            "action": ["tool": "http.request",
                       "args": ["method": "GET", "url": "https://api.example.com/x"]],
        ])
        for _ in 0..<2000 where model.pending.isEmpty {
            await Task.yield()
            try? await Task.sleep(for: .milliseconds(5))
        }
        await model.deny(try #require(model.pending.first))
        let res = try #require(result(await reply.value))
        #expect(res["error_code"] as? String == "SALLYPORT_DENIED")
        #expect(res["ok"] as? Bool == false)
    }
}

/// The gate that stops a local process with Accessibility rights from driving
/// Sallyport's own window (synthetic clicks) to re-bind a key, clear a per-call
/// flag, or switch the session gate to observe (docs/14 §2.4).
@Suite("Touch ID for configuration changes", .serialized)
@MainActor
struct ConfigChangeGateTests {

    /// Refuses every biometric prompt — the stand-in for "the finger never came".
    private final class DenyingAuthenticator: Authenticator, @unchecked Sendable {
        let lastAuthenticatedContext: LAContext? = nil
        let isBiometric = true
        private let lock = NSLock()
        private(set) var prompts: [String] = []
        func authenticate(reason: String) async -> AuthOutcome {
            lock.withLock { prompts.append(reason) }
            return .denied
        }
        var seen: [String] { lock.withLock { prompts } }
    }

    /// A REAL model (not demo) whose biometric surface always refuses.
    private func gatedModel(_ auth: any Authenticator) async throws -> (AppModel, URL) {
        let root = URL(fileURLWithPath: "/tmp/spgate-\(UUID().uuidString.prefix(8))", isDirectory: true)
        let paths = OnboardingPaths(home: root.appendingPathComponent("h").path)
        try FileManager.default.createDirectory(atPath: paths.sallyportHome, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o700],
                                              ofItemAtPath: paths.sallyportHome)
        let signer = SoftwareKeyCustodian()
        let model = AppModel(signer: signer, authenticator: auth,
                             setup: SallyportSetup(paths: paths),
                             identityGate: IdentityGate(blobURL: root.appendingPathComponent("id.sealed")))
        try await model.runtime.createVault(hardwareGate: false, signer: signer, gate: nil)
        return (model, root)
    }

    @Test("without the fingerprint NOTHING changes — and the prompt NAMES the change")
    func mutationsRequireTouchID() async throws {
        let auth = DenyingAuthenticator()
        let (model, root) = try await gatedModel(auth)
        defer { model.runtime.host?.stop(); try? FileManager.default.removeItem(at: root) }

        // Every mutation the config surface offers is refused.
        await #expect(throws: (any Error).self) {
            try await model.mgmt.setSecret(SecretInput(
                name: "cf_token", kind: "bearer", value: "sk_live", bind: ["api.cloudflare.com"]))
        }
        await #expect(throws: (any Error).self) {
            try await model.mgmt.setHost(Host(name: "prod-1", addr: "10.0.0.1", user: "root"))
        }
        await #expect(throws: (any Error).self) {
            try await model.mgmt.setUpstream(Upstream(name: "linear", transport: "http",
                                                      url: "https://mcp.linear.app/mcp"))
        }
        await #expect(throws: (any Error).self) {
            // The one that matters most: an attacker turning the session gate OFF.
            _ = try await model.mgmt.updateSettings(sessionAuth: "off")
        }

        // NOTHING landed.
        #expect(try await model.mgmt.listSecrets().isEmpty)
        #expect(try await model.mgmt.listHosts().isEmpty)
        #expect(try await model.mgmt.listUpstreams().isEmpty)
        #expect(try await model.mgmt.settings().sessionAuth == "click")   // still gated

        // The prompt NAMED each change: a synthetic-click attacker cannot ride a
        // fingerprint the human is giving for something else — they'd read the
        // wrong sentence.
        #expect(auth.seen.contains { $0.contains("Add the key") && $0.contains("cf_token") })
        #expect(auth.seen.contains { $0.contains("SSH host") && $0.contains("prod-1") })
        #expect(auth.seen.contains { $0.contains("MCP server") && $0.contains("linear") })
        // The session-gate change is named precisely — not a generic "settings".
        #expect(auth.seen.contains { $0.contains("Set new-agent approval to \"Off\"") })
    }

    @Test("reads and session revoke are NOT gated — killing a rogue agent can't wait on a finger")
    func readsAndRevokeStayFree() async throws {
        let auth = DenyingAuthenticator()
        let (model, root) = try await gatedModel(auth)
        defer { model.runtime.host?.stop(); try? FileManager.default.removeItem(at: root) }

        _ = try await model.mgmt.listSecrets()
        _ = try await model.mgmt.listHosts()
        _ = try await model.mgmt.listSessions()
        _ = try await model.mgmt.status()
        try await model.mgmt.revokeSession(key: "4321:1000000")   // exempt: only REDUCES access
        #expect(auth.seen.isEmpty, "a read or a revoke must never ask for a fingerprint")
    }

    /// Flips between approve and deny mid-test, so one model can turn the gate
    /// off (with a finger) and then be denied for the next attempt.
    private final class SwitchableAuthenticator: Authenticator, @unchecked Sendable {
        let lastAuthenticatedContext: LAContext? = nil
        let isBiometric = true
        private let lock = NSLock()
        private var approve = true
        private(set) var prompts: [String] = []
        func setApprove(_ v: Bool) { lock.withLock { approve = v } }
        func authenticate(reason: String) async -> AuthOutcome {
            lock.withLock { prompts.append(reason); return approve ? .approved : .denied }
        }
        var seen: [String] { lock.withLock { prompts } }
    }

    @Test("security-posture settings ALWAYS take a fingerprint — even with the change-gate OFF")
    func securitySettingsAlwaysGated() async throws {
        let auth = SwitchableAuthenticator()
        let (model, root) = try await gatedModel(auth)
        defer { model.runtime.host?.stop(); try? FileManager.default.removeItem(at: root) }

        // Turn the general change-gate OFF (itself a settings change → prompted).
        _ = try await model.mgmt.updateSettings(requireTouchIDForChanges: false)
        #expect(model.runtime.host?.settings.requireTouchIDForChanges() == false)

        // Now DENY every further finger.
        auth.setApprove(false)

        // A non-security mutation is now free (the operator lifted its gate)…
        try await model.mgmt.setSecret(SecretInput(
            name: "k", kind: "bearer", value: "sk_live", bind: ["api.example.com"]))
        #expect(try await model.mgmt.listSecrets().map(\.name) == ["k"])

        // …but flipping the SESSION GATE to Off is refused despite the toggle,
        // and the prompt names it precisely (anti-phishing).
        await #expect(throws: (any Error).self) {
            _ = try await model.mgmt.updateSettings(sessionAuth: "off")
        }
        #expect(model.runtime.host?.settings.sessionAuth() == "click", "the session gate must be unchanged")
        #expect(auth.seen.contains { $0.contains("Set new-agent approval to \"Off\"") })

        // Auto-lock and lock-on-screen-lock are likewise always gated.
        await #expect(throws: (any Error).self) {
            _ = try await model.mgmt.updateSettings(autoLockMinutes: 0)
        }
        await #expect(throws: (any Error).self) {
            _ = try await model.mgmt.updateSettings(lockOnScreenLock: false)
        }
        #expect(auth.seen.contains { $0.contains("auto-lock") })
        #expect(auth.seen.contains { $0.contains("screen-lock") })

        // Adding to the agent ALLOWLIST is always gated too — a synthetic click
        // must not be able to auto-approve itself (docs/14 §2.5).
        await #expect(throws: (any Error).self) {
            try await model.mgmt.addAllowlist(AllowlistItem(
                label: "evil", kind: "cdhash", cdhashes: ["deadbeef"]))
        }
        #expect(try await model.mgmt.listAllowlist().isEmpty, "nothing was allowlisted without a fingerprint")
        #expect(auth.seen.contains { $0.contains("Auto-approve the agent") })
    }

    @Test("with the fingerprint the change lands — and the gate can only be lifted WITH one")
    func fingerprintLetsChangesThrough() async throws {
        let (model, root) = try await gatedModel(DevAuthenticator())   // always approves
        defer { model.runtime.host?.stop(); try? FileManager.default.removeItem(at: root) }

        try await model.mgmt.setSecret(SecretInput(
            name: "cf_token", kind: "bearer", value: "sk_live", bind: ["api.cloudflare.com"]))
        #expect(try await model.mgmt.listSecrets().map(\.name) == ["cf_token"])

        // Turning the gate OFF is itself a change → it too took a fingerprint.
        let posture = try await model.mgmt.updateSettings(requireTouchIDForChanges: false)
        #expect(!posture.requireTouchIDForChanges)
    }
}
