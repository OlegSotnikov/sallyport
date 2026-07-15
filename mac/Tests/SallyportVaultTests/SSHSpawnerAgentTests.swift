import Testing
import Foundation
import Darwin
@testable import SallyportVault

/// The integration seam: `SSHSpawner` posix_spawns the REAL `sp-ssh`, hands it a
/// private socketpair on fd 3, and serves the ssh-agent from Swift. These prove
/// the cross-language handshake over the inherited fd — the Go agent client asks
/// our Swift `SSHAgentServer` for identities and gets them — WITHOUT needing a
/// full SSH server (the dial is expected to fail; the agent step happens first).
@Suite("SSH agent-signing — spawn + cross-language agent handshake", .serialized)
struct SSHSpawnerAgentTests {

    private static let ed25519PEM = """
    -----BEGIN OPENSSH PRIVATE KEY-----
    b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
    QyNTUxOQAAACD7h/ZZqiUmzNnzYaRYIrev5Txs+zE2rMN6yA7dS9FKrAAAAJAF/g86Bf4P
    OgAAAAtzc2gtZWQyNTUxOQAAACD7h/ZZqiUmzNnzYaRYIrev5Txs+zE2rMN6yA7dS9FKrA
    AAAEBym//pp6FZ+2w6QefNdl+sIHqX8UoD4q/+8BOE+njHtfuH9lmqJSbM2fNhpFgit6/l
    PGz7MTasw3rIDt1L0UqsAAAABmZpeC1lZAECAwQFBgc=
    -----END OPENSSH PRIVATE KEY-----
    """

    /// Build `sp-ssh` once; nil (→ tests no-op) when the Go toolchain is absent.
    static let spSSHPath: String? = buildSPSSH()

    private static func buildSPSSH() -> String? {
        let coreDir = URL(fileURLWithPath: #filePath)      // …/mac/Tests/SallyportVaultTests/<file>
            .deletingLastPathComponent()                    // SallyportVaultTests
            .deletingLastPathComponent()                    // Tests
            .deletingLastPathComponent()                    // mac
            .deletingLastPathComponent()                    // sallyport
            .appendingPathComponent("core")
        let out = "/tmp/spx-spssh-\(getpid())"
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        p.arguments = ["go", "build", "-o", out, "./cmd/sp-ssh"]
        p.currentDirectoryURL = coreDir
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        do { try p.run() } catch { return nil }
        p.waitUntilExit()
        return (p.terminationStatus == 0 && FileManager.default.isExecutableFile(atPath: out)) ? out : nil
    }

    /// Spawn sp-ssh with the agent served (or not), a bogus host, and return the
    /// helper's error string.
    private func runSpawn(serveAgent: Bool) throws -> String {
        let bin = try #require(Self.spSSHPath, "sp-ssh could not be built (is Go installed?)")
        let key = try SSHPrivateKey(opensshPEM: Data(Self.ed25519PEM.utf8))

        var sp: [Int32] = [0, 0]
        #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &sp) == 0)
        let child = try SSHSpawner.spawnHelper(path: bin, agentChildFD: sp[1])
        kill(child.pid, SIGCONT)   // the child is spawned suspended (C1); resume it
        close(sp[1])

        var agentThread: Thread?
        if serveAgent {
            let server = SSHAgentServer(key: key, comment: "fleet-key")
            let fd = sp[0]
            let t = Thread { server.serve(fd: fd) }
            t.start(); agentThread = t
        } else {
            close(sp[0])                                    // no agent → child's fd 3 peer is gone
        }
        defer { if serveAgent { shutdown(sp[0], SHUT_RDWR); close(sp[0]) }; _ = agentThread }

        // A host that refuses TCP (port 1): the agent handshake runs BEFORE the
        // dial, so a served agent yields a dial error, an absent one yields an
        // agent error.
        let req: [String: Any] = [
            "host": "127.0.0.1", "user": "nobody", "port": 1,
            "hostKeyPolicy": "accept-new", "command": "true", "timeoutS": 3,
            "knownHostsPath": "/tmp/spx-kh-\(UUID().uuidString)", "agentFD": 3,
        ]
        let reqData = try JSONSerialization.data(withJSONObject: req)
        let inH = FileHandle(fileDescriptor: child.stdinWrite, closeOnDealloc: true)
        try? inH.write(contentsOf: reqData); try? inH.close()
        let out = FileHandle(fileDescriptor: child.stdoutRead, closeOnDealloc: true).readDataToEndOfFile()
        var st: Int32 = 0; waitpid(child.pid, &st, 0)

        let obj = (try? JSONSerialization.jsonObject(with: out)) as? [String: Any] ?? [:]
        return (obj["error"] as? String) ?? ""
    }

    @Test("the real sp-ssh gets fd 3 and completes the agent identities handshake")
    func agentHandshakeSucceeds() throws {
        let err = try runSpawn(serveAgent: true)
        // The agent answered (no agent error). The remaining failure is the dial
        // to a refused port — proof the inherited-fd handshake worked end to end.
        #expect(!err.isEmpty, "the dial to :1 should still fail")
        #expect(!err.lowercased().contains("agent"),
                "the agent handshake should have succeeded over fd 3; got: \(err)")
    }

    @Test("with NO agent served, sp-ssh fails at the agent step (fd 3 is required)")
    func agentAbsentFailsClosed() throws {
        let err = try runSpawn(serveAgent: false)
        #expect(err.lowercased().contains("agent"),
                "without an agent the helper must fail at the agent step; got: \(err)")
    }

    @Test("the full execute() path serves the agent and tears down cleanly (no crash)")
    func executePathTearsDownCleanly() async throws {
        let bin = try #require(Self.spSSHPath, "sp-ssh could not be built (is Go installed?)")
        let spawner = SSHSpawner(helperPath: bin,
                                 knownHostsPath: "/tmp/spx-kh-\(UUID().uuidString)",
                                 recordDir: "",
                                 inventory: { _ in nil })
        let host = HostRef(name: "t", addr: "127.0.0.1", user: "nobody", port: 1,
                           hostKeyPolicy: "accept-new", keyName: "k")
        // The agent thread starts + answers identities, then the dial to :1 is
        // refused → execute throws. The point is the whole path (posix_spawn,
        // agent serve, pthread_join, teardown) runs WITHOUT crashing or hanging.
        do {
            _ = try await spawner.execute(host: host, command: "true", timeoutS: 3,
                                          keyPEM: Data(Self.ed25519PEM.utf8))
            Issue.record("expected the dial to :1 to fail")
        } catch {
            let msg = "\(error)".lowercased()
            #expect(!msg.contains("could not start signing agent"),
                    "the agent thread should have started; got: \(msg)")
        }
    }
}
