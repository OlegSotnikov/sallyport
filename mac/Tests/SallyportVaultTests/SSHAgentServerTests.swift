import Testing
import Foundation
@testable import SallyportVault

@Suite("SSH agent server — protocol + socket round-trip")
struct SSHAgentServerTests {

    // A real ed25519 openssh-key-v1 (from ssh-keygen), reused across cases.
    private static let ed25519PEM = """
    -----BEGIN OPENSSH PRIVATE KEY-----
    b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
    QyNTUxOQAAACD7h/ZZqiUmzNnzYaRYIrev5Txs+zE2rMN6yA7dS9FKrAAAAJAF/g86Bf4P
    OgAAAAtzc2gtZWQyNTUxOQAAACD7h/ZZqiUmzNnzYaRYIrev5Txs+zE2rMN6yA7dS9FKrA
    AAAEBym//pp6FZ+2w6QefNdl+sIHqX8UoD4q/+8BOE+njHtfuH9lmqJSbM2fNhpFgit6/l
    PGz7MTasw3rIDt1L0UqsAAAABmZpeC1lZAECAwQFBgc=
    -----END OPENSSH PRIVATE KEY-----
    """

    private func makeServer() throws -> (SSHAgentServer, SSHPrivateKey) {
        let key = try SSHPrivateKey(opensshPEM: Data(Self.ed25519PEM.utf8))
        return (SSHAgentServer(key: key, comment: "fleet-key"), key)
    }

    @Test("REQUEST_IDENTITIES answers with the one public key + comment")
    func listIdentities() throws {
        let (server, key) = try makeServer()
        let resp = server.handle(Data([11]))               // SSH_AGENTC_REQUEST_IDENTITIES
        #expect(resp.first == 12)                          // SSH_AGENT_IDENTITIES_ANSWER
        var r = SSHWire.Reader(resp.dropFirst())
        #expect(try r.uint32() == 1)
        #expect(try r.string() == key.publicKeyBlob)
        #expect(try r.stringUTF8() == "fleet-key")
    }

    @Test("SIGN_REQUEST for our key returns a verifying signature; a foreign blob fails")
    func signRequest() throws {
        let (server, key) = try makeServer()
        let data = Data("challenge bytes".utf8)
        var req = SSHWire.Writer()
        req.byte(13)                                       // SSH_AGENTC_SIGN_REQUEST
        req.string(key.publicKeyBlob)
        req.string(data)
        req.uint32(0)
        let resp = server.handle(req.data)
        #expect(resp.first == 14)                          // SSH_AGENT_SIGN_RESPONSE
        var r = SSHWire.Reader(resp.dropFirst())
        let sig = try r.string()
        #expect(try SSHVerify.verify(pubBlob: key.publicKeyBlob, sigBlob: sig, data: data))

        // A sign request for a key we don't hold is refused.
        var bad = SSHWire.Writer()
        bad.byte(13); bad.string(Data("ssh-ed25519-not-ours".utf8)); bad.string(data); bad.uint32(0)
        #expect(server.handle(bad.data).first == 5)        // SSH_AGENT_FAILURE
    }

    @Test("an unknown request type is a clean FAILURE")
    func unknownType() throws {
        let (server, _) = try makeServer()
        #expect(server.handle(Data([99])).first == 5)
        #expect(server.handle(Data()).first == 5)
    }

    @Test("signing stops after revoke() and past the per-exec budget (C1)")
    func revokeAndBudget() throws {
        let key = try SSHPrivateKey(opensshPEM: Data(Self.ed25519PEM.utf8))
        func signReq() -> Data {
            var w = SSHWire.Writer(); w.byte(13); w.string(key.publicKeyBlob); w.string(Data("x".utf8)); w.uint32(0)
            return w.data
        }
        // Budget of 2: two signs succeed, the third is refused.
        let budgeted = SSHAgentServer(key: key, maxSignatures: 2)
        #expect(budgeted.handle(signReq()).first == 14)
        #expect(budgeted.handle(signReq()).first == 14)
        #expect(budgeted.handle(signReq()).first == 5, "over budget → FAILURE")

        // revoke() stops all further signatures immediately.
        let revocable = SSHAgentServer(key: key)
        #expect(revocable.handle(signReq()).first == 14)
        revocable.revoke()
        #expect(revocable.handle(signReq()).first == 5, "revoked → FAILURE")
        // But identities still list (harmless) — only signing is cut off.
        #expect(revocable.handle(Data([11])).first == 12)
    }

    @Test("SSHLifecycle.killAll revokes every registered agent (H1)")
    func lifecycleRevokesAgents() throws {
        let key = try SSHPrivateKey(opensshPEM: Data(Self.ed25519PEM.utf8))
        let agent = SSHAgentServer(key: key)
        let lc = SSHLifecycle()
        lc.register(pid: 2_000_000_000, agent: agent)   // bogus pid → kill is a no-op
        var w = SSHWire.Writer(); w.byte(13); w.string(key.publicKeyBlob); w.string(Data("x".utf8)); w.uint32(0)
        #expect(agent.handle(w.data).first == 14, "signs before lock")
        lc.killAll()
        #expect(agent.handle(w.data).first == 5, "a lock revokes the agent — no more signatures")
    }

    @Test("the framed serve loop over a real socketpair answers a client")
    func socketRoundTrip() throws {
        let (server, key) = try makeServer()
        var fds = [Int32](repeating: 0, count: 2)
        #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0)
        let serverFD = fds[0], clientFD = fds[1]

        let finished = DispatchSemaphore(value: 0)
        let t = Thread {
            defer {
                close(serverFD)
                finished.signal()
            }
            server.serve(fd: serverFD)
        }
        t.start()
        defer {
            // The serve thread exclusively owns serverFD. Closing it here while
            // serve() is blocked in read() lets the descriptor number be reused
            // before that thread exits; a later response can then hit an
            // unrelated stream (and SIGPIPE the whole process). EOF the client
            // endpoint and join the owner instead.
            _ = shutdown(clientFD, SHUT_RDWR)
            close(clientFD)
            #expect(finished.wait(timeout: .now() + 1) == .success)
        }

        // Client: send a framed REQUEST_IDENTITIES, read the framed answer.
        try sendFrame(clientFD, Data([11]))
        let answer = try recvFrame(clientFD)
        #expect(answer.first == 12)
        var r = SSHWire.Reader(answer.dropFirst())
        #expect(try r.uint32() == 1)
        #expect(try r.string() == key.publicKeyBlob)

        // Client: sign a challenge over the socket, verify the result.
        let data = Data("over the wire".utf8)
        var req = SSHWire.Writer()
        req.byte(13); req.string(key.publicKeyBlob); req.string(data); req.uint32(0)
        try sendFrame(clientFD, req.data)
        let signResp = try recvFrame(clientFD)
        #expect(signResp.first == 14)
        var sr = SSHWire.Reader(signResp.dropFirst())
        #expect(try SSHVerify.verify(pubBlob: key.publicKeyBlob, sigBlob: sr.string(), data: data))
    }

    // Framed client helpers (uint32 length prefix).
    private func sendFrame(_ fd: Int32, _ payload: Data) throws {
        var noSigPipe: Int32 = 1
        _ = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe,
                       socklen_t(MemoryLayout<Int32>.size))
        var out = Data([UInt8((payload.count >> 24) & 0xff), UInt8((payload.count >> 16) & 0xff),
                        UInt8((payload.count >> 8) & 0xff), UInt8(payload.count & 0xff)])
        out.append(payload)
        try out.withUnsafeBytes { raw in
            var off = 0
            while off < raw.count {
                let w = write(fd, raw.baseAddress!.advanced(by: off), raw.count - off)
                if w <= 0 { throw SSHError.malformed("write failed") }
                off += w
            }
        }
    }

    private func recvFrame(_ fd: Int32) throws -> Data {
        func readN(_ n: Int) throws -> [UInt8] {
            var buf = [UInt8](repeating: 0, count: n); var got = 0
            while got < n {
                let r = buf.withUnsafeMutableBytes { read(fd, $0.baseAddress!.advanced(by: got), n - got) }
                if r <= 0 { throw SSHError.truncated }
                got += r
            }
            return buf
        }
        let lb = try readN(4)
        let len = (Int(lb[0]) << 24) | (Int(lb[1]) << 16) | (Int(lb[2]) << 8) | Int(lb[3])
        return Data(try readN(len))
    }
}
