import Foundation
import Testing
@testable import SallyportKit

// MARK: - Test helpers

/// Records what a `MgmtClient` sends, so a test can reply by id.
private actor Recorder {
    private(set) var messages: [OutboundMessage] = []
    func record(_ message: OutboundMessage) { messages.append(message) }

    /// Spin until at least `count` messages have been recorded (or give up).
    func awaitCount(_ count: Int) async -> [OutboundMessage] {
        for _ in 0..<10_000 {
            if messages.count >= count { return messages }
            await Task.yield()
        }
        return messages
    }
}

private func idOp(_ message: OutboundMessage) -> (id: String, op: String, arg: JSONValue?)? {
    guard case let .mgmt(id, op, arg) = message else { return nil }
    return (id, op, arg)
}

@Suite("Mgmt codec")
struct MgmtCodecTests {

    /// One representative `mgmt` message per op — round-trips app→wire→app.
    @Test("every mgmt op round-trips through the codec")
    func everyOpRoundTrips() throws {
        let secret = SecretInput(name: "cf_token", kind: "bearer", value: "s3cr3t",
                                 bind: ["api.cloudflare.com"], header: nil, format: "Bearer {secret}")
        let host = Host(name: "r-kz", addr: "192.168.89.1", user: "os", port: 442,
                        tags: ["fleet", "kz"], key: "ws_kz_key", hostkey: "accept-new")
        let sim = PolicySimInput(principal: "agent://mac.cli", channel: "http",
                                 tool: "http.request", host: "api.cloudflare.com", method: "POST")

        let messages: [OutboundMessage] = [
            .mgmt(id: "m1", op: "secrets.list", arg: nil),
            .mgmt(id: "m2", op: "secrets.set", arg: secret.arg),
            .mgmt(id: "m3", op: "secrets.rotate", arg: .object(["name": .string("cf_token"), "value": .string("new")])),
            .mgmt(id: "m4", op: "secrets.delete", arg: .object(["name": .string("cf_token")])),
            .mgmt(id: "m5", op: "hosts.list", arg: nil),
            .mgmt(id: "m6", op: "hosts.set", arg: host.arg),
            .mgmt(id: "m7", op: "hosts.delete", arg: .object(["name": .string("r-kz")])),
            .mgmt(id: "m8", op: "policy.get", arg: nil),
            .mgmt(id: "m9", op: "policy.set", arg: .object(["main": .string("allow: a"), "tests": .string("allow: a")])),
            .mgmt(id: "m10", op: "policy.test", arg: nil),
            .mgmt(id: "m11", op: "policy.simulate", arg: sim.arg),
            .mgmt(id: "m12", op: "status", arg: nil),
        ]
        for message in messages {
            let data = try ControlCodec.encode(message)
            let back = try ControlCodec.decodeOutbound(data)
            #expect(back == message, "round-trip mismatch for \(message)")
        }
    }

    @Test("a no-arg mgmt op omits the arg key on the wire")
    func noArgOmitsArg() throws {
        let text = String(decoding: try ControlCodec.encode(.mgmt(id: "m1", op: "status", arg: nil)), as: UTF8.self)
        #expect(text.contains("\"op\":\"status\""))
        #expect(!text.contains("\"arg\""))
    }

    @Test("mgmt.reply ok:true decodes with a typed result")
    func replyOkDecodes() throws {
        let json = """
        {"type":"mgmt.reply","id":"m1","ok":true,"result":{"secrets":[\
        {"name":"cf_token","kind":"bearer","bind":["api.cloudflare.com"],"adapter":"bearer","version":3,"rotatedAt":"t"}]}}
        """
        guard case let .mgmtReply(id, ok, result, error, detail, _) = try ControlCodec.decodeInbound(line: json) else {
            Issue.record("wrong case"); return
        }
        #expect(id == "m1")
        #expect(ok)
        #expect(error == nil)
        #expect(detail == nil)
        let secrets = try #require(result?.objectValue?["secrets"]).decoded([SecretMetadata].self)
        #expect(secrets.first?.name == "cf_token")
        #expect(secrets.first?.version == 3)
    }

    @Test("mgmt.reply ok:false decodes error + detail")
    func replyFailDecodes() throws {
        let json = """
        {"type":"mgmt.reply","id":"m9","ok":false,"error":"invalid confirm",\
        "detail":[{"field":"confirm","got":"sometimes"}]}
        """
        guard case let .mgmtReply(_, ok, _, error, detail, _) = try ControlCodec.decodeInbound(line: json) else {
            Issue.record("wrong case"); return
        }
        #expect(!ok)
        #expect(error == "invalid confirm")
        #expect(detail != nil)
    }
}

@Suite("Mgmt models")
struct MgmtModelTests {

    @Test("Host decodes with defaults and builds the right arg")
    func hostRoundTrip() throws {
        let host = try JSONValue.object([
            "name": .string("ws-kz"), "addr": .string("10.10.3.10"),
            "user": .string("os"), "port": .int(442),
            "tags": .array([.string("fleet")]), "key": .string("ws_kz_key"),
            "hostkey": .string("strict"),
        ]).decoded(Host.self)
        #expect(host.port == 442)
        #expect(host.hostkey == "strict")
        #expect(host.arg.objectValue?["addr"]?.stringValue == "10.10.3.10")
    }

    @Test("StatusInfo decodes a partial reply")
    func statusPartial() throws {
        let status = try JSONValue.object([
            "vault": .object(["locked": .bool(false), "ttlSec": .int(21600)]),
            "daemon": .object(["version": .string("running"), "uptimeSec": .int(0), "home": .string("~/.sallyport")]),
        ]).decoded(StatusInfo.self)
        #expect(status.vault?.locked == false)
        #expect(status.daemon?.version == "running")
        #expect(status.counts == nil)
    }

    @Test("SecretInput includes `passphrase` in arg only when non-empty")
    func secretInputPassphraseArg() {
        // With a passphrase → the arg carries it (write-only, alongside value).
        let withPass = SecretInput(name: "ws_kz_key", kind: "ssh-ed25519",
                                   value: "-----BEGIN OPENSSH PRIVATE KEY-----…",
                                   passphrase: "hunter2")
        #expect(withPass.arg.objectValue?["passphrase"]?.stringValue == "hunter2")

        // No passphrase (nil) → the key is omitted entirely.
        let noPass = SecretInput(name: "ws_kz_key", kind: "ssh-ed25519", value: "key")
        #expect(noPass.arg.objectValue?.keys.contains("passphrase") == false)

        // Blank/whitespace passphrase → also omitted (uses the .nonEmpty helper).
        let blank = SecretInput(name: "ws_kz_key", kind: "ssh-ed25519", value: "key", passphrase: "   ")
        #expect(blank.arg.objectValue?.keys.contains("passphrase") == false)
    }

    @Test("SecretMetadata has no value field — decoding drops any stray value")
    func secretMetadataMetadataOnly() throws {
        // Even if a value sneaks into the JSON, the typed model cannot surface it.
        let json = JSONValue.object([
            "name": .string("cf_token"), "kind": .string("bearer"),
            "value": .string("SUPER_SECRET_VALUE"), "bind": .array([.string("api.cloudflare.com")]),
        ])
        let meta = try json.decoded(SecretMetadata.self)
        #expect(meta.name == "cf_token")
        let reencoded = String(decoding: try JSONEncoder().encode(meta), as: UTF8.self)
        #expect(!reencoded.contains("SUPER_SECRET_VALUE"))
    }
}

@Suite("MgmtClient request/reply correlation")
struct MgmtClientTests {

    @Test("correlates replies by id, even delivered out of order")
    func outOfOrderCorrelation() async throws {
        let recorder = Recorder()
        let client = MgmtClient(sender: { await recorder.record($0) }, timeout: nil)

        // Two concurrent requests; capture the ids the client assigned.
        let hostsTask = Task { try await client.request(op: "hosts.list") }
        let secretsTask = Task { try await client.request(op: "secrets.list") }

        let sent = await recorder.awaitCount(2)
        let byOp = Dictionary(uniqueKeysWithValues: sent.compactMap { idOp($0).map { ($0.op, $0.id) } })
        let hostsID = try #require(byOp["hosts.list"])
        let secretsID = try #require(byOp["secrets.list"])

        // Reply to the SECOND request first — correlation must still hold.
        await client.deliver(.mgmtReply(id: secretsID, ok: true,
                                        result: .object(["secrets": .array([])]), error: nil, detail: nil, code: nil))
        await client.deliver(.mgmtReply(id: hostsID, ok: true,
                                        result: .object(["hosts": .array([.object(["name": .string("r-kz")])])]),
                                        error: nil, detail: nil, code: nil))

        let hosts = try await hostsTask.value
        let secrets = try await secretsTask.value
        #expect(hosts.objectValue?["hosts"]?.arrayValueCount == 1)
        #expect(secrets.objectValue?["secrets"]?.arrayValueCount == 0)
    }

    @Test("deliver ignores non-mgmt messages")
    func deliverIgnoresOther() async {
        let client = MgmtClient(sender: { _ in }, timeout: nil)
        let consumed = await client.deliver(.vaultState(VaultState(locked: false, ttlSec: 1)))
        #expect(consumed == false)
    }

    @Test("a send failure fails the request closed")
    func sendFailureFailsClosed() async {
        struct Boom: Error {}
        let client = MgmtClient(sender: { _ in throw Boom() }, timeout: nil)
        await #expect(throws: Boom.self) {
            _ = try await client.request(op: "status")
        }
    }

    @Test("a request times out when no reply arrives (instant sleeper)")
    func requestTimesOut() async {
        let client = MgmtClient(sender: { _ in },          // never delivers
                                timeout: .seconds(5),
                                sleeper: { _ in })          // instant → timeout fires at once
        await #expect(throws: MgmtClient.Failure.timedOut(op: "status")) {
            _ = try await client.request(op: "status")
        }
    }

    @Test("failAll rejects in-flight requests (fail-closed on link drop)")
    func failAllRejects() async {
        let client = MgmtClient(sender: { _ in }, timeout: nil)
        let task = Task { try await client.request(op: "hosts.list") }
        // Let the request register before failing it all.
        while await client.inFlight == 0 { await Task.yield() }
        await client.failAll()
        await #expect(throws: MgmtClient.Failure.linkDropped) { _ = try await task.value }
    }
}

@Suite("MgmtClient over the mock daemon")
struct MgmtClientMockTests {

    @Test("secrets.list returns metadata only — the value never comes back")
    func secretListMetadataOnly() async throws {
        let client = MgmtClient.mock(daemon: MockMgmtDaemon(seeded: false))
        try await client.setSecret(SecretInput(name: "cf_token", kind: "bearer",
                                               value: "SUPER_SECRET_VALUE",
                                               bind: ["api.cloudflare.com"], format: "Bearer {secret}"))
        let secrets = try await client.listSecrets()
        let cf = try #require(secrets.first { $0.name == "cf_token" })
        #expect(cf.kind == "bearer")
        #expect(cf.bind == ["api.cloudflare.com"])
        // The stored value must not be reachable through any metadata field.
        let encoded = String(decoding: try JSONEncoder().encode(secrets), as: UTF8.self)
        #expect(!encoded.contains("SUPER_SECRET_VALUE"))
    }

    @Test("hosts CRUD round-trips through the mock daemon")
    func hostsCRUD() async throws {
        let client = MgmtClient.mock(daemon: MockMgmtDaemon(seeded: false))
        #expect(try await client.listHosts().isEmpty)
        try await client.setHost(Host(name: "ws-kz", addr: "10.10.3.10", user: "os", port: 442,
                                       tags: ["fleet"], key: "ws_kz_key", hostkey: "strict"))
        var hosts = try await client.listHosts()
        #expect(hosts.count == 1)
        #expect(hosts.first?.addr == "10.10.3.10")
        try await client.deleteHost(name: "ws-kz")
        hosts = try await client.listHosts()
        #expect(hosts.isEmpty)
    }

    @Test("status reflects the seeded mock daemon")
    func statusReflectsMock() async throws {
        let client = MgmtClient.mock()
        let status = try await client.status()
        #expect(status.daemon?.version == "v0.1-demo")
        #expect(status.vault?.locked == false)
        #expect((status.counts?.secrets ?? 0) >= 1)
    }

}


@Suite("SSH key passphrase import")
struct SecretPassphraseTests {

    @Test("isPassphraseRequired triggers on the passphrase_required code, not others")
    func passphraseRequiredByCode() {
        let needs = MgmtError(op: "secrets.set", message: "encrypted",
                              code: MgmtError.passphraseRequiredCode)
        #expect(needs.isPassphraseRequired)

        // A wrong passphrase comes back as a normal `invalid` — must NOT re-prompt.
        let wrong = MgmtError(op: "secrets.set",
                              message: "could not decrypt ssh key (wrong passphrase?): x",
                              code: "invalid")
        #expect(!wrong.isPassphraseRequired)

        // Other codes never trigger the prompt.
        for code in ["not_found", "conflict", "locked", "policy_tests_failed", "internal"] {
            #expect(!MgmtError(op: "secrets.set", message: "nope", code: code).isPassphraseRequired)
        }
    }

    @Test("isPassphraseRequired falls back to the sentinel message when code is absent")
    func passphraseRequiredByMessage() {
        // The control socket omits the structured code; the daemon's stable
        // sentinel message must still trigger the prompt.
        let socket = MgmtError(op: "secrets.set",
                               message: "ssh private key is passphrase-protected; provide the passphrase")
        #expect(socket.code == nil)
        #expect(socket.isPassphraseRequired)

        // The wrong-passphrase message (no code) must NOT be mistaken for it.
        let wrong = MgmtError(op: "secrets.set",
                              message: "could not decrypt ssh key (wrong passphrase?): x")
        #expect(!wrong.isPassphraseRequired)
    }

    @Test("mgmt.reply carries the structured error code when the transport sends it")
    func replyDecodesCode() throws {
        let json = """
        {"type":"mgmt.reply","id":"m1","ok":false,\
        "error":"ssh private key is passphrase-protected; provide the passphrase",\
        "code":"passphrase_required"}
        """
        guard case let .mgmtReply(_, ok, _, _, _, code) = try ControlCodec.decodeInbound(line: json) else {
            Issue.record("wrong case"); return
        }
        #expect(!ok)
        #expect(code == "passphrase_required")
    }

    @Test("import flow through the mock: encrypted key needs a passphrase, then imports")
    func importFlowThroughMock() async throws {
        let client = MgmtClient.mock(daemon: MockMgmtDaemon(seeded: false))
        let encrypted = SecretInput(name: "id_ed25519", kind: "ssh-ed25519",
                                    value: "-----BEGIN OPENSSH PRIVATE KEY-----\nENCRYPTED…")

        // 1) No passphrase → the daemon asks for one (code surfaces on MgmtError).
        do {
            try await client.setSecret(encrypted)
            Issue.record("expected passphrase_required")
        } catch let error as MgmtError {
            #expect(error.isPassphraseRequired)
            #expect(error.code == MgmtError.passphraseRequiredCode)
        }

        // 2) With a passphrase → the key imports and appears in the list.
        var withPass = encrypted
        withPass.passphrase = "hunter2"
        try await client.setSecret(withPass)
        #expect(try await client.listSecrets().contains { $0.name == "id_ed25519" })
    }
}

// Small helper used above.
private extension JSONValue {
    var arrayValueCount: Int? {
        if case let .array(a) = self { return a.count }
        return nil
    }
}
