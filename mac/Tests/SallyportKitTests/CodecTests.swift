import Foundation
import Testing
@testable import SallyportKit

@Suite("Control protocol codec")
struct CodecTests {

    // MARK: Inbound round-trips (daemon → app)

    @Test("approval_request decodes with full provenance and danger tokens")
    func approvalRequestDecodes() throws {
        let json = """
        {"type":"approval_request","id":"req-1","action":{"channel":"http","tool":"http.request",\
        "summary":"POST https://api.cloudflare.com/... (mutating)","host":"api.cloudflare.com",\
        "argsPreview":{"method":"POST","path":"/zones"},"bodyPreview":"{}","dangerTokens":["POST"]},\
        "why":{"rule":"http-mutating","reason":"bound cred"},\
        "provenance":{"origin":{"pid":4321,"name":"claude","appName":"Claude Code",\
        "path":"/x","validSignature":true},"chain":[{"pid":4321,"name":"claude","path":"/x","ppid":10}],\
        "intact":true}}
        """
        let message = try ControlCodec.decodeInbound(line: json)
        guard case let .approvalRequest(id, action, why, provenance, _) = message else {
            Issue.record("wrong case"); return
        }
        #expect(id == "req-1")
        #expect(action.channel == "http")
        #expect(action.tool == "http.request")
        #expect(action.host == "api.cloudflare.com")
        #expect(action.dangerTokens == ["POST"])
        #expect(action.argsPreview?.objectValue?["method"]?.stringValue == "POST")
        #expect(why.rule == "http-mutating")
        #expect(provenance.origin.appName == "Claude Code")
        #expect(provenance.chain.count == 1)
        #expect(provenance.intact == true)
    }

    @Test("approval_request tolerates a missing dangerTokens field")
    func approvalRequestMissingDangerTokens() throws {
        let json = """
        {"type":"approval_request","id":"r","action":{"channel":"ssh","tool":"ssh.exec",\
        "summary":"df -h"},"why":{"rule":"x","reason":"y"},\
        "provenance":{"origin":{"pid":1,"name":"a"},"chain":[],"intact":false}}
        """
        let message = try ControlCodec.decodeInbound(line: json)
        guard case let .approvalRequest(_, action, _, _, _) = message else {
            Issue.record("wrong case"); return
        }
        #expect(action.dangerTokens == [])
    }

    @Test("approval_request tolerates a null provenance chain (Go nil slice → JSON null)")
    func approvalRequestNullChain() throws {
        // The daemon marshals a nil `Provenance.Chain` as `null`; the app must not
        // drop the whole approval on it (the old non-optional decode threw).
        let json = """
        {"type":"approval_request","id":"r","action":{"channel":"ssh","tool":"ssh.exec",\
        "summary":"df -h"},"why":{"rule":"x","reason":"y"},\
        "provenance":{"origin":{"pid":1,"name":"a"},"chain":null,"intact":true}}
        """
        let message = try ControlCodec.decodeInbound(line: json)
        guard case let .approvalRequest(_, _, _, provenance, _) = message else {
            Issue.record("wrong case"); return
        }
        #expect(provenance.chain.isEmpty)
        #expect(provenance.intact)
    }

    @Test("activity decodes with nullable fields")
    func activityDecodes() throws {
        let json = """
        {"type":"activity","row":{"ts":"2026-07-08T14:22:31Z","identity":"agent://mac.cli",\
        "channel":"http","tool":"http.request","argsPreview":"GET /zones","target":"api.cloudflare.com",\
        "decision":"allow","rule":"http-get-bound","isError":false,"bytesOut":214,"durationMs":88,\
        "grantId":null,"recording":null}}
        """
        let message = try ControlCodec.decodeInbound(line: json)
        guard case let .activity(row) = message else { Issue.record("wrong case"); return }
        #expect(row.identity == "agent://mac.cli")
        #expect(row.decision == "allow")
        #expect(row.bytesOut == 214)
        #expect(row.grantId == nil)
        #expect(row.isFlagged == false)
    }

    @Test("vault_state decodes")
    func vaultStateDecodes() throws {
        let message = try ControlCodec.decodeInbound(line: #"{"type":"vault_state","locked":false,"ttlSec":21600}"#)
        guard case let .vaultState(state) = message else { Issue.record("wrong case"); return }
        #expect(state.locked == false)
        #expect(state.ttlSec == 21600)
    }

    @Test("unknown inbound type throws a typed error")
    func unknownTypeThrows() {
        #expect(throws: ControlCodec.CodecError.unknownType("nope")) {
            _ = try ControlCodec.decodeInbound(line: #"{"type":"nope"}"#)
        }
    }

    // MARK: Outbound round-trips (app → daemon)




    /// The whole point of shipping issuedAt: the daemon reconstructs the grant
    /// from the stored approval_request + the decision's fields and verifies the
    /// signature. This exercises exactly that path end-to-end.
}

@Suite("LineFramer")
struct LineFramerTests {

    @Test("reassembles frames split across chunks")
    func reassembly() throws {
        var framer = LineFramer()
        #expect(try framer.push(Data("{\"a\":1}".utf8)).isEmpty)   // no newline yet
        let lines = try framer.push(Data("\n{\"b\":2}\n".utf8))
        #expect(lines.count == 2)
        #expect(String(decoding: lines[0], as: UTF8.self) == "{\"a\":1}")
        #expect(String(decoding: lines[1], as: UTF8.self) == "{\"b\":2}")
    }

    @Test("skips empty lines and keeps trailing partial buffered")
    func emptyAndPartial() throws {
        var framer = LineFramer()
        let lines = try framer.push(Data("\n\nhalf".utf8))
        #expect(lines.isEmpty)
        #expect(framer.pendingByteCount == 4)
    }

    @Test("enforces the max line guardrail")
    func tooLong() {
        var framer = LineFramer(maxLineBytes: 8)
        #expect(throws: LineFramer.FramerError.self) {
            _ = try framer.push(Data("0123456789".utf8))  // 10 bytes, no newline
        }
    }

    @Test("a newline cannot bypass the frame cap")
    func terminatedLineTooLong() {
        var framer = LineFramer(maxLineBytes: 8)
        #expect(throws: LineFramer.FramerError.lineTooLong(10)) {
            _ = try framer.push(Data("0123456789\n".utf8))
        }
    }

    @Test("the cap applies per frame, not to a chunk containing many frames")
    func capIsPerFrame() throws {
        var framer = LineFramer(maxLineBytes: 4)
        let lines = try framer.push(Data("one\ntwo\n3\n".utf8))
        #expect(lines.map { String(decoding: $0, as: UTF8.self) } == ["one", "two", "3"])
        #expect(framer.pendingByteCount == 0)
    }

    @Test("an exactly-at-cap partial frame remains valid when its newline arrives later")
    func exactCapAcrossChunks() throws {
        var framer = LineFramer(maxLineBytes: 8)
        #expect(try framer.push(Data("01234567".utf8)).isEmpty)
        let lines = try framer.push(Data("\nnext".utf8))
        #expect(lines == [Data("01234567".utf8)])
        #expect(framer.pendingByteCount == 4)
    }
}

@Suite("JSONValue")
struct JSONValueTests {
    @Test("round-trips nested structures")
    func roundTrip() throws {
        let value = JSONValue.object([
            "s": .string("hi"), "n": .int(3), "b": .bool(true),
            "arr": .array([.int(1), .null]),
        ])
        let data = try JSONEncoder().encode(value)
        let back = try JSONDecoder().decode(JSONValue.self, from: data)
        #expect(back == value)
    }

    @Test("integer projection rejects hostile numeric boundaries without trapping")
    func safeIntegerProjection() throws {
        #expect(JSONValue.double(42).intValue == 42)
        #expect(JSONValue.double(42.5).intValue == nil)
        #expect(JSONValue.double(.infinity).intValue == nil)
        #expect(JSONValue.double(.nan).intValue == nil)

        // On 64-bit platforms this JSON number is exactly one above Int.max.
        // JSONDecoder represents it as Double; projecting it used to call
        // Int(d), which terminates the process on overflow.
        let tooLarge = try JSONDecoder().decode(
            JSONValue.self, from: Data("9223372036854775808".utf8))
        #expect(tooLarge.intValue == nil)
        #expect(JSONValue.double(Double(Int.min)).intValue == Int.min)
        #expect(JSONValue.double(Double(Int.max)).intValue == nil)
    }

    @Test("credential_request decodes (agent proposes, you add the key)")
    func credentialRequestDecodes() throws {
        let json = """
        {"type":"credential_request","id":"cr-1","host":"api.namecheap.com",\
        "purpose":"list domains","kind":"bearer","suggestedName":"namecheap_key",\
        "docsUrl":"https://ap.www.namecheap.com/settings/tools/apiaccess",\
        "scopes":["domains:read"],"provenance":{"origin":{"pid":42,"name":"claude","appName":"Claude Code"},\
        "chain":[{"pid":42,"name":"claude"}],"intact":true}}
        """
        let msg = try ControlCodec.decodeInbound(line: json)
        guard case let .credentialRequest(req) = msg else {
            Issue.record("expected credentialRequest, got \(msg)"); return
        }
        #expect(req.id == "cr-1")
        #expect(req.host == "api.namecheap.com")
        #expect(req.kind == "bearer")
        #expect(req.suggestedName == "namecheap_key")
        #expect(req.scopes == ["domains:read"])
        #expect(req.docsURL.contains("namecheap"))
    }


}
