import Foundation

/// Encodes and decodes newline-delimited control messages.
public enum ControlCodec {

    public enum CodecError: Error, Equatable {
        case unknownType(String)
        case notUTF8
    }

    // MARK: Wire structs

    private struct TypeProbe: Decodable { let type: String }

    private struct ApprovalRequestWire: Codable {
        let type: String
        let id: String
        let action: ActionDescriptor
        let why: WhyDescriptor
        let provenance: Provenance
        let mode: String?
    }
    private struct CredentialRequestWire: Codable {
        let type: String
        let id: String
        let host: String
        let hosts: [String]?
        let purpose: String?
        let kind: String?
        let suggestedName: String?
        let docsUrl: String?
        let scopes: [String]?
        let provenance: Provenance
    }
    private struct ActivityWire: Codable {
        let type: String
        let row: ActivityRow
    }
    private struct VaultStateWire: Codable {
        let type: String
        let locked: Bool
        let ttlSec: Int
    }
    private struct MgmtReplyWire: Decodable {
        let type: String
        let id: String
        let ok: Bool
        let result: JSONValue?
        let error: String?
        let detail: JSONValue?
        // Optional structured error code such as `passphrase_required` or `invalid`.
        // the control-socket reply may omit it, in which case callers fall back to
        // the `error` message.
        let code: String?
    }
    private struct MgmtWire: Encodable {
        let type = "mgmt"
        let id: String
        let op: String
        let arg: JSONValue?   // synthesized Encodable omits this key when nil
    }

    private struct SubscribeWire: Encodable {
        let type = "subscribe"
    }

    // MARK: Decoding

    /// Decode a single JSON line (no trailing newline) into an `InboundMessage`.
    public static func decodeInbound(_ data: Data) throws -> InboundMessage {
        let decoder = JSONDecoder()
        let probe = try decoder.decode(TypeProbe.self, from: data)
        switch probe.type {
        case "approval_request":
            let w = try decoder.decode(ApprovalRequestWire.self, from: data)
            return .approvalRequest(id: w.id, action: w.action, why: w.why,
                                    provenance: w.provenance, mode: w.mode ?? "")
        case "activity":
            let w = try decoder.decode(ActivityWire.self, from: data)
            return .activity(w.row)
        case "credential_request":
            let w = try decoder.decode(CredentialRequestWire.self, from: data)
            return .credentialRequest(CredentialRequest(
                id: w.id, host: w.host, hosts: w.hosts ?? [], purpose: w.purpose ?? "",
                kind: w.kind ?? "bearer", suggestedName: w.suggestedName ?? "",
                docsURL: w.docsUrl ?? "", scopes: w.scopes ?? [], provenance: w.provenance))
        case "vault_state":
            let w = try decoder.decode(VaultStateWire.self, from: data)
            return .vaultState(VaultState(locked: w.locked, ttlSec: w.ttlSec))
        case "mgmt.reply":
            let w = try decoder.decode(MgmtReplyWire.self, from: data)
            return .mgmtReply(id: w.id, ok: w.ok, result: w.result,
                              error: w.error, detail: w.detail, code: w.code)
        default:
            throw CodecError.unknownType(probe.type)
        }
    }

    public static func decodeInbound(line: String) throws -> InboundMessage {
        guard let data = line.data(using: .utf8) else { throw CodecError.notUTF8 }
        return try decodeInbound(data)
    }

    // MARK: Encoding

    /// Encode an `OutboundMessage` to a single compact JSON line (no newline).
    public static func encode(_ message: OutboundMessage) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.withoutEscapingSlashes]
        switch message {
        case .subscribe:
            return try encoder.encode(SubscribeWire())
        case .mgmt(let id, let op, let arg):
            return try encoder.encode(MgmtWire(id: id, op: op, arg: arg))
        }
    }

    /// Encode a message as a newline-terminated frame ready for the socket.
    public static func encodeFrame(_ message: OutboundMessage) throws -> Data {
        var data = try encode(message)
        data.append(0x0A)  // '\n'
        return data
    }

    /// Round-trip helper for tests: decode an OutboundMessage back from its wire form.
    public static func decodeOutbound(_ data: Data) throws -> OutboundMessage {
        let decoder = JSONDecoder()
        let probe = try decoder.decode(TypeProbe.self, from: data)
        struct MgmtIn: Decodable { let id: String; let op: String; let arg: JSONValue? }
        switch probe.type {
        case "subscribe":
            return .subscribe
        case "mgmt":
            let w = try decoder.decode(MgmtIn.self, from: data)
            return .mgmt(id: w.id, op: w.op, arg: w.arg)
        default:
            throw CodecError.unknownType(probe.type)
        }
    }
}
