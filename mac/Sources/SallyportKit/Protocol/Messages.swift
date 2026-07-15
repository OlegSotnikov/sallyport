import Foundation

// MARK: - Shared sub-structures


/// User-facing description of an agent action.
public struct ActionDescriptor: Sendable, Hashable, Codable {
    public var channel: String            // "http" | "ssh" | "mcp"
    public var tool: String               // e.g. "http.request"
    public var summary: String            // "POST https://... (mutating)"
    public var host: String?
    public var argsPreview: JSONValue?
    public var bodyPreview: String?
    public var dangerTokens: [String]

    public init(channel: String, tool: String, summary: String,
                host: String? = nil, argsPreview: JSONValue? = nil,
                bodyPreview: String? = nil, dangerTokens: [String] = []) {
        self.channel = channel
        self.tool = tool
        self.summary = summary
        self.host = host
        self.argsPreview = argsPreview
        self.bodyPreview = bodyPreview
        self.dangerTokens = dangerTokens
    }

    // dangerTokens is optional on the wire; default to [] when absent.
    private enum CodingKeys: String, CodingKey {
        case channel, tool, summary, host, argsPreview, bodyPreview, dangerTokens
    }
    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        channel = try c.decode(String.self, forKey: .channel)
        tool = try c.decode(String.self, forKey: .tool)
        summary = try c.decode(String.self, forKey: .summary)
        host = try c.decodeIfPresent(String.self, forKey: .host)
        argsPreview = try c.decodeIfPresent(JSONValue.self, forKey: .argsPreview)
        bodyPreview = try c.decodeIfPresent(String.self, forKey: .bodyPreview)
        dangerTokens = try c.decodeIfPresent([String].self, forKey: .dangerTokens) ?? []
    }
}

/// Reason supplied with an approval request.
public struct WhyDescriptor: Sendable, Hashable, Codable {
    public var rule: String
    public var reason: String
    public init(rule: String, reason: String) {
        self.rule = rule
        self.reason = reason
    }
}

/// One process in the caller chain.
public struct ProcessHop: Sendable, Hashable, Codable, Identifiable {
    public var pid: Int
    public var name: String
    public var path: String?
    public var ppid: Int?
    public var appName: String?
    public var validSignature: Bool?
    /// Code-signing authority. Nil when unsigned or unavailable.
    public var signedBy: String?

    public var id: Int { pid }

    public init(pid: Int, name: String, path: String? = nil, ppid: Int? = nil,
                appName: String? = nil, validSignature: Bool? = nil, signedBy: String? = nil) {
        self.pid = pid
        self.name = name
        self.path = path
        self.ppid = ppid
        self.appName = appName
        self.validSignature = validSignature
        self.signedBy = signedBy
    }
}

/// Verified provenance shipped with an approval request.
public struct Provenance: Sendable, Hashable, Codable {
    public var origin: ProcessHop
    public var chain: [ProcessHop]
    public var intact: Bool
    public init(origin: ProcessHop, chain: [ProcessHop], intact: Bool) {
        self.origin = origin
        self.chain = chain
        self.intact = intact
    }

    // Accept a missing or null process chain.
    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        origin = try c.decode(ProcessHop.self, forKey: .origin)
        chain = try c.decodeIfPresent([ProcessHop].self, forKey: .chain) ?? []
        intact = try c.decodeIfPresent(Bool.self, forKey: .intact) ?? false
    }
}

/// Kernel-captured identity of the calling executable.
public struct ActivityOrigin: Sendable, Hashable, Codable {
    public var name: String?
    public var path: String?
    public var app: String?
    public var pid: Int?
    public var signed: Bool?
    public var signedBy: String?
    public var chain: String?   // "Claude -> login -> sp"

    public init(name: String? = nil, path: String? = nil, app: String? = nil, pid: Int? = nil,
                signed: Bool? = nil, signedBy: String? = nil, chain: String? = nil) {
        self.name = name; self.path = path; self.app = app; self.pid = pid
        self.signed = signed; self.signedBy = signedBy; self.chain = chain
    }

    /// App bundle name, process name, or `unknown`.
    public var displayName: String { app ?? name ?? "unknown" }
}

/// One row of the live activity feed.
public struct ActivityRow: Sendable, Hashable, Codable, Identifiable {
    public var ts: String                 // RFC3339
    public var identity: String
    public var channel: String
    public var tool: String
    public var argsPreview: String
    public var target: String
    public var decision: String           // allow, deny, ask, or a resolved ask state
    public var rule: String?
    public var isError: Bool
    public var bytesOut: Int?
    public var durationMs: Int?
    public var grantId: String?
    public var recording: String?
    public var origin: ActivityOrigin?

    // Feeds get a stable identity for SwiftUI diffing even though the wire has none.
    public var id: String { "\(ts)|\(identity)|\(tool)|\(target)" }

    public init(ts: String, identity: String, channel: String, tool: String,
                argsPreview: String, target: String, decision: String,
                rule: String? = nil, isError: Bool = false, bytesOut: Int? = nil,
                durationMs: Int? = nil, grantId: String? = nil, recording: String? = nil,
                origin: ActivityOrigin? = nil) {
        self.ts = ts
        self.identity = identity
        self.channel = channel
        self.tool = tool
        self.argsPreview = argsPreview
        self.target = target
        self.decision = decision
        self.rule = rule
        self.isError = isError
        self.bytesOut = bytesOut
        self.durationMs = durationMs
        self.grantId = grantId
        self.recording = recording
        self.origin = origin
    }
}

/// Vault lock state.
public struct VaultState: Sendable, Hashable, Codable {
    public var locked: Bool
    public var ttlSec: Int
    public init(locked: Bool, ttlSec: Int) {
        self.locked = locked
        self.ttlSec = ttlSec
    }
}

// MARK: - Inbound

/// An agent request for the user to add a credential.
public struct CredentialRequest: Sendable, Hashable, Identifiable {
    public var id: String
    public var host: String
    /// Domains that may receive the credential. Always includes `host`.
    public var hosts: [String]
    public var purpose: String
    public var kind: String            // suggested adapter: bearer|basic|header
    /// For kind=header: the header name the API expects (e.g. X-Api-Key).
    public var header: String
    /// How the value is sent, `{secret}` being the placeholder.
    public var format: String
    public var suggestedName: String
    public var docsURL: String         // where to create the token
    public var scopes: [String]        // suggested permissions/zones
    public var provenance: Provenance

    public init(id: String, host: String, hosts: [String] = [], purpose: String, kind: String,
                header: String = "", format: String = "",
                suggestedName: String, docsURL: String, scopes: [String], provenance: Provenance) {
        self.id = id; self.host = host
        self.hosts = hosts.isEmpty ? [host] : hosts
        self.purpose = purpose; self.kind = kind
        self.header = header; self.format = format
        self.suggestedName = suggestedName; self.docsURL = docsURL
        self.scopes = scopes; self.provenance = provenance
    }
}

public enum InboundMessage: Sendable, Hashable {
    case approvalRequest(id: String, action: ActionDescriptor, why: WhyDescriptor,
                         provenance: Provenance, mode: String)
    case activity(ActivityRow)
    case vaultState(VaultState)
    /// An agent-proposed credential request for the add-key prompt.
    case credentialRequest(CredentialRequest)
    /// Reply to a management request. `code` is optional for transport compatibility.
    case mgmtReply(id: String, ok: Bool, result: JSONValue?, error: String?, detail: JSONValue?, code: String?)
}

// MARK: - Outbound

public enum OutboundMessage: Sendable, Hashable {
    case subscribe
    /// A management request. `op` selects the operation;
    /// `arg` is the operation-specific payload, omitted on the wire when nil.
    case mgmt(id: String, op: String, arg: JSONValue?)
}
