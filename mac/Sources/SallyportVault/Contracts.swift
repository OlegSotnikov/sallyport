import Foundation
import SallyportKit   // JSONValue

/// Shared vault types used by storage, execution, sessions, and auditing.

// MARK: - Secrets

/// How a bound credential is attached to an outbound request.
public struct Inject: Codable, Sendable, Hashable {
    public var adapter: String          // bearer | header | basic | aws-sigv4 | oauth2
    public var header: String           // header name for header/bearer adapters
    public var format: String           // value template containing {secret}
    /// Non-secret adapter configuration (aws-sigv4: region/service; oauth2:
    /// tokenUrl/clientId/scope). The secret value itself stays in the vault.
    public var params: [String: String]

    public init(adapter: String = "", header: String = "", format: String = "",
                params: [String: String] = [:]) {
        self.adapter = adapter; self.header = header; self.format = format; self.params = params
    }
}

/// Secret metadata without the value.
public struct SecretMeta: Codable, Sendable, Hashable {
    public var name: String
    public var version: Int
    public var kind: String             // bearer|basic|header|ssh-ed25519|aws-sigv4|oauth2
    public var bindHosts: [String]      // Hosts where this key may be injected.
    public var bindPaths: [String]
    public var inject: Inject
    public var createdAt: Date
    /// Per-call approval mode: empty, `click`, or `touchid`.
    public var confirm: String
    /// Disable certificate verification for this key's bound hosts. Default: off.
    public var insecureTLS: Bool

    public init(name: String, version: Int = 0, kind: String,
                bindHosts: [String] = [], bindPaths: [String] = [],
                inject: Inject = Inject(), createdAt: Date = Date(), confirm: String = "",
                insecureTLS: Bool = false) {
        self.name = name; self.version = version; self.kind = kind
        self.bindHosts = bindHosts; self.bindPaths = bindPaths
        self.inject = inject; self.createdAt = createdAt; self.confirm = confirm
        self.insecureTLS = insecureTLS
    }

    // Older records without `insecureTLS` decode with verification enabled.
    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        name = try c.decode(String.self, forKey: .name)
        version = try c.decodeIfPresent(Int.self, forKey: .version) ?? 0
        kind = try c.decode(String.self, forKey: .kind)
        bindHosts = try c.decodeIfPresent([String].self, forKey: .bindHosts) ?? []
        bindPaths = try c.decodeIfPresent([String].self, forKey: .bindPaths) ?? []
        inject = try c.decodeIfPresent(Inject.self, forKey: .inject) ?? Inject()
        createdAt = try c.decodeIfPresent(Date.self, forKey: .createdAt) ?? Date()
        confirm = try c.decodeIfPresent(String.self, forKey: .confirm) ?? ""
        insecureTLS = try c.decodeIfPresent(Bool.self, forKey: .insecureTLS) ?? false
    }
}

/// A resolved credential for injection. The caller zeroizes `secret` after use.
public struct Cred: Sendable {
    public var name: String
    public var kind: String
    public var inject: Inject
    public var secret: Data
    /// Mirrors `SecretMeta.insecureTLS`.
    public var insecureTLS: Bool
    public init(name: String, kind: String, inject: Inject, secret: Data, insecureTLS: Bool = false) {
        self.name = name; self.kind = kind; self.inject = inject; self.secret = secret
        self.insecureTLS = insecureTLS
    }
}

// MARK: - Actions & results

/// A canonicalized tool call used for approval and auditing.
public struct Action: Sendable {
    public var tool: String             // "http.request" | "ssh.exec" | "<upstream>.<tool>"
    public var args: [String: JSONValue]
    public init(tool: String, args: [String: JSONValue]) { self.tool = tool; self.args = args }
}

/// Result of an invoked action. Output is returned faithfully from the channel.
public struct InvokeResult: Sendable {
    public var ok: Bool
    public var output: [String: JSONValue]
    public var errorCode: String
    public var reason: String
    public var rule: String
    public var decision: String
    public init(ok: Bool, output: [String: JSONValue] = [:], errorCode: String = "",
                reason: String = "", rule: String = "", decision: String = "") {
        self.ok = ok; self.output = output; self.errorCode = errorCode
        self.reason = reason; self.rule = rule; self.decision = decision
    }

    public static func denied(_ code: String, _ reason: String, rule: String = "") -> InvokeResult {
        InvokeResult(ok: false, errorCode: code, reason: reason, rule: rule, decision: "deny")
    }
}

// MARK: - Executor contract

/// An egress executor (HTTP, SSH, upstream MCP). Given an action and a credential
/// resolver, it performs the side effect and returns the channel output.
public protocol ChannelExecutor: Sendable {
    func execute(_ action: Action, resolve: CredResolver) async throws -> ExecOutput
}

/// Resolves the credential bound to a target, materializing the secret at point of
/// use. Returns nil when nothing is bound (the call proceeds unauthenticated).
public typealias CredResolver = @Sendable (_ host: String, _ path: String) async throws -> Cred?

/// An executor's outputs, audited uniformly.
public struct ExecOutput: Sendable {
    public var output: [String: JSONValue]
    public var bytesOut: Int
    public var recording: String
    public init(output: [String: JSONValue] = [:], bytesOut: Int = 0,
                recording: String = "") {
        self.output = output; self.bytesOut = bytesOut
        self.recording = recording
    }
}
