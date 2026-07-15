import Foundation

// MARK: - JSONValue helpers

public extension JSONValue {
    /// Decode this value into a `Decodable` model (re-encodes to Data, decodes T).
    func decoded<T: Decodable>(_ type: T.Type = T.self) throws -> T {
        let data = try JSONEncoder().encode(self)
        return try JSONDecoder().decode(T.self, from: data)
    }

    /// Wrap any `Encodable` value as a `JSONValue` (for building replies/fixtures).
    static func encoding<T: Encodable>(_ value: T) throws -> JSONValue {
        let data = try JSONEncoder().encode(value)
        return try JSONDecoder().decode(JSONValue.self, from: data)
    }

    /// Build an object, dropping nil entries so optional wire fields are omitted.
    static func compactObject(_ pairs: [(String, JSONValue?)]) -> JSONValue {
        var object: [String: JSONValue] = [:]
        for (key, value) in pairs { if let value { object[key] = value } }
        return .object(object)
    }

    /// JSON string array.
    static func strings(_ values: [String]) -> JSONValue { .array(values.map(JSONValue.string)) }

    /// A non-empty trimmed string as `.string`, else nil (so blank fields drop out).
    static func nonEmpty(_ value: String?) -> JSONValue? {
        guard let trimmed = value?.trimmingCharacters(in: .whitespacesAndNewlines),
              !trimmed.isEmpty else { return nil }
        return .string(trimmed)
    }
}

// MARK: - Secret metadata

/// Secret metadata returned by `secrets.list`. It has no value field.
public struct SecretMetadata: Codable, Sendable, Hashable, Identifiable {
    public var name: String
    public var kind: String                 // bearer | basic | header | ssh-ed25519
    public var bind: [String]               // hosts this key may be sent to
    public var adapter: String?             // inject adapter (bearer/basic/header)
    public var header: String?              // header name for kind=header
    public var format: String?              // e.g. "Bearer {secret}"
    public var params: [String: String]     // adapter config (sigv4/oauth2 non-secret)
    public var version: Int?
    public var rotatedAt: String?
    /// Per-call approval: "" (off), "click", or "touchid".
    public var confirm: String
    /// Whether TLS certificate verification is disabled for bound hosts.
    public var insecureTLS: Bool

    public var id: String { name }

    public init(name: String, kind: String, bind: [String] = [], adapter: String? = nil,
                header: String? = nil, format: String? = nil, params: [String: String] = [:],
                version: Int? = nil, rotatedAt: String? = nil, confirm: String = "",
                insecureTLS: Bool = false) {
        self.name = name
        self.kind = kind
        self.bind = bind
        self.adapter = adapter
        self.header = header
        self.format = format
        self.params = params
        self.version = version
        self.rotatedAt = rotatedAt
        self.confirm = confirm
        self.insecureTLS = insecureTLS
    }

    // Default a missing binding list to empty.
    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        name = try c.decode(String.self, forKey: .name)
        kind = try c.decode(String.self, forKey: .kind)
        bind = try c.decodeIfPresent([String].self, forKey: .bind) ?? []
        adapter = try c.decodeIfPresent(String.self, forKey: .adapter)
        header = try c.decodeIfPresent(String.self, forKey: .header)
        format = try c.decodeIfPresent(String.self, forKey: .format)
        params = try c.decodeIfPresent([String: String].self, forKey: .params) ?? [:]
        version = try c.decodeIfPresent(Int.self, forKey: .version)
        rotatedAt = try c.decodeIfPresent(String.self, forKey: .rotatedAt)
        confirm = try c.decodeIfPresent(String.self, forKey: .confirm) ?? ""
        insecureTLS = try c.decodeIfPresent(Bool.self, forKey: .insecureTLS) ?? false
    }

    enum CodingKeys: String, CodingKey {
        case name, kind, bind, adapter, header, format, params, version, rotatedAt, confirm
        case insecureTLS = "insecure_tls"
    }

    public var kindLabel: String { SecretKind(rawValue: kind)?.label ?? kind }
}

/// The known secret kinds, for the add/edit picker.
public enum SecretKind: String, CaseIterable, Sendable, Identifiable {
    case bearer, basic, header
    case awsSigV4 = "aws-sigv4"
    case oauth2
    case sshEd25519 = "ssh-ed25519"

    public var id: String { rawValue }
    public var label: String {
        switch self {
        case .bearer: return "Bearer token"
        case .basic: return "Basic auth"
        case .header: return "Custom header"
        case .awsSigV4: return "AWS Signature v4"
        case .oauth2: return "OAuth2 (client credentials)"
        case .sshEd25519: return "SSH key (ed25519)"
        }
    }
    public var isHTTPCredential: Bool { self != .sshEd25519 }
    public var needsHeaderName: Bool { self == .header }
    /// Adapters that use `{secret}` inject format (bearer/header). SigV4/OAuth2
    /// build the auth themselves, so no format field.
    public var usesInjectFormat: Bool { self == .bearer || self == .header }

    /// Label for the secret value field.
    public var valueLabel: String {
        switch self {
        case .basic: return "user:password"
        case .awsSigV4: return "AccessKeyID:SecretAccessKey"
        case .oauth2: return "Client secret"
        case .sshEd25519: return "Private key (PEM)"
        default: return "Secret value"
        }
    }

    /// Non-secret adapter fields.
    public var paramFields: [ParamField] {
        switch self {
        case .awsSigV4:
            return [ParamField("region", "Region", "us-east-1"),
                    ParamField("service", "Service", "execute-api")]
        case .oauth2:
            return [ParamField("tokenUrl", "Token URL", "https://issuer/oauth/token"),
                    ParamField("clientId", "Client ID", "abc123"),
                    ParamField("scope", "Scope (optional)", "read write")]
        default:
            return []
        }
    }
}

/// One adapter parameter input (non-secret config).
public struct ParamField: Sendable, Hashable, Identifiable {
    public let key: String
    public let label: String
    public let placeholder: String
    public var id: String { key }
    public init(_ key: String, _ label: String, _ placeholder: String) {
        self.key = key; self.label = label; self.placeholder = placeholder
    }
}

/// Write-only input for `secrets.set` and `secrets.rotate`.
public struct SecretInput: Sendable, Hashable {
    public var name: String
    public var kind: String
    public var value: String
    public var bind: [String]
    public var header: String?
    public var format: String?
    /// Non-secret adapter configuration.
    public var params: [String: String]
    /// Optional passphrase for importing a password-protected SSH private key.
    /// Used once to decrypt the key and omitted when blank.
    public var passphrase: String?
    /// Per-call approval: "" (off), "click", or "touchid".
    public var confirm: String
    /// Disable certificate verification for this key's bound hosts.
    public var insecureTLS: Bool

    public init(name: String, kind: String, value: String, bind: [String] = [],
                header: String? = nil, format: String? = nil,
                params: [String: String] = [:], passphrase: String? = nil, confirm: String = "",
                insecureTLS: Bool = false) {
        self.name = name
        self.kind = kind
        self.value = value
        self.bind = bind
        self.header = header
        self.format = format
        self.params = params
        self.passphrase = passphrase
        self.confirm = confirm
        self.insecureTLS = insecureTLS
    }

    /// The `arg` object for `secrets.set` (blank optional fields are omitted).
    public var arg: JSONValue {
        var fields: [(String, JSONValue?)] = [
            ("name", .string(name)),
            ("kind", .string(kind)),
            ("value", .string(value)),
            ("bind", .strings(bind)),
            ("header", .nonEmpty(header)),
            ("format", .nonEmpty(format)),
            // Omit blank passphrases.
            ("passphrase", .nonEmpty(passphrase)),
            ("confirm", .nonEmpty(confirm)),
            // Omit the default secure setting.
            ("insecure_tls", insecureTLS ? .bool(true) : nil),
        ]
        let cleaned = params.filter { !$0.value.isEmpty }
        if !cleaned.isEmpty {
            fields.append(("params", .object(cleaned.mapValues { .string($0) })))
        }
        return .compactObject(fields)
    }
}

// MARK: - SSH host

/// SSH host metadata. `key` refers to a stored SSH secret by name.
/// One vault secret exposed to an upstream MCP server as an env var.
public struct UpstreamKeyBinding: Codable, Sendable, Hashable {
    public var secret: String        // vault secret name
    public var envVar: String        // e.g. GITHUB_TOKEN
    public init(secret: String, envVar: String) {
        self.secret = secret; self.envVar = envVar
    }
}

/// Local or remote MCP server exposed under `<name>.<tool>`.
public struct Upstream: Codable, Sendable, Hashable, Identifiable {
    public var name: String          // tool-namespace prefix: [a-z0-9_-]
    public var transport: String     // "stdio" | "http"
    // stdio:
    public var command: String       // executable (bare name resolves via PATH)
    public var args: [String]
    public var env: [String: String] // static, non-secret environment
    public var keys: [UpstreamKeyBinding]
    // http:
    public var url: String           // endpoint; keys bind via Keys & APIs host binding
    /// Remote auth: "apikey" (host-bound vault key, the http.request model) or
    /// "oauth" (browser sign-in; tokens sealed under the vault key).
    public var auth: String
    /// Per-call approval for this server.
    public var confirm: String
    public var enabled: Bool

    // Server-reported, read-only fields.
    /// OAuth only: whether this server is signed in, and as whom.
    public var oauthConnected: Bool
    public var oauthAccount: String
    public var oauthExpiry: String

    public var id: String { name }

    public init(name: String, transport: String = "stdio", command: String = "",
                args: [String] = [], env: [String: String] = [:],
                keys: [UpstreamKeyBinding] = [], url: String = "",
                auth: String = "apikey", confirm: String = "", enabled: Bool = true,
                oauthConnected: Bool = false, oauthAccount: String = "", oauthExpiry: String = "") {
        self.name = name
        self.transport = transport
        self.command = command
        self.args = args
        self.env = env
        self.keys = keys
        self.url = url
        self.auth = auth
        self.confirm = confirm
        self.enabled = enabled
        self.oauthConnected = oauthConnected
        self.oauthAccount = oauthAccount
        self.oauthExpiry = oauthExpiry
    }

    enum CodingKeys: String, CodingKey {
        case name, transport, command, args, env, keys, url, auth, confirm, enabled
        case oauthConnected, oauthAccount, oauthExpiry
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        name = try c.decode(String.self, forKey: .name)
        transport = try c.decodeIfPresent(String.self, forKey: .transport) ?? "stdio"
        command = try c.decodeIfPresent(String.self, forKey: .command) ?? ""
        args = try c.decodeIfPresent([String].self, forKey: .args) ?? []
        env = try c.decodeIfPresent([String: String].self, forKey: .env) ?? [:]
        keys = try c.decodeIfPresent([UpstreamKeyBinding].self, forKey: .keys) ?? []
        url = try c.decodeIfPresent(String.self, forKey: .url) ?? ""
        auth = try c.decodeIfPresent(String.self, forKey: .auth) ?? "apikey"
        confirm = try c.decodeIfPresent(String.self, forKey: .confirm) ?? ""
        enabled = try c.decodeIfPresent(Bool.self, forKey: .enabled) ?? true
        oauthConnected = try c.decodeIfPresent(Bool.self, forKey: .oauthConnected) ?? false
        oauthAccount = try c.decodeIfPresent(String.self, forKey: .oauthAccount) ?? ""
        oauthExpiry = try c.decodeIfPresent(String.self, forKey: .oauthExpiry) ?? ""
    }

    public var arg: JSONValue { (try? .encoding(self)) ?? .null }
}

/// Agent allowlist entry used by management operations.
public struct AllowlistItem: Codable, Sendable, Hashable, Identifiable {
    public var id: String
    public var label: String
    public var kind: String          // "cdhash" | "publisher"
    public var teamID: String
    public var bundleID: String
    public var cdhashes: [String]
    public var requirement: String
    public var scopeHosts: [String]  // empty means any target
    public var capturedFrom: String

    public init(id: String = "", label: String = "", kind: String = "cdhash",
                teamID: String = "", bundleID: String = "", cdhashes: [String] = [],
                requirement: String = "", scopeHosts: [String] = [], capturedFrom: String = "") {
        self.id = id; self.label = label; self.kind = kind
        self.teamID = teamID; self.bundleID = bundleID; self.cdhashes = cdhashes
        self.requirement = requirement; self.scopeHosts = scopeHosts; self.capturedFrom = capturedFrom
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decodeIfPresent(String.self, forKey: .id) ?? ""
        label = try c.decodeIfPresent(String.self, forKey: .label) ?? ""
        kind = try c.decodeIfPresent(String.self, forKey: .kind) ?? "cdhash"
        teamID = try c.decodeIfPresent(String.self, forKey: .teamID) ?? ""
        bundleID = try c.decodeIfPresent(String.self, forKey: .bundleID) ?? ""
        cdhashes = try c.decodeIfPresent([String].self, forKey: .cdhashes) ?? []
        requirement = try c.decodeIfPresent(String.self, forKey: .requirement) ?? ""
        scopeHosts = try c.decodeIfPresent([String].self, forKey: .scopeHosts) ?? []
        capturedFrom = try c.decodeIfPresent(String.self, forKey: .capturedFrom) ?? ""
    }

    public var arg: JSONValue { (try? .encoding(self)) ?? .null }
}

/// Process identity preview used to create an allowlist entry.
public struct AllowlistCapturePreview: Codable, Sendable, Hashable {
    public var label: String
    public var cdhashes: [String]
    public var teamID: String
    public var bundleID: String
    public var signed: Bool
    public var authority: String
    public var capturedFrom: String
    public var publisherRequirement: String?

    public init(label: String = "", cdhashes: [String] = [], teamID: String = "",
                bundleID: String = "", signed: Bool = false, authority: String = "",
                capturedFrom: String = "", publisherRequirement: String? = nil) {
        self.label = label; self.cdhashes = cdhashes; self.teamID = teamID
        self.bundleID = bundleID; self.signed = signed; self.authority = authority
        self.capturedFrom = capturedFrom; self.publisherRequirement = publisherRequirement
    }
}

public struct Host: Codable, Sendable, Hashable, Identifiable {
    public var name: String
    public var addr: String
    public var user: String
    public var port: Int
    public var tags: [String]
    public var key: String?          // secret name (ssh-ed25519)
    public var hostkey: String       // accept-new | strict

    public var id: String { name }

    public init(name: String, addr: String, user: String, port: Int = 22,
                tags: [String] = [], key: String? = nil, hostkey: String = "accept-new") {
        self.name = name
        self.addr = addr
        self.user = user
        self.port = port
        self.tags = tags
        self.key = key
        self.hostkey = hostkey
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        name = try c.decode(String.self, forKey: .name)
        addr = try c.decode(String.self, forKey: .addr)
        user = try c.decodeIfPresent(String.self, forKey: .user) ?? ""
        port = try c.decodeIfPresent(Int.self, forKey: .port) ?? 22
        tags = try c.decodeIfPresent([String].self, forKey: .tags) ?? []
        key = try c.decodeIfPresent(String.self, forKey: .key)
        hostkey = try c.decodeIfPresent(String.self, forKey: .hostkey) ?? "accept-new"
    }

    public var arg: JSONValue {
        .compactObject([
            ("name", .string(name)),
            ("addr", .string(addr)),
            ("user", .string(user)),
            ("port", .int(port)),
            ("tags", .strings(tags)),
            ("key", .nonEmpty(key)),
            ("hostkey", .string(hostkey)),
        ])
    }
}

// MARK: - Legacy policy.simulate compatibility

/// Input for a dry-run decision preview.
public struct PolicySimInput: Sendable, Hashable {
    public var principal: String
    public var channel: String
    public var tool: String
    public var host: String
    public var method: String?

    public init(principal: String, channel: String, tool: String, host: String, method: String? = nil) {
        self.principal = principal
        self.channel = channel
        self.tool = tool
        self.host = host
        self.method = method
    }

    public var arg: JSONValue {
        // The legacy operation expects tool and identity with nested arguments.
        var args: [(String, JSONValue?)] = [
            ("host", .nonEmpty(host)),
            ("method", .nonEmpty(method)),
        ]
        let trimmedHost = host.trimmingCharacters(in: .whitespaces)
        if channel == "http", !trimmedHost.isEmpty {
            // HTTP credential binding uses args["url"].
            args.append(("url", .string("https://\(trimmedHost)")))
        }
        return .compactObject([
            ("tool", .nonEmpty(tool)),
            ("identity", .nonEmpty(principal)),
            ("args", .compactObject(args)),
        ])
    }
}

/// Result of the legacy simulation operation.
public struct PolicySimulation: Codable, Sendable, Hashable {
    public var decision: String       // allow | deny | ask
    public var rule: String?
    public var why: [String]
    public init(decision: String, rule: String? = nil, why: [String] = []) {
        self.decision = decision
        self.rule = rule
        self.why = why
    }

    // Accept an array, a legacy single string, or a missing value.
    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        decision = try c.decode(String.self, forKey: .decision)
        rule = try c.decodeIfPresent(String.self, forKey: .rule)
        if let arr = try? c.decode([String].self, forKey: .why) {
            why = arr
        } else if let s = try? c.decode(String.self, forKey: .why) {
            why = s.isEmpty ? [] : [s]
        } else {
            why = []
        }
    }
    enum CodingKeys: String, CodingKey { case decision, rule, why }
}

// MARK: - Runtime status

/// Runtime security settings.
public struct PostureSettings: Codable, Sendable, Hashable {
    /// The ceremony a NEW agent process faces: "off" (observe) | "click" | "touchid".
    public var sessionAuth: String
    /// Whether ordinary configuration changes require Touch ID.
    public var requireTouchIDForChanges: Bool
    /// Compatibility field. Currently stored but not consumed at runtime.
    public var logBodies: Bool
    /// Lock the vault N minutes after unlock; 0 = never auto-lock.
    public var autoLockMinutes: Int
    /// Whether locking the Mac also locks the vault.
    public var lockOnScreenLock: Bool

    enum CodingKeys: String, CodingKey {
        case sessionAuth, requireTouchIDForChanges, logBodies, autoLockMinutes, lockOnScreenLock
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        sessionAuth = try c.decodeIfPresent(String.self, forKey: .sessionAuth) ?? "click"
        requireTouchIDForChanges = try c.decodeIfPresent(Bool.self, forKey: .requireTouchIDForChanges) ?? true
        logBodies = try c.decodeIfPresent(Bool.self, forKey: .logBodies) ?? false
        autoLockMinutes = try c.decodeIfPresent(Int.self, forKey: .autoLockMinutes) ?? 480
        lockOnScreenLock = try c.decodeIfPresent(Bool.self, forKey: .lockOnScreenLock) ?? true
    }

    public init(sessionAuth: String = "click", requireTouchIDForChanges: Bool = true,
                logBodies: Bool = false,
                autoLockMinutes: Int = 480, lockOnScreenLock: Bool = true) {
        self.sessionAuth = sessionAuth
        self.requireTouchIDForChanges = requireTouchIDForChanges
        self.logBodies = logBodies
        self.autoLockMinutes = autoLockMinutes
        self.lockOnScreenLock = lockOnScreenLock
    }

    /// Whether a new agent process is confirmed at all (false = observe mode).
    public var perSessionAuth: Bool { sessionAuth != "off" }
}

/// One active or ended agent session.
public struct SessionInfo: Codable, Sendable, Hashable, Identifiable {
    public var key: String
    public var pid: Int
    public var name: String
    public var app: String?
    public var signed: Bool
    public var signedBy: String?
    /// How the session was admitted: "approved" | "per-call" | "observed".
    public var status: String
    /// Number of calls this session has made.
    public var calls: Int
    public var approvedAt: String
    /// Journal entries only: when and why the session ended
    /// ("exited" | "revoked" | "vault locked").
    public var endedAt: String?
    public var reason: String?

    public var id: String { key + (endedAt.map { "|" + $0 } ?? "") }
    /// App bundle name or process basename.
    public var displayName: String { app ?? name }

    enum CodingKeys: String, CodingKey {
        case key, pid, name, app, signed, signedBy, status, calls, approvedAt, endedAt, reason
    }
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        key = try c.decodeIfPresent(String.self, forKey: .key) ?? ""
        pid = try c.decodeIfPresent(Int.self, forKey: .pid) ?? 0
        name = try c.decodeIfPresent(String.self, forKey: .name) ?? ""
        app = try c.decodeIfPresent(String.self, forKey: .app)
        signed = try c.decodeIfPresent(Bool.self, forKey: .signed) ?? false
        signedBy = try c.decodeIfPresent(String.self, forKey: .signedBy)
        status = try c.decodeIfPresent(String.self, forKey: .status) ?? "approved"
        calls = try c.decodeIfPresent(Int.self, forKey: .calls) ?? 0
        approvedAt = try c.decodeIfPresent(String.self, forKey: .approvedAt) ?? ""
        endedAt = try c.decodeIfPresent(String.self, forKey: .endedAt)
        reason = try c.decodeIfPresent(String.self, forKey: .reason)
    }
    public init(key: String, pid: Int, name: String, app: String? = nil,
                signed: Bool = false, signedBy: String? = nil,
                status: String = "approved", calls: Int = 0, approvedAt: String = "",
                endedAt: String? = nil, reason: String? = nil) {
        self.key = key; self.pid = pid; self.name = name; self.app = app
        self.signed = signed; self.signedBy = signedBy
        self.status = status; self.calls = calls; self.approvedAt = approvedAt
        self.endedAt = endedAt; self.reason = reason
    }
}

/// Status reply. Fields are optional for compatibility.
public struct StatusInfo: Codable, Sendable, Hashable {
    public struct Vault: Codable, Sendable, Hashable {
        public var locked: Bool
        public var ttlSec: Int
        public init(locked: Bool, ttlSec: Int) { self.locked = locked; self.ttlSec = ttlSec }
    }
    public struct Daemon: Codable, Sendable, Hashable {
        public var version: String
        public var uptimeSec: Int
        public var home: String
        public init(version: String, uptimeSec: Int, home: String) {
            self.version = version; self.uptimeSec = uptimeSec; self.home = home
        }
    }
    public struct Counts: Codable, Sendable, Hashable {
        public var secrets: Int
        public var hosts: Int
        public init(secrets: Int, hosts: Int) {
            self.secrets = secrets; self.hosts = hosts
        }
    }

    public var vault: Vault?
    public var daemon: Daemon?
    public var counts: Counts?

    public init(vault: Vault? = nil, daemon: Daemon? = nil, counts: Counts? = nil) {
        self.vault = vault; self.daemon = daemon; self.counts = counts
    }
}
