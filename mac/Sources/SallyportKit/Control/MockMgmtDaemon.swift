import Foundation

/// In-memory management responder for demos, previews, and tests.
public actor MockMgmtDaemon {
    private var secrets: [String: SecretMetadata] = [:]
    private var secretValues: [String: String] = [:]     // write-only
    private var hosts: [String: Host] = [:]
    private var upstreams: [String: Upstream] = [:]
    private var vaultLocked = false
    private var vaultTTL = 21_600
    private var posture = PostureSettings()
    private var sessions: [SessionInfo] = [
        SessionInfo(key: "4321:1000000", pid: 4321, name: "claude", app: "Claude Code",
                    signed: true, signedBy: "Developer ID Application: Anthropic PBC (Q6L2SF6YDW)",
                    status: "approved", calls: 12, approvedAt: "2026-07-09T14:20:00Z"),
        SessionInfo(key: "5150:2000000", pid: 5150, name: "python3.13",
                    signed: false, status: "observed", calls: 3, approvedAt: "2026-07-09T15:02:00Z"),
    ]
    private var history: [SessionInfo] = [
        SessionInfo(key: "3777:900000", pid: 3777, name: "claude", app: "Claude Code",
                    signed: true, signedBy: "Developer ID Application: Anthropic PBC (Q6L2SF6YDW)",
                    status: "approved", calls: 31, approvedAt: "2026-07-09T11:00:00Z",
                    endedAt: "2026-07-09T12:40:00Z", reason: "exited"),
    ]

    public init(seeded: Bool = true) {
        guard seeded else { return }
        secrets = Self.seedSecrets
        secretValues = ["cf_token": "redacted", "gh_pat": "redacted", "ws_kz_key": "redacted"]
        hosts = Self.seedHosts
    }

    struct MockFailure: Error {
        let message: String
        let detail: JSONValue?
        let code: String?
        init(_ message: String, detail: JSONValue? = nil, code: String? = nil) {
            self.message = message
            self.detail = detail
            self.code = code
        }
    }

    /// Handle one outbound message. Returns a `mgmt.reply` for `mgmt` messages,
    /// nil for anything else (non-mgmt traffic isn't this fake's concern).
    public func handle(_ message: OutboundMessage) -> InboundMessage? {
        guard case let .mgmt(id, op, arg) = message else { return nil }
        do {
            let result = try dispatch(op: op, arg: arg)
            return .mgmtReply(id: id, ok: true, result: result, error: nil, detail: nil, code: nil)
        } catch let failure as MockFailure {
            return .mgmtReply(id: id, ok: false, result: nil, error: failure.message,
                              detail: failure.detail, code: failure.code)
        } catch {
            return .mgmtReply(id: id, ok: false, result: nil, error: "\(error)", detail: nil, code: nil)
        }
    }

    // MARK: - Dispatch

    private func dispatch(op: String, arg: JSONValue?) throws -> JSONValue {
        switch op {
        case "secrets.list":
            return try .object(["secrets": .array(sortedSecrets.map { try .encoding($0) })])
        case "secrets.set":
            try upsertSecret(arg)
            return .object([:])
        case "secrets.update":
            if let o = arg?.objectValue, let name = o["name"]?.stringValue, var m = secrets[name] {
                if let bind = o["bind"].flatMap({ try? $0.decoded([String].self) }) { m.bind = bind }
                if let h = o["header"]?.stringValue { m.header = h }
                if let f = o["format"]?.stringValue { m.format = f }
                if let c = o["confirm"]?.stringValue { m.confirm = c }
                secrets[name] = m
            }
            return .object([:])
        case "secrets.rotate":
            try rotateSecret(arg)
            return .object([:])
        case "secrets.delete":
            let name = try name(from: arg)
            secrets[name] = nil
            secretValues[name] = nil
            return .object([:])

        case "hosts.list":
            return try .object(["hosts": .array(sortedHosts.map { try .encoding($0) })])
        case "hosts.set":
            let host = try (arg ?? .null).decoded(Host.self)
            hosts[host.name] = host
            return .object([:])
        case "hosts.delete":
            hosts[try name(from: arg)] = nil
            return .object([:])

        case "upstreams.list":
            let sorted = upstreams.values.sorted { $0.name < $1.name }
            return try .object(["upstreams": .array(sorted.map { try .encoding($0) })])
        case "upstreams.set":
            let upstream = try (arg ?? .null).decoded(Upstream.self)
            upstreams[upstream.name] = upstream
            return .object([:])
        case "upstreams.delete":
            upstreams[try name(from: arg)] = nil
            return .object([:])

        case "settings.get", "settings.set":
            // The mock keeps a single posture blob; settings.set merges fields.
            if op == "settings.set", let o = arg?.objectValue {
                if let v = o["sessionAuth"]?.stringValue { posture.sessionAuth = v }
                if case let .bool(v)? = o["requireTouchIDForChanges"] { posture.requireTouchIDForChanges = v }
                if case let .bool(v)? = o["logBodies"] { posture.logBodies = v }
                if let v = o["autoLockMinutes"]?.intValue { posture.autoLockMinutes = v }
                if case let .bool(v)? = o["lockOnScreenLock"] { posture.lockOnScreenLock = v }
            }
            return try .encoding(posture)

        case "status":
            return try .encoding(currentStatus())

        case "sessions.list":
            return try .object(["sessions": .array(sessions.map { try .encoding($0) })])
        case "sessions.history":
            return try .object(["sessions": .array(history.map { try .encoding($0) })])
        case "sessions.revoke":
            if case let .object(o)? = arg, case let .string(key)? = o["key"] {
                sessions.removeAll { $0.key == key }
            }
            return .object([:])

        default:
            throw MockFailure("unknown op \"\(op)\"")
        }
    }

    // MARK: - Secrets

    private var sortedSecrets: [SecretMetadata] { secrets.values.sorted { $0.name < $1.name } }

    private func upsertSecret(_ arg: JSONValue?) throws {
        guard let object = arg?.objectValue, let name = object["name"]?.stringValue else {
            throw MockFailure("secrets.set requires a name")
        }
        let kind = object["kind"]?.stringValue ?? "bearer"
        // Use the `ENCRYPTED` marker to exercise passphrase retry.
        try Self.simulateSSHPassphrase(kind: kind,
                                       value: object["value"]?.stringValue,
                                       passphrase: object["passphrase"]?.stringValue)
        let bind = (object["bind"].flatMap { try? $0.decoded([String].self) }) ?? []
        let existing = secrets[name]
        secrets[name] = SecretMetadata(
            name: name, kind: kind, bind: bind,
            adapter: object["adapter"]?.stringValue ?? kind,
            header: object["header"]?.stringValue,
            format: object["format"]?.stringValue,
            version: Self.incremented(existing?.version),
            rotatedAt: Self.now(),
            confirm: object["confirm"]?.stringValue ?? "")
        // The value is stored write-only and omitted from listings.
        if let value = object["value"]?.stringValue { secretValues[name] = value }
    }

    /// Simulates passphrase validation for SSH key imports.
    private static func simulateSSHPassphrase(kind: String, value: String?, passphrase: String?) throws {
        guard kind.hasPrefix("ssh-"), let value, value.contains("ENCRYPTED") else { return }
        let pass = passphrase?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if pass.isEmpty {
            throw MockFailure("ssh private key is passphrase-protected; provide the passphrase",
                              code: MgmtError.passphraseRequiredCode)
        }
    }

    private func rotateSecret(_ arg: JSONValue?) throws {
        let name = try name(from: arg)
        // Rotating an SSH key can also carry a passphrase for an encrypted import.
        try Self.simulateSSHPassphrase(kind: secrets[name]?.kind ?? "",
                                       value: arg?.objectValue?["value"]?.stringValue,
                                       passphrase: arg?.objectValue?["passphrase"]?.stringValue)
        guard var meta = secrets[name] else { throw MockFailure("no such secret '\(name)'") }
        meta.version = Self.incremented(meta.version)
        meta.rotatedAt = Self.now()
        secrets[name] = meta
        if let value = arg?.objectValue?["value"]?.stringValue { secretValues[name] = value }
    }

    // MARK: - Hosts ordering

    private var sortedHosts: [Host] { hosts.values.sorted { $0.name < $1.name } }

    // MARK: - Status

    private func currentStatus() -> StatusInfo {
        StatusInfo(
            vault: .init(locked: vaultLocked, ttlSec: vaultLocked ? 0 : vaultTTL),
            daemon: .init(version: "v0.1-demo", uptimeSec: 0, home: "~/.sallyport (mock)"),
            counts: .init(secrets: secrets.count, hosts: hosts.count))
    }

    // MARK: - Helpers / seed

    private func name(from arg: JSONValue?) throws -> String {
        guard let name = arg?.objectValue?["name"]?.stringValue, !name.isEmpty else {
            throw MockFailure("operation requires a name")
        }
        return name
    }

    private static func now() -> String { ISO8601DateFormatter().string(from: Date()) }

    private static func incremented(_ value: Int?) -> Int {
        let value = value ?? 0
        return value < Int.max ? value + 1 : Int.max
    }

    // MARK: - Seed data

    private static let seedSecrets: [String: SecretMetadata] = [
        "cf_token": SecretMetadata(name: "cf_token", kind: "bearer",
                                   bind: ["api.cloudflare.com"], adapter: "bearer",
                                   format: "Bearer {secret}", version: 3,
                                   rotatedAt: "2026-07-01T09:12:00Z"),
        "gh_pat": SecretMetadata(name: "gh_pat", kind: "bearer",
                                 bind: ["api.github.com"], adapter: "bearer",
                                 format: "token {secret}", version: 1,
                                 rotatedAt: "2026-06-20T14:03:00Z"),
        "ws_kz_key": SecretMetadata(name: "ws_kz_key", kind: "ssh-ed25519",
                                    bind: [], adapter: "ssh", version: 1,
                                    rotatedAt: "2026-05-30T08:00:00Z"),
    ]

    private static let seedHosts: [String: Host] = [
        "r-kz": Host(name: "r-kz", addr: "192.168.89.1", user: "deploy", port: 22,
                     tags: ["fleet", "kz", "mikrotik"], hostkey: "accept-new"),
        "ws-kz": Host(name: "ws-kz", addr: "10.10.3.10", user: "deploy", port: 442,
                      tags: ["fleet", "kz", "nginx"], key: "ws_kz_key", hostkey: "strict"),
        "web-prod-1": Host(name: "web-prod-1", addr: "203.0.113.10", user: "deploy", port: 442,
                           tags: ["fleet", "kz", "hosting"], key: "ws_kz_key", hostkey: "accept-new"),
    ]

}
