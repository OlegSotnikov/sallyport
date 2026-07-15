import Foundation

/// The payload half of a `mgmt.reply`, after correlation by id.
public struct MgmtReplyPayload: Sendable, Equatable {
    public var ok: Bool
    public var result: JSONValue?
    public var error: String?
    public var detail: JSONValue?
    public var code: String?
    public init(ok: Bool, result: JSONValue? = nil, error: String? = nil,
                detail: JSONValue? = nil, code: String? = nil) {
        self.ok = ok
        self.result = result
        self.error = error
        self.detail = detail
        self.code = code
    }
}

/// A structured management error.
public struct MgmtError: Error, Sendable, Equatable, LocalizedError {
    public var op: String
    public var message: String
    public var detail: JSONValue?
    /// Structured error code when available.
    public var code: String?

    public init(op: String, message: String, detail: JSONValue? = nil, code: String? = nil) {
        self.op = op
        self.message = message
        self.detail = detail
        self.code = code
    }

    public var errorDescription: String? { message }


    /// Error code for an encrypted SSH private key that needs a passphrase.
    public static let passphraseRequiredCode = "passphrase_required"

    /// Whether import should prompt for a passphrase and retry.
    public var isPassphraseRequired: Bool {
        if code == Self.passphraseRequiredCode { return true }
        if code != nil { return false }
        return message.range(of: "passphrase-protected", options: .caseInsensitive) != nil
    }
}

/// Typed request/reply client for management operations.
public actor MgmtClient {
    public typealias Sender = @Sendable (OutboundMessage) async throws -> Void
    /// Optional in-process responder used by the app, previews, and tests.
    public typealias Loopback = @Sendable (OutboundMessage) async -> InboundMessage?

    public enum Failure: Error, Sendable, Equatable, LocalizedError {
        case notConnected
        case linkDropped
        case timedOut(op: String)

        public var errorDescription: String? {
            switch self {
            case .notConnected: return "Management service is unavailable."
            case .linkDropped: return "Management connection closed."
            case .timedOut(let op): return "Management request \"\(op)\" timed out."
            }
        }
    }

    private struct Pending {
        let continuation: CheckedContinuation<MgmtReplyPayload, Error>
        let timeout: Task<Void, Never>?
    }

    private let sender: Sender
    private let loopback: Loopback?
    private let idPrefix: String
    private let timeout: Duration?
    private let sleeper: @Sendable (Duration) async -> Void
    private var pending: [String: Pending] = [:]

    public init(sender: @escaping Sender,
                loopback: Loopback? = nil,
                idPrefix: String = "m",
                timeout: Duration? = .seconds(15),
                sleeper: @escaping @Sendable (Duration) async -> Void = { try? await Task.sleep(for: $0) }) {
        self.sender = sender
        self.loopback = loopback
        self.idPrefix = idPrefix
        self.timeout = timeout
        self.sleeper = sleeper
    }

    private func nextId() -> String {
        // Check the live map in case UUID generation produces a duplicate.
        while true {
            let candidate = "\(idPrefix)\(UUID().uuidString.lowercased())"
            if pending[candidate] == nil { return candidate }
        }
    }

    /// The number of in-flight requests (for tests).
    public var inFlight: Int { pending.count }

    /// Send a `mgmt` request and await its correlated reply. Returns `result` on
    /// `ok:true`; throws `MgmtError` (carrying `detail`) on `ok:false`.
    @discardableResult
    public func request(op: String, arg: JSONValue? = nil,
                        timeout timeoutOverride: Duration? = nil) async throws -> JSONValue {
        let id = nextId()
        // OAuth browser sign-in can override the default timeout.
        let timeout = timeoutOverride ?? self.timeout
        // `isolation: self` keeps the body on the actor, so registering `pending`
        // can't race with the send/loopback task that resolves it.
        let payload = try await withCheckedThrowingContinuation(isolation: self) { (cont: CheckedContinuation<MgmtReplyPayload, Error>) in
            // Arm an optional timeout that fails the request closed if no reply lands.
            var timeoutTask: Task<Void, Never>?
            if let timeout {
                let sleeper = self.sleeper
                timeoutTask = Task { [weak self] in
                    await sleeper(timeout)
                    await self?.resolve(id: id, with: .failure(Failure.timedOut(op: op)))
                }
            }
            pending[id] = Pending(continuation: cont, timeout: timeoutTask)
            // Fire the send; a send failure resolves the request immediately. If a
            // loopback is configured (mock/demo), deliver its reply back inline.
            let message = OutboundMessage.mgmt(id: id, op: op, arg: arg)
            let sender = self.sender
            let loopback = self.loopback
            Task { [weak self] in
                do {
                    try await sender(message)
                    if let loopback, let reply = await loopback(message) {
                        await self?.deliver(reply)
                    }
                } catch {
                    await self?.resolve(id: id, with: .failure(error))
                }
            }
        }
        if payload.ok { return payload.result ?? .null }
        throw MgmtError(op: op, message: payload.error ?? "mgmt \(op) failed",
                        detail: payload.detail, code: payload.code)
    }

    /// Feed an inbound message; if it is a `mgmt.reply`, resolve the matching
    /// pending request and return true. Non-mgmt messages are ignored (false), so
    /// the caller routes everything else to its normal handler.
    @discardableResult
    public func deliver(_ message: InboundMessage) -> Bool {
        guard case let .mgmtReply(id, ok, result, error, detail, code) = message else { return false }
        resolve(id: id, with: .success(
            MgmtReplyPayload(ok: ok, result: result, error: error, detail: detail, code: code)))
        return true
    }

    /// Rejects every in-flight request.
    public func failAll(_ error: Error = Failure.linkDropped) {
        let inflight = pending
        pending.removeAll()
        for (_, p) in inflight {
            p.timeout?.cancel()
            p.continuation.resume(throwing: error)
        }
    }

    private func resolve(id: String, with result: Result<MgmtReplyPayload, Error>) {
        guard let p = pending.removeValue(forKey: id) else { return }
        p.timeout?.cancel()
        p.continuation.resume(with: result)
    }
}

// MARK: - Factories

public extension MgmtClient {

    /// In-memory client for demos, previews, and tests.
    static func mock(daemon: MockMgmtDaemon = MockMgmtDaemon(),
                     timeout: Duration? = nil) -> MgmtClient {
        MgmtClient(sender: { _ in },
                   loopback: { message in await daemon.handle(message) },
                   timeout: timeout)
    }
}

// MARK: - Typed operations (thin wrappers over `request`)

public extension MgmtClient {
    // Secret listings contain metadata only. Set and rotate carry the value.
    func listSecrets() async throws -> [SecretMetadata] {
        let result = try await request(op: "secrets.list")
        return try result.arrayField("secrets").decoded([SecretMetadata].self)
    }
    func setSecret(_ input: SecretInput) async throws {
        try await request(op: "secrets.set", arg: input.arg)
    }
    func rotateSecret(name: String, value: String) async throws {
        try await request(op: "secrets.rotate",
                          arg: .compactObject([("name", .string(name)), ("value", .string(value))]))
    }
    func deleteSecret(name: String) async throws {
        try await request(op: "secrets.delete", arg: .compactObject([("name", .string(name))]))
    }
    /// Updates secret metadata without sending the value.
    func updateSecret(name: String, bind: [String], header: String?, format: String?,
                      confirm: String, insecureTLS: Bool? = nil) async throws {
        var fields: [(String, JSONValue)] = [
            ("name", .string(name)),
            ("bind", .array(bind.map { .string($0) })),
            ("confirm", .string(confirm)),
        ]
        if let insecureTLS { fields.append(("insecure_tls", .bool(insecureTLS))) }
        if let header { fields.append(("header", .string(header))) }
        if let format { fields.append(("format", .string(format))) }
        try await request(op: "secrets.update", arg: .compactObject(fields))
    }

    // SSH hosts.
    func listHosts() async throws -> [Host] {
        let result = try await request(op: "hosts.list")
        return try result.arrayField("hosts").decoded([Host].self)
    }
    func setHost(_ host: Host) async throws {
        try await request(op: "hosts.set", arg: host.arg)
    }
    func deleteHost(name: String) async throws {
        try await request(op: "hosts.delete", arg: .compactObject([("name", .string(name))]))
    }

    // Upstream MCP servers.
    func listUpstreams() async throws -> [Upstream] {
        let result = try await request(op: "upstreams.list")
        return try result.arrayField("upstreams").decoded([Upstream].self)
    }
    func setUpstream(_ upstream: Upstream) async throws {
        try await request(op: "upstreams.set", arg: upstream.arg)
    }
    func deleteUpstream(name: String) async throws {
        try await request(op: "upstreams.delete", arg: .compactObject([("name", .string(name))]))
    }

    // Agent allowlist.
    func listAllowlist() async throws -> [AllowlistItem] {
        let result = try await request(op: "allowlist.list")
        return try result.arrayField("allowlist").decoded([AllowlistItem].self)
    }
    /// Captures an identity from a process or file.
    func captureAllowlist(pid: Int? = nil, path: String? = nil) async throws -> AllowlistCapturePreview {
        var fields: [(String, JSONValue)] = []
        if let pid { fields.append(("pid", .int(pid))) }
        if let path { fields.append(("path", .string(path))) }
        let result = try await request(op: "allowlist.capture", arg: .compactObject(fields))
        return try result.field("capture").decoded(AllowlistCapturePreview.self)
    }
    func addAllowlist(_ item: AllowlistItem) async throws {
        try await request(op: "allowlist.add", arg: item.arg)
    }
    func deleteAllowlist(id: String) async throws {
        try await request(op: "allowlist.delete", arg: .compactObject([("id", .string(id))]))
    }
    /// Runs OAuth 2.1 sign-in and returns the updated server.
    func authorizeUpstream(name: String) async throws -> Upstream {
        // Allow enough time for browser sign-in and the server deadline.
        try await request(op: "upstreams.authorize",
                          arg: .compactObject([("name", .string(name))]),
                          timeout: .seconds(360)).decoded(Upstream.self)
    }
    /// Forget an OAuth upstream's tokens.
    func disconnectUpstream(name: String) async throws {
        try await request(op: "upstreams.disconnect", arg: .compactObject([("name", .string(name))]))
    }

    // Status.
    func status() async throws -> StatusInfo {
        try await request(op: "status").decoded(StatusInfo.self)
    }

    // Settings.
    func settings() async throws -> PostureSettings {
        try await request(op: "settings.get").decoded(PostureSettings.self)
    }
    /// Applies only the supplied settings and returns the result.
    @discardableResult
    func updateSettings(sessionAuth: String? = nil, requireTouchIDForChanges: Bool? = nil,
                        logBodies: Bool? = nil,
                        autoLockMinutes: Int? = nil, lockOnScreenLock: Bool? = nil) async throws -> PostureSettings {
        var fields: [(String, JSONValue)] = []
        if let sessionAuth { fields.append(("sessionAuth", .string(sessionAuth))) }
        if let requireTouchIDForChanges {
            fields.append(("requireTouchIDForChanges", .bool(requireTouchIDForChanges)))
        }
        if let logBodies { fields.append(("logBodies", .bool(logBodies))) }
        if let autoLockMinutes { fields.append(("autoLockMinutes", .int(autoLockMinutes))) }
        if let lockOnScreenLock { fields.append(("lockOnScreenLock", .bool(lockOnScreenLock))) }
        return try await request(op: "settings.set", arg: .compactObject(fields)).decoded(PostureSettings.self)
    }

    // Ended sessions, newest first.
    func sessionsHistory() async throws -> [SessionInfo] {
        try await request(op: "sessions.history").arrayField("sessions").decoded([SessionInfo].self)
    }

    // Active agent sessions.
    func listSessions() async throws -> [SessionInfo] {
        try await request(op: "sessions.list").arrayField("sessions").decoded([SessionInfo].self)
    }
    func revokeSession(key: String) async throws {
        try await request(op: "sessions.revoke", arg: .compactObject([("key", .string(key))]))
    }
}

private extension JSONValue {
    /// Returns an empty array for a missing or null field.
    func arrayField(_ key: String) -> JSONValue {
        guard let v = objectValue?[key] else { return .array([]) }
        if case .null = v { return .array([]) }
        return v
    }

    /// A single object field, or `.null` if absent.
    func field(_ key: String) -> JSONValue { objectValue?[key] ?? .null }
}
