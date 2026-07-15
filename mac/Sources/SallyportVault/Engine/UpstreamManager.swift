import Foundation
import SallyportKit
import Darwin

/// Errors from the upstream MCP channel.
public enum UpstreamError: Error, CustomStringConvertible, Sendable {
    case spawnFailed(String, String)      // upstream, reason
    case protocolError(String, String)    // upstream, reason
    case timeout(String)                  // upstream
    case down(String)                     // upstream (exited / killed)

    public var description: String {
        switch self {
        case .spawnFailed(let u, let r): return "Upstream \"\(u)\" failed to start: \(r)"
        case .protocolError(let u, let r): return "Upstream \"\(u)\": \(r)"
        case .timeout(let u): return "Upstream \"\(u)\" timed out."
        case .down(let u): return "Upstream \"\(u)\" is not running."
        }
    }
}

/// Local or remote MCP connection. It returns injected values with each response
/// so the engine can redact any echoed credentials.
protocol MCPConnection: AnyObject, Sendable {
    var isAlive: Bool { get }
    func start(timeout: TimeInterval) async throws
    func listTools(timeout: TimeInterval) async throws -> [JSONValue]
    func callTool(_ tool: String, arguments: [String: JSONValue],
                  timeout: TimeInterval) async throws -> (output: [String: JSONValue], injected: [Data])
    func terminate()
}

/// Manages configured MCP servers and forwards approved `<name>.<tool>` calls.
/// Stdio credentials are injected into child environments; HTTP credentials are
/// attached per request. Upstreams run only while the vault is open, and
/// `killAll()` terminates child processes and remote sessions on lock.
public final class UpstreamManager: @unchecked Sendable {

    /// Per-call ceiling; an upstream that answers slower is assumed wedged.
    static let callTimeout: TimeInterval = 120
    /// Handshake ceiling (npx/uvx cold starts are slow, but not minutes).
    static let startTimeout: TimeInterval = 45

    private let store: VaultStore
    private let netGuard = NetGuard()
    /// Cookie-free client that refuses redirects for OAuth requests.
    private let oauthSession: URLSession = {
        let c = URLSessionConfiguration.ephemeral
        c.httpShouldSetCookies = false
        c.httpCookieAcceptPolicy = .never
        c.urlCache = nil
        c.requestCachePolicy = .reloadIgnoringLocalCacheData
        return URLSession(configuration: c, delegate: RefuseRedirects.shared, delegateQueue: nil)
    }()
    private let lock = NSLock()
    private var connections: [String: any MCPConnection] = [:]
    /// One-shot stdio children tracked so `killAll` can stop them mid-call.
    private var oneShots: [ObjectIdentifier: any MCPConnection] = [:]
    /// In-flight connections deduplicated by upstream name.
    private var pending: [String: Task<any MCPConnection, any Error>] = [:]
    /// Per-name token that invalidates connections started before a kill or change.
    private var generation: [String: UUID] = [:]
    /// OAuth refreshes deduplicated by upstream name.
    private var refreshing: [String: Task<String, any Error>] = [:]
    /// Raw (un-namespaced) tools/list result per running upstream.
    private var toolCache: [String: [JSONValue]] = [:]

    public init(store: VaultStore) {
        self.store = store
    }

    // MARK: - Lifecycle

    /// Background warm-up after unlock: spawn every enabled upstream so the
    /// tool catalog is ready when the first agent asks. Failures are logged
    /// and left to the lazy respawn path; they never block the unlock.
    public func warmUp(_ entries: [UpstreamsStore.Entry]) async {
        for entry in entries where entry.enabled {
            // Per-call credentials must not be attached during warm-up.
            if await hasPerCallKey(entry) {
                LogSink.line("upstream \"\(entry.name)\" has a per-call key; skipping warm-up")
                continue
            }
            do { _ = try await connection(for: entry) }
            catch { LogSink.line("upstream \"\(entry.name)\" warm-up failed: \(error)") }
        }
    }

    /// Whether server or key settings require per-call approval.
    private func hasPerCallKey(_ entry: UpstreamsStore.Entry) async -> Bool {
        // Server-level approval applies to every transport, including OAuth.
        if !entry.confirm.isEmpty { return true }
        do {
            if entry.transport == UpstreamsStore.Entry.httpTransport {
                // OAuth without server-level confirmation has no per-call key.
                if entry.auth == UpstreamsStore.Entry.oauthAuth { return false }
                let (h, p) = Engine.hostPath(.string(entry.url))
                return !((try await store.boundMeta(host: h, path: p)?.confirm ?? "").isEmpty)
            }
            for binding in entry.keys {
                if !((try await store.meta(name: binding.secret)?.confirm ?? "").isEmpty) { return true }
            }
            return false
        } catch {
            // Skip warm-up if confirmation settings cannot be read.
            return true
        }
    }

    /// Terminate every upstream and drop the tool cache. Called on vault lock
    /// (children hold injected secrets) and on app shutdown. Synchronous.
    public func killAll() {
        let victims: [any MCPConnection]
        let pendingTasks: [Task<any MCPConnection, any Error>]
        let refreshTasks: [Task<String, any Error>]
        (victims, pendingTasks, refreshTasks) = lock.withLock {
            var v = Array(connections.values)
            v.append(contentsOf: oneShots.values)     // in-flight one-shot children
            let p = Array(pending.values)             // in-flight establishments
            let r = Array(refreshing.values)          // in-flight OAuth refreshes
            connections = [:]
            oneShots = [:]
            toolCache = [:]
            for name in Array(generation.keys) { generation[name] = UUID() }
            return (v, p, r)
        }
        // Cancel pending connections and refreshes before terminating live ones.
        for t in pendingTasks { t.cancel() }
        for t in refreshTasks { t.cancel() }
        for conn in victims { conn.terminate() }
    }

    /// Terminate one upstream (config changed / deleted). Next call respawns
    /// it from the fresh entry.
    public func kill(name: String) {
        let (victim, pendingTask): ((any MCPConnection)?, Task<any MCPConnection, any Error>?) = lock.withLock {
            toolCache[name] = nil
            generation[name] = UUID()   // invalidate any in-flight establish
            return (connections.removeValue(forKey: name), pending[name])
        }
        pendingTask?.cancel()
        victim?.terminate()
    }

    // MARK: - Catalog

    /// Namespaced tool definitions from running upstreams.
    public func namespacedToolDefs() -> [JSONValue] {
        let cache = lock.withLock { toolCache }
        return cache.sorted { $0.key < $1.key }.flatMap { (upstream, tools) in
            tools.compactMap { tool -> JSONValue? in
                guard case .object(var o) = tool,
                      let raw = o["name"]?.stringValue else { return nil }
                // Preserve each definition and prefix only its tool name.
                o["name"] = .string("\(upstream).\(raw)")
                return .object(o)
            }
        }
    }

    // MARK: - Calls

    /// Forward one ladder-approved call. Returns the upstream's result object
    /// plus the exact secret values injected into that upstream's environment,
    /// so the engine can DLP-scrub any echo of them out of the output.
    public func call(entry: UpstreamsStore.Entry, tool: String,
                     args: [String: JSONValue]) async throws -> (output: [String: JSONValue], injected: [Data]) {
        // Use a one-shot stdio child when its environment carries a per-call key.
        if entry.transport == UpstreamsStore.Entry.stdioTransport, await hasPerCallKey(entry) {
            if await store.locked() { throw VaultStoreError.locked }
            let conn = try await makeConnection(for: entry)
            let key = ObjectIdentifier(conn)
            lock.withLock { oneShots[key] = conn }
            defer { lock.withLock { oneShots[key] = nil }; conn.terminate() }
            try await conn.start(timeout: Self.startTimeout)
            // Abort if the vault locked during startup.
            if await store.locked() { throw VaultStoreError.locked }
            return try await conn.callTool(tool, arguments: args, timeout: Self.callTimeout)
        }
        let conn = try await connection(for: entry)
        return try await conn.callTool(tool, arguments: args, timeout: Self.callTimeout)
    }

    // MARK: - Connections

    private func connection(for entry: UpstreamsStore.Entry) async throws -> any MCPConnection {
        if let existing = lock.withLock({ connections[entry.name] }), existing.isAlive {
            return existing
        }
        // Dedup concurrent establishment: the first caller creates the task,
        // everyone else awaits the same one.
        let (task, isOwner): (Task<any MCPConnection, any Error>, Bool) = lock.withLock {
            if let inFlight = pending[entry.name] { return (inFlight, false) }
            let t = Task { try await self.establish(entry) }
            pending[entry.name] = t
            return (t, true)
        }
        defer {
            if isOwner { lock.withLock { pending[entry.name] = nil } }
        }
        return try await task.value
    }

    private func establish(_ entry: UpstreamsStore.Entry) async throws -> any MCPConnection {
        // Register a lifecycle token before connecting so `killAll` can invalidate
        // even the first connection attempt.
        let startGen = lock.withLock { () -> UUID in
            if let existing = generation[entry.name] { return existing }
            let fresh = UUID()
            generation[entry.name] = fresh
            return fresh
        }
        let conn = try await makeConnection(for: entry)
        do {
            try await conn.start(timeout: Self.startTimeout)
            let tools = try await conn.listTools(timeout: Self.startTimeout)
            // Do not register a connection that finished after lock.
            if await store.locked() {
                conn.terminate()
                throw VaultStoreError.locked
            }
            // Register only if the upstream was not killed or reconfigured during
            // startup. Terminate any replaced connection explicitly.
            let outcome: (register: Bool, evicted: (any MCPConnection)?) = lock.withLock {
                guard generation[entry.name] == startGen else {
                    return (false, nil)
                }
                let old = connections[entry.name]
                connections[entry.name] = conn
                toolCache[entry.name] = tools
                return (true, old)
            }
            guard outcome.register else {
                conn.terminate()
                throw UpstreamError.down(entry.name)
            }
            if let evicted = outcome.evicted, evicted !== conn { evicted.terminate() }
            return conn
        } catch {
            conn.terminate()
            throw error
        }
    }

    private func makeConnection(for entry: UpstreamsStore.Entry) async throws -> any MCPConnection {
        if entry.transport == UpstreamsStore.Entry.httpTransport {
            guard let endpoint = Self.validatedRemoteURL(entry.url) else {
                throw UpstreamError.spawnFailed(entry.name,
                    "Invalid endpoint URL. HTTPS is required except for loopback HTTP.")
            }
            if entry.usesOAuth {
                // Refresh and reseal OAuth access tokens at call time.
                let name = entry.name
                let resource = endpoint.absoluteString
                return RemoteMCPConnection(
                    name: name, endpoint: endpoint,
                    bearer: { [weak self] in
                        guard let self else { throw UpstreamError.down(name) }
                        return try await self.freshAccessToken(upstream: name, resource: resource)
                    })
            }
            // Resolve the host-bound credential for each request.
            let storeRef = store
            let host = endpoint.host ?? ""
            let path = endpoint.path.isEmpty ? "/" : endpoint.path
            return RemoteMCPConnection(name: entry.name, endpoint: endpoint,
                                       resolveCred: { try await storeRef.resolve(host: host, path: path) })
        }

        // Resolve stdio environment keys immediately before spawning.
        var env = entry.env
        var injected: [Data] = []
        for binding in entry.keys {
            let value = try await store.secretValue(name: binding.secret)
            env[binding.envVar] = String(decoding: value, as: UTF8.self)
            injected.append(value)
        }
        return try StdioMCPConnection(
            name: entry.name, command: entry.command, args: entry.args,
            extraEnv: env, injected: injected,
            onExit: { [weak self] name in
                guard let self else { return }
                self.lock.withLock {
                    if self.connections[name]?.isAlive != true {
                        self.connections[name] = nil
                        self.toolCache[name] = nil
                    }
                }
            })
    }

    // MARK: - OAuth 2.1

    /// What the UI shows for an OAuth upstream.
    public struct OAuthStatus: Sendable, Equatable {
        public var connected: Bool
        public var account: String
        public var expiry: Date?
        public var canRefresh: Bool
    }

    /// The sealed grant for `upstream`, or nil when it has never signed in.
    /// Requires the unlocked vault (the grant is sealed under the DEK).
    func grant(upstream: String) async throws -> MCPOAuth.Grant? {
        guard let data = try await store.blob(key: MCPOAuth.Grant.blobKey(upstream: upstream)) else {
            return nil
        }
        return try? JSONDecoder().decode(MCPOAuth.Grant.self, from: data)
    }

    private func seal(_ grant: MCPOAuth.Grant, upstream: String) async throws {
        let data = try JSONEncoder().encode(grant)
        try await store.setBlob(key: MCPOAuth.Grant.blobKey(upstream: upstream), data: data)
    }

    /// Sign-in status for the UI. A locked vault reports "not connected" rather
    /// than leaking that a grant exists.
    public func oauthStatus(upstream: String) async -> OAuthStatus {
        guard let g = ((try? await grant(upstream: upstream)) ?? nil) else {
            return OAuthStatus(connected: false, account: "", expiry: nil, canRefresh: false)
        }
        return OAuthStatus(connected: !g.accessToken.isEmpty || !g.refreshToken.isEmpty,
                           account: g.account, expiry: g.expiry, canRefresh: !g.refreshToken.isEmpty)
    }

    /// Forget an upstream's tokens (and drop its live session).
    public func oauthDisconnect(upstream: String) async throws {
        try await store.setBlob(key: MCPOAuth.Grant.blobKey(upstream: upstream), data: Data())
        kill(name: upstream)
    }

    /// Runs browser-based OAuth sign-in and seals the resulting tokens.
    @discardableResult
    public func oauthAuthorize(entry: UpstreamsStore.Entry,
                               openBrowser: @escaping @Sendable (URL) -> Void,
                               timeout: TimeInterval = 300) async throws -> OAuthStatus {
        guard entry.usesOAuth, let endpoint = Self.validatedRemoteURL(entry.url) else {
            throw UpstreamError.spawnFailed(entry.name, "not an OAuth MCP server")
        }
        if await store.locked() { throw VaultStoreError.locked }

        let existing = try await grant(upstream: entry.name)
        let allowPrivate = MCPOAuth.allowsPrivate(endpoint: endpoint)
        let meta = try await MCPOAuth.discover(endpoint: endpoint, session: oauthSession,
                                               netGuard: netGuard, timeout: 30)

        // Reuse a registered redirect port when available.
        let preferredPort = existing.flatMap { URL(string: $0.redirectURI)?.port } ?? 0
        let listener = try LoopbackCallbackServer(preferredPort: preferredPort)
        defer { listener.close() }
        let redirectURI = listener.redirectURI

        var clientID = existing?.clientID ?? ""
        var clientSecret = existing?.clientSecret ?? ""
        if clientID.isEmpty || existing?.redirectURI != redirectURI {
            let registered = try await MCPOAuth.register(metadata: meta, redirectURI: redirectURI,
                                                         session: oauthSession, netGuard: netGuard,
                                                         allowPrivate: allowPrivate, timeout: 30)
            clientID = registered.id
            clientSecret = registered.secret
        }

        let pkce = MCPOAuth.PKCE()
        let state = MCPOAuth.randomState()
        let resource = endpoint.absoluteString
        let scopes: String
        if let existing, !existing.scopes.isEmpty {
            scopes = existing.scopes
        } else {
            scopes = meta.scopesSupported
        }
        let authorizeURL = try MCPOAuth.authorizeURL(
            metadata: meta, clientID: clientID, redirectURI: redirectURI,
            scopes: scopes, resource: resource, pkce: pkce, state: state,
            allowPrivate: allowPrivate)

        openBrowser(authorizeURL)
        let callback = try await listener.wait(timeout: timeout)
        // CSRF: the state we generated must come back verbatim.
        guard callback.state == state else {
            throw MCPOAuth.OAuthError.authorizationFailed("Callback state did not match.")
        }

        let token = try await MCPOAuth.exchange(
            code: callback.code, metadata: meta, clientID: clientID, clientSecret: clientSecret,
            redirectURI: redirectURI, resource: resource, verifier: pkce.verifier,
            session: oauthSession, netGuard: netGuard, allowPrivate: allowPrivate, timeout: 30)

        // Do not store tokens if the vault locked during browser sign-in.
        if await store.locked() { throw VaultStoreError.locked }

        let fresh = MCPOAuth.Grant(
            issuer: meta.issuer, authorizeEndpoint: meta.authorize, tokenEndpoint: meta.token,
            registrationEndpoint: meta.registration, clientID: clientID, clientSecret: clientSecret,
            redirectURI: redirectURI,
            scopes: token.scopes.isEmpty ? scopes : token.scopes,
            resource: resource, accessToken: token.access, refreshToken: token.refresh,
            expiry: token.expiry, account: endpoint.host ?? entry.name)
        try await seal(fresh, upstream: entry.name)

        // Reconnect with the new token on the next call.
        kill(name: entry.name)
        return OAuthStatus(connected: true, account: fresh.account, expiry: fresh.expiry,
                           canRefresh: !fresh.refreshToken.isEmpty)
    }

    /// Returns a fresh access token, deduplicating refreshes by upstream.
    private func freshAccessToken(upstream: String, resource: String) async throws -> String {
        let (task, isOwner): (Task<String, any Error>, Bool) = lock.withLock {
            if let inFlight = refreshing[upstream] { return (inFlight, false) }
            let t = Task { try await self.refreshLocked(upstream: upstream, resource: resource) }
            refreshing[upstream] = t
            return (t, true)
        }
        // Only the task that created this refresh may clear its slot.
        defer { if isOwner { lock.withLock { refreshing[upstream] = nil } } }
        return try await task.value
    }

    private func refreshLocked(upstream: String, resource: String) async throws -> String {
        guard let g = try await grant(upstream: upstream), !g.accessToken.isEmpty || !g.refreshToken.isEmpty else {
            throw MCPOAuth.OAuthError.notSignedIn(upstream)
        }
        // Clear tokens issued for a different endpoint resource.
        guard g.resource == resource else {
            try? await store.setBlob(key: MCPOAuth.Grant.blobKey(upstream: upstream), data: Data())
            throw MCPOAuth.OAuthError.notSignedIn(upstream)
        }
        if g.isFresh() { return g.accessToken }
        let refreshed: (access: String, refresh: String, expiry: Date, scopes: String)
        do {
            refreshed = try await MCPOAuth.refresh(grant: g, session: oauthSession,
                                                   netGuard: netGuard, timeout: 30)
        } catch MCPOAuth.OAuthError.grantRevoked {
            // Clear a permanently rejected refresh token so the UI can reconnect.
            try? await store.setBlob(key: MCPOAuth.Grant.blobKey(upstream: upstream), data: Data())
            throw MCPOAuth.OAuthError.notSignedIn(upstream)
        }
        // Preserve the stored grant after transient failures.
        var updated = g
        updated.accessToken = refreshed.access
        updated.refreshToken = refreshed.refresh
        updated.expiry = refreshed.expiry
        updated.scopes = refreshed.scopes
        try await seal(updated, upstream: upstream)
        return updated.accessToken
    }

    /// Accepts HTTPS endpoints and loopback HTTP endpoints.
    public static func validatedRemoteURL(_ raw: String) -> URL? {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = URL(string: s), let host = url.host, !host.isEmpty else { return nil }
        switch url.scheme?.lowercased() {
        case "https":
            return url
        case "http":
            let h = host.lowercased()
            if h == "localhost" || IPAddr(h)?.unmapped().isLoopback == true { return url }
            return nil
        default:
            return nil
        }
    }
}

/// Minimal stderr logger for the vault module (mirrors the app's `Log`).
enum LogSink {
    static func line(_ message: @autoclosure () -> String) {
        guard ProcessInfo.processInfo.environment["SALLYPORT_LOG"] == "1"
            || ProcessInfo.processInfo.environment["SALLYPORT_DEV_AUTOAPPROVE"] == "1" else { return }
        FileHandle.standardError.write(Data(("sallyport-vault: " + message() + "\n").utf8))
    }
}

enum JSONRPCRequestIDError: Error, Equatable { case exhausted }

/// Issues unique string IDs for one connection and reports exhaustion at UInt64.max.
struct JSONRPCRequestIDSequence {
    private var nextValue: UInt64
    private var exhausted = false

    init(nextValue: UInt64 = 1) { self.nextValue = nextValue }

    mutating func take() throws -> String {
        guard !exhausted else { throw JSONRPCRequestIDError.exhausted }
        let result = String(nextValue)
        if nextValue == UInt64.max {
            exhausted = true
        } else {
            nextValue += 1
        }
        return result
    }
}

/// Total conversion for untrusted timeout values. Invalid/non-positive values
/// become an immediate timeout; huge finite values saturate instead of trapping
/// during Double-to-UInt64 conversion.
func timeoutNanoseconds(_ seconds: TimeInterval) -> UInt64 {
    guard seconds.isFinite, seconds > 0 else { return 0 }
    let largestWholeSeconds = TimeInterval(UInt64.max / 1_000_000_000)
    guard seconds < largestWholeSeconds else { return UInt64.max }
    return UInt64((seconds * 1_000_000_000).rounded(.up))
}

func timeoutDeadline(after seconds: TimeInterval,
                     now: UInt64 = DispatchTime.now().uptimeNanoseconds) -> UInt64 {
    let delta = timeoutNanoseconds(seconds)
    guard delta < UInt64.max, delta <= UInt64.max - now else { return UInt64.max }
    return now + delta
}

// MARK: - One stdio MCP connection

/// Spawned MCP server using newline-delimited JSON-RPC over stdin and stdout.
final class StdioMCPConnection: MCPConnection, @unchecked Sendable {

    /// Maximum response-line size.
    private static let maxLineBytes = 8 * 1024 * 1024
    private static let readChunkBytes = 64 * 1024

    private let name: String
    private let process: Process
    private let stdinHandle: FileHandle
    private let stdoutHandle: FileHandle
    private let onExit: @Sendable (String) -> Void

    private let lock = NSLock()
    /// JSON-RPC frames share one byte stream. Serialize them so concurrent calls
    /// cannot interleave, and use raw nonblocking writes under a hard deadline.
    private let writeLock = NSLock()
    private var framer = LineFramer(maxLineBytes: maxLineBytes)
    private var requestIDs = JSONRPCRequestIDSequence()
    private var pending: [String: CheckedContinuation<[String: JSONValue], any Error>] = [:]
    private var terminated = false
    /// Environment values retained for response redaction and cleared on termination.
    private var injected: [Data]

    var isAlive: Bool { process.isRunning }

    init(name: String, command: String, args: [String], extraEnv: [String: String],
         injected: [Data], onExit: @escaping @Sendable (String) -> Void) throws {
        self.name = name
        self.onExit = onExit
        self.injected = injected

        let proc = Process()
        // `/usr/bin/env` resolves bare command names ("npx", "uvx") through
        // PATH; an absolute path passes through unchanged. The app's own PATH
        // is minimal, so the common tool locations are appended.
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        proc.arguments = [command] + args
        var env = ProcessInfo.processInfo.environment
        let extraPath = "/usr/local/bin:/opt/homebrew/bin"
        env["PATH"] = (env["PATH"].map { "\($0):" } ?? "") + extraPath
        for (k, v) in extraEnv { env[k] = v }
        proc.environment = env

        let stdin = Pipe(), stdout = Pipe()
        proc.standardInput = stdin
        proc.standardOutput = stdout
        // Discard stderr so an undrained pipe cannot block the child.
        proc.standardError = FileHandle.nullDevice
        self.process = proc
        self.stdinHandle = stdin.fileHandleForWriting
        self.stdoutHandle = stdout.fileHandleForReading
        // The child can exit between `isRunning` and a JSON-RPC write. Turn that
        // race into EPIPE for the existing error path instead of SIGPIPE killing
        // the entire vault process.
        guard fcntl(self.stdinHandle.fileDescriptor, F_SETNOSIGPIPE, 1) == 0 else {
            throw UpstreamError.spawnFailed(name, "could not suppress SIGPIPE on upstream stdin")
        }
        let currentFlags = fcntl(self.stdinHandle.fileDescriptor, F_GETFL)
        guard currentFlags >= 0,
              fcntl(self.stdinHandle.fileDescriptor, F_SETFL, currentFlags | O_NONBLOCK) == 0 else {
            throw UpstreamError.spawnFailed(name, "could not make upstream stdin deadline-bounded")
        }
        let stdoutFlags = fcntl(self.stdoutHandle.fileDescriptor, F_GETFL)
        guard stdoutFlags >= 0,
              fcntl(self.stdoutHandle.fileDescriptor, F_SETFL, stdoutFlags | O_NONBLOCK) == 0 else {
            throw UpstreamError.spawnFailed(name, "could not bound upstream stdout reads")
        }

        stdoutHandle.readabilityHandler = { [weak self] _ in
            self?.readAvailableOutput()
        }
        proc.terminationHandler = { [weak self] _ in
            guard let self else { return }
            self.failAllPending(UpstreamError.down(name))
            self.stdoutHandle.readabilityHandler = nil
            onExit(name)
        }
        do {
            try proc.run()
        } catch {
            throw UpstreamError.spawnFailed(name, error.localizedDescription)
        }
    }

    /// Runs `initialize`, then sends `notifications/initialized`.
    func start(timeout: TimeInterval) async throws {
        _ = try await request(method: "initialize", params: [
            "protocolVersion": "2024-11-05",
            "capabilities": [:] as [String: Any],
            "clientInfo": ["name": "sallyport", "version": "1.0"],
        ], timeout: timeout)
        try notify(method: "notifications/initialized", timeout: timeout)
    }

    /// The upstream's raw tool catalog.
    func listTools(timeout: TimeInterval) async throws -> [JSONValue] {
        let result = try await request(method: "tools/list", params: [:], timeout: timeout)
        if case let .array(tools)? = result["tools"] { return tools }
        return []
    }

    /// One proxied tools/call. Returns the whole MCP result object
    /// (`content`, `isError`, and related fields) as engine output, plus copies of the env-injected
    /// secret values for post-call DLP scrubbing (the engine zeroizes ITS
    /// copies after redaction; ours live until terminate).
    func callTool(_ tool: String, arguments: [String: JSONValue],
                  timeout: TimeInterval) async throws -> (output: [String: JSONValue], injected: [Data]) {
        guard let boundedArguments = try JSONValue.object(arguments).boundedFoundation()
                as? [String: Any] else {
            throw UpstreamError.protocolError(name, "arguments exceed JSON resource limits")
        }
        let result = try await request(method: "tools/call", params: [
            "name": tool,
            "arguments": boundedArguments,
        ], timeout: timeout)
        return (result, lock.withLock { injected.map { Data($0) } })
    }

    /// SIGTERM, then SIGKILL after a short grace. Zeroizes the retained
    /// injected values and fails every in-flight call.
    func terminate() {
        let alreadyDone: Bool = lock.withLock {
            defer { terminated = true }
            return terminated
        }
        guard !alreadyDone else { return }
        failAllPending(UpstreamError.down(name))
        lock.withLock {
            for i in injected.indices { injected[i].resetBytes(in: 0..<injected[i].count) }
            injected.removeAll()
        }
        stdoutHandle.readabilityHandler = nil
        guard process.isRunning else { return }
        process.terminate()
        let proc = process
        DispatchQueue.global().asyncAfter(deadline: .now() + 3) {
            if proc.isRunning { kill(proc.processIdentifier, SIGKILL) }
        }
    }

    // MARK: JSON-RPC plumbing

    private func request(method: String, params: [String: Any],
                         timeout: TimeInterval) async throws -> [String: JSONValue] {
        guard process.isRunning else { throw UpstreamError.down(name) }
        let id: String
        do {
            id = try lock.withLock { try requestIDs.take() }
        } catch {
            throw UpstreamError.protocolError(name, "JSON-RPC request id space exhausted")
        }
        let frame: [String: Any] = ["jsonrpc": "2.0", "id": id, "method": method, "params": params]
        let boundedTimeout = timeout.isFinite && timeout > 0 ? timeout : 0
        let deadline = Self.writeDeadline(after: boundedTimeout)

        return try await withCheckedThrowingContinuation { cont in
            lock.withLock { pending[id] = cont }
            // Arm before serializing/writing. A live child that never reads can
            // fill the pipe and otherwise prevent the timeout from ever existing.
            DispatchQueue.global().asyncAfter(
                deadline: DispatchTime(uptimeNanoseconds: deadline)) { [weak self] in
                guard let self else { return }
                if let c = self.lock.withLock({ self.pending.removeValue(forKey: id) }) {
                    c.resume(throwing: UpstreamError.timeout(self.name))
                    self.terminate()
                }
            }
            do {
                try write(frame, deadline: deadline)
            } catch {
                if let c = lock.withLock({ pending.removeValue(forKey: id) }) {
                    c.resume(throwing: error)
                    terminate()
                }
            }
        }
    }

    private func notify(method: String, timeout: TimeInterval) throws {
        try write(["jsonrpc": "2.0", "method": method],
                  deadline: Self.writeDeadline(after: timeout))
    }

    private static func writeDeadline(after timeout: TimeInterval) -> UInt64 {
        timeoutDeadline(after: timeout)
    }

    private func write(_ obj: [String: Any], deadline: UInt64) throws {
        var data = try JSONSerialization.data(withJSONObject: obj)
        data.append(0x0A)
        guard !data.isEmpty else { return }
        guard data.count <= Self.maxLineBytes else {
            throw UpstreamError.protocolError(name, "outbound frame exceeds limit")
        }
        writeLock.lock()
        defer { writeLock.unlock() }

        let fd = stdinHandle.fileDescriptor
        try data.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else {
                throw UpstreamError.protocolError(name, "outbound frame has no storage")
            }
            var offset = 0
            while offset < raw.count {
                let now = DispatchTime.now().uptimeNanoseconds
                guard now < deadline else { throw UpstreamError.timeout(name) }
                let written = Darwin.write(fd, base.advanced(by: offset), raw.count - offset)
                if written > 0 {
                    offset += written
                    continue
                }
                if written < 0, errno == EINTR { continue }
                if written < 0, errno == EAGAIN || errno == EWOULDBLOCK {
                    let remaining = deadline - now
                    var milliseconds = remaining / 1_000_000
                    if remaining % 1_000_000 != 0 { milliseconds += 1 }
                    let wait = Int32(min(milliseconds, UInt64(Int32.max)))
                    var descriptor = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
                    let result = Darwin.poll(&descriptor, 1, wait)
                    if result > 0, descriptor.revents & Int16(POLLOUT) != 0 { continue }
                    if result < 0, errno == EINTR { continue }
                    if result == 0 { throw UpstreamError.timeout(name) }
                    throw UpstreamError.down(name)
                }
                throw UpstreamError.down(name)
            }
        }
    }

    private func consume(_ chunk: Data) {
        guard !chunk.isEmpty else { return }
        var completed: [(CheckedContinuation<[String: JSONValue], any Error>, Result<[String: JSONValue], any Error>)] = []
        lock.withLock {
            let lines: [Data]
            do {
                // Cap each JSON-RPC frame, not the FileHandle delivery chunk.
                // LineFramer also avoids repeatedly rescanning/removing the
                // front of a large hostile stream (quadratic CPU).
                lines = try framer.push(chunk)
            } catch {
                framer = LineFramer(maxLineBytes: Self.maxLineBytes)
                for (_, c) in pending { completed.append((c, .failure(UpstreamError.protocolError(name, "oversized frame")))) }
                pending.removeAll()
                return
            }
            for line in lines {
                guard let obj = try? JSONSerialization.jsonObject(with: line) as? [String: Any] else { continue }
                // Ignore server-initiated requests and notifications.
                guard let id = obj["id"] as? String,
                      let cont = pending.removeValue(forKey: id) else { continue }
                if let error = obj["error"] as? [String: Any] {
                    let msg = (error["message"] as? String) ?? "unknown JSON-RPC error"
                    // Scrub directly because this block already holds `lock`.
                    completed.append((cont, .failure(UpstreamError.protocolError(name, Self.scrubAgainst(msg, secrets: injected)))))
                } else if let result = obj["result"] as? [String: Any] {
                    do {
                        completed.append((cont, .success(
                            try JSONValue.boundedObject(fromFoundation: result))))
                    } catch {
                        completed.append((cont, .failure(UpstreamError.protocolError(
                            name, "reply exceeds JSON resource limits"))))
                    }
                } else {
                    completed.append((cont, .failure(UpstreamError.protocolError(name, "malformed reply"))))
                }
            }
        }
        for (cont, result) in completed { cont.resume(with: result) }
    }

    /// FileHandle.availableData can allocate everything currently buffered.
    /// Read directly into a fixed buffer instead; stdout is nonblocking, and a
    /// per-callback drain budget prevents a flooding child monopolizing the
    /// Foundation readability queue.
    private func readAvailableOutput() {
        let fd = stdoutHandle.fileDescriptor
        var buffer = [UInt8](repeating: 0, count: Self.readChunkBytes)
        for _ in 0..<16 {
            let count = Darwin.read(fd, &buffer, buffer.count)
            if count > 0 {
                consume(Data(buffer[0..<count]))
                continue
            }
            if count == 0 {
                stdoutHandle.readabilityHandler = nil
                return
            }
            if errno == EINTR { continue }
            if errno == EAGAIN || errno == EWOULDBLOCK { return }
            failAllPending(UpstreamError.down(name))
            stdoutHandle.readabilityHandler = nil
            return
        }
    }

    /// Scrub a server-provided string against known-injected secrets (exact) plus
    /// generic shapes. Static and lock-free so it is safe to call while holding
    /// a connection's lock.
    static func scrubAgainst(_ text: String, secrets: [Data]) -> String {
        var data = Data(text.utf8)
        if !secrets.isEmpty { (data, _) = DLP.redactWith(data, secrets: secrets) }
        let (out, _) = DLP.redact(data)
        return String(decoding: out, as: UTF8.self)
    }
    static func scrubAgainst(_ text: String, injected: [Data]) -> String {
        scrubAgainst(text, secrets: injected)
    }

    private func failAllPending(_ error: any Error) {
        let conts: [CheckedContinuation<[String: JSONValue], any Error>] = lock.withLock {
            let c = Array(pending.values)
            pending.removeAll()
            return c
        }
        for c in conts { c.resume(throwing: error) }
    }
}

// MARK: - One remote (streamable HTTP) MCP connection

/// Remote MCP connection using JSON-RPC over streamable HTTP. It accepts JSON or
/// SSE responses and carries `Mcp-Session-Id` after initialization. Credentials
/// are resolved per request. Redirects and cloud metadata addresses are refused.
final class RemoteMCPConnection: NSObject, MCPConnection, URLSessionTaskDelegate, @unchecked Sendable {

    /// Maximum response-body size.
    private static let maxBodyBytes = 8 * 1024 * 1024

    private let name: String
    private let endpoint: URL
    /// API-key auth: the vault credential bound to the endpoint's host.
    private let resolveCred: (@Sendable () async throws -> Cred?)?
    /// OAuth auth: a valid access token (refreshed + re-sealed as needed).
    private let bearer: (@Sendable () async throws -> String)?
    private let netGuard = NetGuard()
    private var session: URLSession?
    private let oauth: OAuth2TokenCache

    private let lock = NSLock()
    private var requestIDs = JSONRPCRequestIDSequence()
    private var sessionID: String?
    private var protocolVersion: String?
    private var dead = false

    init(name: String, endpoint: URL,
         resolveCred: (@Sendable () async throws -> Cred?)? = nil,
         bearer: (@Sendable () async throws -> String)? = nil) {
        self.name = name
        self.endpoint = endpoint
        self.resolveCred = resolveCred
        self.bearer = bearer
        // Do not persist cookies or cache state.
        let config = URLSessionConfiguration.ephemeral
        config.httpShouldSetCookies = false
        config.httpCookieAcceptPolicy = .never
        config.urlCache = nil
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        let bootstrap = URLSession(configuration: config)
        self.oauth = OAuth2TokenCache(session: bootstrap, timeout: 30, netGuard: netGuard)
        super.init()
        // Assigned only after NSObject initialization, before `self` escapes.
        // Optional (not IUO): every later use fails closed if construction or
        // lifecycle ever leaves the transport unavailable.
        self.session = URLSession(configuration: config, delegate: self, delegateQueue: nil)
    }

    var isAlive: Bool { lock.withLock { !dead } }

    func terminate() {
        lock.withLock {
            dead = true
            sessionID = nil
        }
        let activeSession = lock.withLock { session }
        activeSession?.invalidateAndCancel()
    }

    /// Refuses all redirects.
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest,
                    completionHandler: @escaping @Sendable (URLRequest?) -> Void) {
        completionHandler(nil)
    }

    // MARK: MCP surface

    func start(timeout: TimeInterval) async throws {
        let (result, _) = try await rpc(method: "initialize", params: [
            "protocolVersion": "2025-03-26",
            "capabilities": [:] as [String: Any],
            "clientInfo": ["name": "sallyport", "version": "1.0"],
        ], timeout: timeout)
        if let negotiated = result["protocolVersion"]?.stringValue {
            lock.withLock { protocolVersion = negotiated }
        }
        _ = try await rpc(method: "notifications/initialized", params: [:],
                          isNotification: true, timeout: timeout)
    }

    func listTools(timeout: TimeInterval) async throws -> [JSONValue] {
        let (result, _) = try await rpc(method: "tools/list", params: [:], timeout: timeout)
        if case let .array(tools)? = result["tools"] { return tools }
        return []
    }

    func callTool(_ tool: String, arguments: [String: JSONValue],
                  timeout: TimeInterval) async throws -> (output: [String: JSONValue], injected: [Data]) {
        guard let boundedArguments = try JSONValue.object(arguments).boundedFoundation()
                as? [String: Any] else {
            throw UpstreamError.protocolError(name, "arguments exceed JSON resource limits")
        }
        let (result, injected) = try await rpc(method: "tools/call", params: [
            "name": tool,
            "arguments": boundedArguments,
        ], timeout: timeout)
        return (result, injected)
    }

    // MARK: JSON-RPC over streamable HTTP

    private func rpc(method: String, params: [String: Any], isNotification: Bool = false,
                     timeout: TimeInterval) async throws -> (result: [String: JSONValue], injected: [Data]) {
        guard isAlive else { throw UpstreamError.down(name) }
        // Treat the configured endpoint as bound intent for private ranges while
        // keeping metadata and link-local addresses blocked.
        try netGuard.validate(host: endpoint.host ?? "", bound: true)

        var frame: [String: Any] = ["jsonrpc": "2.0", "method": method, "params": params]
        var id = ""
        if !isNotification {
            do {
                id = try lock.withLock { try requestIDs.take() }
            } catch {
                throw UpstreamError.protocolError(name, "JSON-RPC request id space exhausted")
            }
            frame["id"] = id
        }
        let body = try JSONSerialization.data(withJSONObject: frame)

        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.httpBody = body
        let timeoutNanos = timeoutNanoseconds(timeout)
        guard timeoutNanos > 0 else { throw UpstreamError.timeout(name) }
        request.timeoutInterval = timeoutNanos == UInt64.max
            ? TimeInterval(UInt64.max / 1_000_000_000)
            : TimeInterval(timeoutNanos) / 1_000_000_000
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json, text/event-stream", forHTTPHeaderField: "Accept")
        let (sid, ver) = lock.withLock { (sessionID, protocolVersion) }
        if let sid { request.setValue(sid, forHTTPHeaderField: "Mcp-Session-Id") }
        if let ver { request.setValue(ver, forHTTPHeaderField: "MCP-Protocol-Version") }

        // Attach an OAuth token or host-bound vault credential.
        var injected: [Data] = []
        if let bearer {
            let token = try await bearer()
            request.setValue("Bearer " + token, forHTTPHeaderField: "Authorization")
            injected = [Data(token.utf8)]
        } else if let resolveCred, let cred = try await resolveCred() {
            injected = try await Adapters.inject(cred, into: &request, body: body, oauth: oauth)
        }

        let finalRequest = request
        // Cap the streamed reply and refuse redirects.
        let policy = RedirectPolicy(origin: endpoint.hostPort,
                                    originScheme: endpoint.scheme?.lowercased() ?? "https",
                                    hasCredential: true, maxBody: Self.maxBodyBytes)
        guard let activeSession = lock.withLock({ session }) else {
            throw UpstreamError.down(name)
        }
        let (data, http) = try await withTimeout(timeout, upstream: name) {
            try await policy.loadCapped(request: finalRequest, session: activeSession,
                                        hardTimeout: timeout)
        }
        // Store the session ID. A 404 after initialization forces reconnection.
        if let sid = http.value(forHTTPHeaderField: "Mcp-Session-Id") {
            lock.withLock { sessionID = sid }
        }
        if http.statusCode == 404, lock.withLock({ sessionID }) != nil {
            lock.withLock { dead = true }
            throw UpstreamError.down(name)
        }
        guard (200..<300).contains(http.statusCode) else {
            throw UpstreamError.protocolError(name, "HTTP \(http.statusCode) from endpoint")
        }
        if policy.bodyOverflowed {
            throw UpstreamError.protocolError(name, "oversized reply")
        }
        if isNotification || data.isEmpty {
            return ([:], injected)
        }

        let contentType = (http.value(forHTTPHeaderField: "Content-Type") ?? "").lowercased()
        let message: [String: Any]?
        if contentType.contains("text/event-stream") {
            message = Self.sseMessage(matching: id, in: data)
        } else {
            message = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        }
        guard let message else {
            throw UpstreamError.protocolError(name, "unparseable reply")
        }
        if let error = message["error"] as? [String: Any] {
            let msg = (error["message"] as? String) ?? "unknown JSON-RPC error"
            throw UpstreamError.protocolError(name, StdioMCPConnection.scrubAgainst(msg, injected: injected))
        }
        guard let result = message["result"] as? [String: Any] else {
            throw UpstreamError.protocolError(name, "malformed reply")
        }
        do {
            return (try JSONValue.boundedObject(fromFoundation: result), injected)
        } catch {
            throw UpstreamError.protocolError(name, "reply exceeds JSON resource limits")
        }
    }

    /// Extract the JSON-RPC response with `id` from an SSE body: events are
    /// separated by blank lines; each carries one or more `data:` lines.
    static func sseMessage(matching id: String, in body: Data) -> [String: Any]? {
        guard var text = String(data: body, encoding: .utf8) else { return nil }
        text = text.replacingOccurrences(of: "\r\n", with: "\n")
        for rawEvent in text.components(separatedBy: "\n\n") {
            let dataPayload = rawEvent.split(separator: "\n")
                .filter { $0.hasPrefix("data:") }
                .map { $0.dropFirst(5).trimmingCharacters(in: .whitespaces) }
                .joined(separator: "\n")
            guard !dataPayload.isEmpty,
                  let obj = (try? JSONSerialization.jsonObject(with: Data(dataPayload.utf8))) as? [String: Any],
                  (obj["id"] as? String) == id else { continue }
            return obj
        }
        return nil
    }
}

/// Applies a hard deadline in addition to URLRequest's inactivity timeout.
func withTimeout<T: Sendable>(_ seconds: TimeInterval, upstream: String,
                              _ op: @escaping @Sendable () async throws -> T) async throws -> T {
    let nanos = timeoutNanoseconds(seconds)
    guard nanos > 0 else { throw UpstreamError.timeout(upstream) }
    return try await withThrowingTaskGroup(of: T.self) { group in
        defer { group.cancelAll() }
        group.addTask { try await op() }
        group.addTask {
            try await Task.sleep(nanoseconds: nanos)
            throw UpstreamError.timeout(upstream)
        }
        guard let first = try await group.next() else {
            throw UpstreamError.timeout(upstream)
        }
        return first
    }
}

/// Stateless URLSession delegate that refuses redirects.
final class RefuseRedirects: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    static let shared = RefuseRedirects()
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest,
                    completionHandler: @escaping @Sendable (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}
