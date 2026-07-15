import Foundation

/// Vault-backed inventory of local and remote MCP servers.
public final class UpstreamsStore: @unchecked Sendable {

    /// A vault secret injected into a local server environment variable.
    public struct KeyBinding: Codable, Sendable, Hashable {
        public var secret: String       // vault secret name
        public var envVar: String       // e.g. GITHUB_TOKEN
        public init(secret: String, envVar: String) {
            self.secret = secret; self.envVar = envVar
        }
    }

    public struct Entry: Codable, Sendable, Hashable {
        /// The stdio transport: a local process Sallyport spawns.
        public static let stdioTransport = "stdio"
        /// The remote transport: a streamable-HTTP MCP endpoint Sallyport calls.
        public static let httpTransport = "http"

        /// Remote auth with the key bound to the endpoint host. This is the default.
        public static let apiKeyAuth = "apikey"
        /// Remote auth with OAuth 2.1. Sallyport signs in through the browser and
        /// seals the resulting tokens under the vault key.
        public static let oauthAuth = "oauth"

        /// Tool namespace prefix validated by the management surface.
        public var name: String
        /// `stdio` (default) or `http`. Decides which of the field groups below
        /// applies; the other group is ignored.
        public var transport: String
        // Local stdio server.
        public var command: String      // executable path (absolute) or login-PATH name
        public var args: [String]
        /// Static non-secret environment.
        public var env: [String: String]
        public var keys: [KeyBinding]
        // Remote HTTP server.
        /// MCP endpoint URL. Authentication data is stored separately.
        public var url: String
        /// `apikey` or `oauth` for remote transport.
        public var auth: String
        /// Per-call approval requirement for this server.
        public var confirm: String

        public var enabled: Bool

        public init(name: String, transport: String = Entry.stdioTransport,
                    command: String = "", args: [String] = [],
                    env: [String: String] = [:], keys: [KeyBinding] = [],
                    url: String = "", auth: String = Entry.apiKeyAuth,
                    confirm: String = "", enabled: Bool = true) {
            self.name = name; self.transport = transport
            self.command = command; self.args = args
            self.env = env; self.keys = keys
            self.url = url; self.auth = auth
            self.confirm = confirm; self.enabled = enabled
        }

        /// Whether this entry signs in through OAuth (remote only).
        public var usesOAuth: Bool {
            transport == Entry.httpTransport && auth == Entry.oauthAuth
        }

        enum CodingKeys: String, CodingKey {
            case name, transport, command, args, env, keys, url, auth, confirm, enabled
        }

        /// Older entries without `transport` or `url` decode as stdio.
        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            name = try c.decode(String.self, forKey: .name)
            transport = try c.decodeIfPresent(String.self, forKey: .transport) ?? Entry.stdioTransport
            command = try c.decodeIfPresent(String.self, forKey: .command) ?? ""
            args = try c.decodeIfPresent([String].self, forKey: .args) ?? []
            env = try c.decodeIfPresent([String: String].self, forKey: .env) ?? [:]
            keys = try c.decodeIfPresent([KeyBinding].self, forKey: .keys) ?? []
            url = try c.decodeIfPresent(String.self, forKey: .url) ?? ""
            auth = try c.decodeIfPresent(String.self, forKey: .auth) ?? Entry.apiKeyAuth
            confirm = try c.decodeIfPresent(String.self, forKey: .confirm) ?? ""
            enabled = try c.decodeIfPresent(Bool.self, forKey: .enabled) ?? true
        }
    }

    private let lock = NSLock()
    private let mutations = AsyncMutationGate()
    private var upstreams: [String: Entry] = [:]
    /// Optimistic publication token.
    private var generation = UUID()
    private var lifecycleEpoch: Int64?
    private var highestLifecycleEpoch: Int64 = -1
    /// Persistence callback supplied by `VaultHost`.
    private var persist: (@Sendable ([Entry], Int64?) async throws -> Void)?

    public init(entries: [Entry] = []) {
        upstreams = Dictionary(uniqueKeysWithValues: entries.map { ($0.name, $0) })
    }

    /// Wire the vault-sealing persistence sink (called once by the host).
    public func onPersist(_ sink: @escaping @Sendable ([Entry]) async throws -> Void) {
        lock.withLock { persist = { entries, _ in try await sink(entries) } }
    }

    func onPersist(_ sink: @escaping @Sendable ([Entry], Int64) async throws -> Void) {
        lock.withLock {
            persist = { entries, epoch in
                guard let epoch else { throw VaultStoreError.locked }
                try await sink(entries, epoch)
            }
        }
    }

    /// Installs the inventory after unlock.
    public func hydrate(_ entries: [Entry], lifecycleEpoch epoch: Int64? = nil) {
        lock.withLock {
            if let epoch {
                guard epoch > highestLifecycleEpoch else { return }
                highestLifecycleEpoch = epoch
            }
            upstreams = Dictionary(uniqueKeysWithValues: entries.map { ($0.name, $0) })
            lifecycleEpoch = epoch
            generation = UUID()
        }
    }

    /// Clears the in-memory inventory on lock.
    public func clear() {
        lock.withLock {
            upstreams = [:]
            lifecycleEpoch = nil
            generation = UUID()
        }
    }

    public func list() -> [Entry] { lock.withLock { upstreams.values.sorted { $0.name < $1.name } } }

    public func get(_ name: String) -> Entry? { lock.withLock { upstreams[name] } }

    public func set(_ entry: Entry) async throws {
        try await mutations.withLock { [self] in
            let (next, entries, sink, baseGeneration, epoch) = lock.withLock {
                var next = upstreams
                next[entry.name] = entry
                return (next, next.values.sorted { $0.name < $1.name }, persist, generation, lifecycleEpoch)
            }
            try await sink?(entries, epoch)
            lock.withLock {
                guard generation == baseGeneration else { return }
                upstreams = next
                generation = UUID()
            }
        }
    }

    @discardableResult
    public func delete(_ name: String) async throws -> Bool {
        try await mutations.withLock { [self] in
            let (existed, next, entries, sink, baseGeneration, epoch) = lock.withLock {
                var next = upstreams
                let existed = next.removeValue(forKey: name) != nil
                return (existed, next, next.values.sorted { $0.name < $1.name }, persist, generation, lifecycleEpoch)
            }
            try await sink?(entries, epoch)
            lock.withLock {
                guard generation == baseGeneration else { return }
                upstreams = next
                generation = UUID()
            }
            return existed
        }
    }

    /// Resolves `<server>.<tool>` against enabled servers.
    public func route(tool: String) -> (entry: Entry, tool: String)? {
        guard let dot = tool.firstIndex(of: ".") else { return nil }
        let prefix = String(tool[..<dot])
        let rest = String(tool[tool.index(after: dot)...])
        guard !rest.isEmpty, let entry = get(prefix), entry.enabled else { return nil }
        return (entry, rest)
    }
}
