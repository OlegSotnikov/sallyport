import Foundation

/// Vault-sealed SSH host inventory used by the UI and `ssh.exec`. Entries refer
/// to private keys by `keyName` and are available only while the vault is open.
public final class HostsStore: @unchecked Sendable {
    public struct Entry: Codable, Sendable, Hashable {
        public var name: String
        public var addr: String
        public var user: String
        public var port: Int
        public var tags: [String]
        public var keyName: String        // vault secret name (ssh-ed25519)
        public var hostKeyPolicy: String  // accept-new | strict
        public init(name: String, addr: String, user: String = "root", port: Int = 22,
                    tags: [String] = [], keyName: String = "", hostKeyPolicy: String = "accept-new") {
            self.name = name; self.addr = addr; self.user = user; self.port = port
            self.tags = tags; self.keyName = keyName; self.hostKeyPolicy = hostKeyPolicy
        }
    }

    private let lock = NSLock()
    private let mutations = AsyncMutationGate()
    private var hosts: [String: Entry] = [:]
    /// UUID token used to reject stale optimistic publications.
    private var generation = UUID()
    private var lifecycleEpoch: Int64?
    private var highestLifecycleEpoch: Int64 = -1
    /// Seals and writes the inventory. Nil in unit tests.
    private var persist: (@Sendable ([Entry], Int64?) async throws -> Void)?

    public init(entries: [Entry] = []) {
        hosts = Dictionary(uniqueKeysWithValues: entries.map { ($0.name, $0) })
    }

    /// Wire the vault-sealing persistence sink (called once by the host).
    public func onPersist(_ sink: @escaping @Sendable ([Entry]) async throws -> Void) {
        lock.withLock { persist = { entries, _ in try await sink(entries) } }
    }

    /// Binds each write to the lifecycle that hydrated the snapshot.
    func onPersist(_ sink: @escaping @Sendable ([Entry], Int64) async throws -> Void) {
        lock.withLock {
            persist = { entries, epoch in
                guard let epoch else { throw VaultStoreError.locked }
                try await sink(entries, epoch)
            }
        }
    }

    /// Install the inventory decrypted from the vault (after unlock).
    public func hydrate(_ entries: [Entry], lifecycleEpoch epoch: Int64? = nil) {
        lock.withLock {
            if let epoch {
                guard epoch > highestLifecycleEpoch else { return }
                highestLifecycleEpoch = epoch
            }
            hosts = Dictionary(uniqueKeysWithValues: entries.map { ($0.name, $0) })
            lifecycleEpoch = epoch
            generation = UUID()
        }
    }

    /// Drop the in-memory inventory (on lock).
    public func clear() {
        lock.withLock {
            hosts = [:]
            lifecycleEpoch = nil
            generation = UUID()
        }
    }

    public func list() -> [Entry] { lock.withLock { hosts.values.sorted { $0.name < $1.name } } }

    public func get(_ name: String) -> Entry? { lock.withLock { hosts[name] } }

    public func set(_ entry: Entry) async throws {
        try await mutations.withLock { [self] in
            let (next, entries, sink, baseGeneration, epoch) = lock.withLock {
                var next = hosts
                next[entry.name] = entry
                return (next, next.values.sorted { $0.name < $1.name }, persist, generation, lifecycleEpoch)
            }
            try await sink?(entries, epoch)
            lock.withLock {
                guard generation == baseGeneration else { return }
                hosts = next
                generation = UUID()
            }
        }
    }

    @discardableResult
    public func delete(_ name: String) async throws -> Bool {
        try await mutations.withLock { [self] in
            let (existed, next, entries, sink, baseGeneration, epoch) = lock.withLock {
                var next = hosts
                let existed = next.removeValue(forKey: name) != nil
                return (existed, next, next.values.sorted { $0.name < $1.name }, persist, generation, lifecycleEpoch)
            }
            try await sink?(entries, epoch)
            lock.withLock {
                guard generation == baseGeneration else { return }
                hosts = next
                generation = UUID()
            }
            return existed
        }
    }

    /// Resolves an `ssh.exec` host name.
    public func ref(_ name: String) -> HostRef? {
        guard let e = get(name) else { return nil }
        return HostRef(name: e.name, addr: e.addr, user: e.user, port: e.port,
                       hostKeyPolicy: e.hostKeyPolicy, keyName: e.keyName, tags: e.tags)
    }

    /// Host names, for the MCP tool hint.
    public func names() -> [String] { lock.withLock { hosts.keys.sorted() } }
}
