import Foundation

/// Agent identity allowed to skip session approval. This does not bypass vault
/// lock or per-call approval, and live code is checked on each call. A `cdhash`
/// entry matches exact builds; a `publisher` entry matches a Team ID and optional
/// bundle ID across updates. Identity matching does not establish agent intent.
public struct AllowlistEntry: Codable, Sendable, Hashable, Identifiable {
    public enum Kind: String, Codable, Sendable { case cdhash, publisher }

    public var id: String
    public var label: String           // bundle display name or basename
    public var kind: Kind
    /// `.cdhash`: the set of code-directory hashes (hex, one per architecture)
    /// captured from the binary. A live process matches if its running slice's
    /// cdhash is in this set. Empty for `.publisher`.
    public var cdhashes: [String]
    /// `.publisher`: a code-signing requirement string, matched with
    /// `SecCodeCheckValidity`. Empty for `.cdhash`.
    public var requirement: String
    public var teamID: String          // display only
    public var bundleID: String        // display only
    /// File path or `live:<name>` source used for capture.
    public var capturedFrom: String
    /// Allowed target hosts. An empty list accepts any target.
    public var scopeHosts: [String]
    public var createdAt: Date

    public init(id: String, label: String, kind: Kind, cdhashes: [String] = [],
                requirement: String = "", teamID: String = "", bundleID: String = "",
                capturedFrom: String = "", scopeHosts: [String] = [], createdAt: Date = Date()) {
        self.id = id; self.label = label; self.kind = kind
        self.cdhashes = cdhashes; self.requirement = requirement
        self.teamID = teamID; self.bundleID = bundleID
        self.capturedFrom = capturedFrom; self.scopeHosts = scopeHosts
        self.createdAt = createdAt
    }

    /// Whether this entry covers `targetHost`.
    public func covers(_ targetHost: String) -> Bool {
        scopeHosts.isEmpty || scopeHosts.contains { $0.caseInsensitiveCompare(targetHost) == .orderedSame }
    }

    /// Whether the entry has a nonempty matcher.
    public var isUsable: Bool {
        switch kind {
        case .cdhash: return !cdhashes.isEmpty
        case .publisher: return !requirement.isEmpty
        }
    }
}

/// Code identity captured for a proposed allowlist entry.
public struct AllowlistCapture: Sendable, Equatable {
    public var label: String
    public var cdhashes: [String]
    public var teamID: String
    public var bundleID: String
    public var signed: Bool             // validly signed under `anchor apple generic`
    public var authority: String        // leaf subject, for display
    public var capturedFrom: String

    public init(label: String, cdhashes: [String], teamID: String, bundleID: String,
                signed: Bool, authority: String, capturedFrom: String) {
        self.label = label; self.cdhashes = cdhashes; self.teamID = teamID
        self.bundleID = bundleID; self.signed = signed; self.authority = authority
        self.capturedFrom = capturedFrom
    }

    /// Publisher requirement using Team ID and bundle ID when available.
    public var publisherRequirement: String? {
        guard !teamID.isEmpty else { return nil }
        let base = "anchor apple generic and certificate leaf[subject.OU] = \"\(teamID)\""
        return bundleID.isEmpty ? base : "\(base) and identifier \"\(bundleID)\""
    }
}

/// Stores allowlist entries and matches them against a live process.
public final class Allowlist: @unchecked Sendable {
    private let lock = NSLock()
    private let mutations = AsyncMutationGate()
    private var entries: [AllowlistEntry] = []
    /// Optimistic publication token. A wrapping integer permits an ABA match
    /// after exhaustion; a fresh UUID has no arithmetic wrap state.
    private var generation = UUID()
    private var lifecycleEpoch: Int64?
    private var highestLifecycleEpoch: Int64 = -1
    private var persist: (@Sendable ([AllowlistEntry], Int64?) async throws -> Void)?
    private let matcher: @Sendable (_ pid: Int, _ startedAt: Int64, _ candidates: [AllowlistEntry]) -> AllowlistEntry?

    public init(matcher: @escaping @Sendable (_ pid: Int, _ startedAt: Int64, _ candidates: [AllowlistEntry]) -> AllowlistEntry?) {
        self.matcher = matcher
    }

    /// Test/standalone persistence seam. VaultHost uses the epoch-bound overload
    /// below so a queued mutation from a prior unlock cannot write into a newer
    /// vault lifecycle.
    public func onPersist(_ sink: @escaping @Sendable ([AllowlistEntry]) async throws -> Void) {
        lock.withLock { persist = { entries, _ in try await sink(entries) } }
    }

    func onPersist(_ sink: @escaping @Sendable ([AllowlistEntry], Int64) async throws -> Void) {
        lock.withLock {
            persist = { entries, epoch in
                guard let epoch else { throw VaultStoreError.locked }
                try await sink(entries, epoch)
            }
        }
    }

    public func hydrate(_ list: [AllowlistEntry], lifecycleEpoch epoch: Int64? = nil) {
        lock.withLock {
            if let epoch {
                guard epoch > highestLifecycleEpoch else { return }
                highestLifecycleEpoch = epoch
            }
            entries = list.filter(\.isUsable)
            lifecycleEpoch = epoch
            generation = UUID()
        }
    }

    public func clear() {
        lock.withLock {
            entries = []
            lifecycleEpoch = nil
            generation = UUID()
        }
    }

    public func list() -> [AllowlistEntry] { lock.withLock { entries } }

    /// Transactional upsert: persist the complete next snapshot before
    /// publishing it. The FIFO mutation gate prevents concurrent add/delete
    /// operations from losing one another or landing on disk out of order.
    public func set(_ entry: AllowlistEntry) async throws {
        guard entry.isUsable else { throw AllowlistMutationError.unusable }
        try await mutations.withLock { [self] in
            let (next, sink, baseGeneration, epoch) = lock.withLock {
                var next = entries.filter { $0.id != entry.id }
                next.append(entry)
                return (next, persist, generation, lifecycleEpoch)
            }
            try await sink?(next, epoch)
            lock.withLock {
                guard generation == baseGeneration else { return }
                entries = next
                generation = UUID()
            }
        }
    }

    @discardableResult
    public func delete(_ id: String) async throws -> Bool {
        try await mutations.withLock { [self] in
            let (existed, next, sink, baseGeneration, epoch) = lock.withLock {
                let existed = entries.contains { $0.id == id }
                let next = entries.filter { $0.id != id }
                return (existed, next, persist, generation, lifecycleEpoch)
            }
            try await sink?(next, epoch)
            lock.withLock {
                guard generation == baseGeneration else { return }
                entries = next
                generation = UUID()
            }
            return existed
        }
    }

    /// The entry that auto-approves `pid` for `targetHost`, or nil. Scope is
    /// filtered here (cheap); the live code check runs only over the survivors.
    public func match(pid: Int, startedAt: Int64, targetHost: String) -> AllowlistEntry? {
        guard pid > 0 else { return nil }
        let candidates = lock.withLock { entries.filter { $0.isUsable && $0.covers(targetHost) } }
        guard !candidates.isEmpty else { return nil }
        return matcher(pid, startedAt, candidates)
    }
}

public enum AllowlistMutationError: Error, Equatable, Sendable {
    case unusable
}
