import Foundation

/// Vault-backed runtime settings.
/// `logBodies` is retained for wire compatibility but has no runtime consumer.
public struct SettingsState: Codable, Sendable {
    /// Session approval mode. Nil defaults to `click`.
    public var sessionAuth: String?
    /// Nil uses the default value of true.
    public var requireTouchIDForChanges: Bool?
    public var logBodies: Bool
    /// Nil uses the default timeout; zero disables auto-lock.
    public var autoLockMinutes: Int?
    /// Nil uses the default value of true.
    public var lockOnScreenLock: Bool?

    public init(sessionAuth: String? = nil, requireTouchIDForChanges: Bool? = nil,
                logBodies: Bool = false, autoLockMinutes: Int? = nil,
                lockOnScreenLock: Bool? = nil) {
        self.sessionAuth = sessionAuth
        self.requireTouchIDForChanges = requireTouchIDForChanges
        self.logBodies = logBodies
        self.autoLockMinutes = autoLockMinutes; self.lockOnScreenLock = lockOnScreenLock
    }

    enum CodingKeys: String, CodingKey {
        case sessionAuth, requireTouchIDForChanges, logBodies, autoLockMinutes, lockOnScreenLock
        case perSessionAuth   // legacy: the two-state switch this replaced
    }
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        if let explicit = try c.decodeIfPresent(String.self, forKey: .sessionAuth) {
            sessionAuth = explicit
        } else if let legacy = try c.decodeIfPresent(Bool.self, forKey: .perSessionAuth) {
            // Map the legacy Boolean to the current session mode.
            sessionAuth = legacy ? SettingsStore.sessionAuthClick : SettingsStore.sessionAuthOff
        } else {
            sessionAuth = nil
        }
        requireTouchIDForChanges = try c.decodeIfPresent(Bool.self, forKey: .requireTouchIDForChanges)
        logBodies = try c.decodeIfPresent(Bool.self, forKey: .logBodies) ?? false
        autoLockMinutes = try c.decodeIfPresent(Int.self, forKey: .autoLockMinutes)
        lockOnScreenLock = try c.decodeIfPresent(Bool.self, forKey: .lockOnScreenLock)
    }

    /// Never re-encode the legacy key (the decoder above reads it; nothing writes it).
    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encodeIfPresent(sessionAuth, forKey: .sessionAuth)
        try c.encodeIfPresent(requireTouchIDForChanges, forKey: .requireTouchIDForChanges)
        try c.encode(logBodies, forKey: .logBodies)
        try c.encodeIfPresent(autoLockMinutes, forKey: .autoLockMinutes)
        try c.encodeIfPresent(lockOnScreenLock, forKey: .lockOnScreenLock)
    }
}

/// Thread-safe settings stored inside the vault.
public final class SettingsStore: @unchecked Sendable {
    private let lock = NSLock()
    private let mutations = AsyncMutationGate()
    private var st: SettingsState
    /// Optimistic publication token.
    private var generation = UUID()
    private var lifecycleEpoch: Int64?
    private var highestLifecycleEpoch: Int64 = -1
    /// Persistence callback supplied by `VaultHost`.
    private var persist: (@Sendable (SettingsState, Int64?) async throws -> Void)?

    public init(initial: SettingsState = SettingsState()) {
        self.st = initial
    }

    /// Wire the vault-sealing persistence sink (called once by the host).
    public func onPersist(_ sink: @escaping @Sendable (SettingsState) async throws -> Void) {
        lock.withLock { persist = { state, _ in try await sink(state) } }
    }

    func onPersist(_ sink: @escaping @Sendable (SettingsState, Int64) async throws -> Void) {
        lock.withLock {
            persist = { state, epoch in
                guard let epoch else { throw VaultStoreError.locked }
                try await sink(state, epoch)
            }
        }
    }

    /// Installs settings after unlock.
    public func hydrate(_ state: SettingsState, lifecycleEpoch epoch: Int64? = nil) {
        lock.withLock {
            if let epoch {
                guard epoch > highestLifecycleEpoch else { return }
                highestLifecycleEpoch = epoch
            }
            st = state
            lifecycleEpoch = epoch
            generation = UUID()
        }
    }

    /// Clears in-memory settings on lock.
    public func clear() {
        lock.withLock {
            st = SettingsState()
            lifecycleEpoch = nil
            generation = UUID()
        }
    }

    public func snapshot() -> SettingsState { lock.withLock { st } }

    /// Default auto-lock timeout: eight hours.
    public static let defaultAutoLockMinutes = 480

    /// Session approval modes.
    public static let sessionAuthOff = "off"
    public static let sessionAuthClick = "click"
    public static let sessionAuthTouchID = "touchid"

    /// Approval mode for a new agent process.
    public func sessionAuth() -> String {
        let raw = lock.withLock { st.sessionAuth } ?? Self.sessionAuthClick
        return [Self.sessionAuthOff, Self.sessionAuthClick, Self.sessionAuthTouchID].contains(raw)
            ? raw : Self.sessionAuthClick
    }

    /// Whether a new agent process must be confirmed at all (off = observe mode).
    public func perSessionAuth() -> Bool { sessionAuth() != Self.sessionAuthOff }

    /// Whether ordinary configuration changes require Touch ID.
    public func requireTouchIDForChanges() -> Bool {
        lock.withLock { st.requireTouchIDForChanges ?? true }
    }

    public func logBodies() -> Bool { lock.withLock { st.logBodies } }

    /// Auto-lock timeout in seconds, or nil when disabled.
    public func autoLockTTL() -> TimeInterval? {
        let minutes = lock.withLock { st.autoLockMinutes ?? Self.defaultAutoLockMinutes }
        guard minutes > 0 else { return nil }
        // Bound the conversion to avoid integer overflow.
        let safeMinutes = min(minutes, Int.max / 120)
        return TimeInterval(safeMinutes * 60)
    }

    /// Whether locking the Mac also locks the vault.
    public func lockOnScreenLock() -> Bool { lock.withLock { st.lockOnScreenLock ?? true } }

    /// Applies and persists a settings change.
    public func update(_ mut: @Sendable (inout SettingsState) -> Void) async throws {
        try await mutations.withLock { [self] in
            let (next, sink, baseGeneration, epoch):
                (SettingsState, (@Sendable (SettingsState, Int64?) async throws -> Void)?, UUID, Int64?) =
                lock.withLock {
                    var next = st
                    mut(&next)
                    return (next, persist, generation, lifecycleEpoch)
                }
            try await sink?(next, epoch)
            lock.withLock {
                guard generation == baseGeneration else { return }
                st = next
                generation = UUID()
            }
        }
    }
}
