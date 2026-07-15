import Foundation
import SallyportKit
import Darwin

/// Owns the vault store, settings, sessions, audit journal, engine, process
/// watcher, and agent control socket.
public final class VaultHost: @unchecked Sendable {
    public let store: VaultStore
    public let sessions: SessionStore
    public let settings: SettingsStore
    public let audit: AuditLog
    public let engine: Engine
    public let hosts: HostsStore
    public let upstreams: UpstreamsStore
    public let upstreamManager: UpstreamManager
    /// Stops active `ssh.exec` processes and revokes their agents on lock.
    private let sshLifecycle: SSHLifecycle
    /// Agent allowlist matched against running code at the session gate.
    public let allowlist: Allowlist
    private let watcher: ProcWatcher?
    private let server: SocketServer
    private let socketPath: String
    private let auditDir: URL
    private let recordDir: URL
    /// Orders hydration, integrity checkpoints, and management commits.
    private let integrityTransactions = AsyncMutationGate()

    struct LifecycleTestHooks: Sendable {
        var beforeHydrationCommit: (@Sendable () async -> Void)?
        var beforeGateCommit: (@Sendable () async -> Void)?
        var beforePostGateEffects: (@Sendable () async -> Void)?
        var beforeReadoptCommit: (@Sendable () async -> Void)?
    }
    private let hooksLock = NSLock()
    private var lifecycleTestHooks = LifecycleTestHooks()

    /// Suspension points for lifecycle tests.
    func _setLifecycleTestHooks(_ hooks: LifecycleTestHooks) {
        hooksLock.withLock { lifecycleTestHooks = hooks }
    }

    public struct Paths: Sendable {
        public var socket: String
        public var auditDir: String
        public var knownHosts: String
        public var recordDir: String
        public var sshHelper: String        // bundled sp-ssh
        public init(socket: String, auditDir: String, knownHosts: String,
                    recordDir: String, sshHelper: String) {
            self.socket = socket; self.auditDir = auditDir
            self.knownHosts = knownHosts; self.recordDir = recordDir; self.sshHelper = sshHelper
        }
    }

    /// - Parameters:
    ///   - store: an already-opened VaultStore (the app owns unlock via the keystore).
    ///   - hosts: the SSH inventory shell (hydrated from the vault on unlock).
    ///   - approver: the app's approval surface.
    public init(store: VaultStore, hosts: HostsStore, paths: Paths, approver: Approver,
                signer: (any AuditSigner)? = nil,
                anchorStore: (any AnchorStore)? = nil) async throws {
        // A host requires the vault's persisted audit recipient.
        guard let recipient = await store.auditRecipient() else {
            throw AuditError.io("audit: the vault has no audit recipient")
        }
        self.store = store
        self.hosts = hosts
        self.socketPath = paths.socket
        self.auditDir = URL(fileURLWithPath: paths.auditDir)
        self.recordDir = URL(fileURLWithPath: paths.recordDir, isDirectory: true)
        self.signer = signer
        self.anchorStore = anchorStore

        // Persist settings and inventories as vault-sealed blobs.
        let storeRef = store
        self.settings = SettingsStore()
        settings.onPersist { st, epoch in
            try await storeRef.setBlob(key: VaultStore.settingsBlobKey, data: Self.encode(st),
                                       expectedEpoch: epoch)
        }
        hosts.onPersist { entries, epoch in
            try await storeRef.setBlob(key: VaultStore.hostsBlobKey, data: Self.encode(entries),
                                       expectedEpoch: epoch)
        }
        self.upstreams = UpstreamsStore()
        upstreams.onPersist { entries, epoch in
            try await storeRef.setBlob(key: VaultStore.upstreamsBlobKey, data: Self.encode(entries),
                                       expectedEpoch: epoch)
        }
        self.upstreamManager = UpstreamManager(store: store)
        // Match allowlist entries against the running code for the caller PID.
        self.allowlist = Allowlist(matcher: Provenance.matchAllowlist)
        allowlist.onPersist { entries, epoch in
            try await storeRef.setBlob(key: VaultStore.allowlistBlobKey,
                                       data: Self.encode(entries), expectedEpoch: epoch)
        }

        // Seal audit rows to the vault's recipient. Corrupt authenticated rows are
        // archived before a new log starts.
        self.audit = try Self.openAudit(dir: auditDir, recipient: recipient, signer: signer)
        self.sessions = SessionStore()

        // Seal SSH recordings before writing them to disk.
        let sshLifecycle = SSHLifecycle()
        self.sshLifecycle = sshLifecycle
        let ssh = SSHSpawner(helperPath: paths.sshHelper, knownHostsPath: paths.knownHosts,
                             recordDir: paths.recordDir,
                             inventory: { [hosts] name in hosts.ref(name) },
                             seal: { cast, filename in
                                 try syncAwaitResult({ try await storeRef.sealRecording(cast, filename: filename) }).get()
                             },
                             lifecycle: sshLifecycle)
        self.engine = Engine(store: store, sessions: sessions, settings: settings, audit: audit,
                             ssh: ssh, upstreams: upstreams, upstreamManager: upstreamManager,
                             approver: approver, allowlist: allowlist)

        // Sessions end the instant their process exits (kqueue NOTE_EXIT); the store
        // arms/disarms the watch, and the watcher expires the session on exit.
        let sess = sessions
        let auditRef = audit
        let w = try? ProcWatcher(onExit: { key in
            if let ended = sess.expire(key: key) {
                _ = try? auditRef.append(SessionJournal.endedEvent(ended))
            }
        })
        self.watcher = w
        if let w {
            sessions.watch = { pid, started, key in w.watch(pid: pid, startedAt: started, key: key) }
            sessions.unwatch = { pid in w.unwatch(pid: pid) }
        }

        // While locked, publish only built-in tool definitions without vault hints.
        let hostsRef = hosts
        let managerRef = upstreamManager
        self.server = SocketServer(path: paths.socket, engine: engine, tools: {
            // Expose vault hints and upstream tools only while ready.
            let staticTools = MCPTools.defs(MCPTools.Hints())
            let epoch = await storeRef.epoch()
            guard await storeRef.operational() else { return staticTools }
            guard let metas = try? await storeRef.list() else {
                return staticTools
            }
            let httpHosts = metas.flatMap { m -> [String] in
                ["bearer", "basic", "header"].contains(m.kind) ? m.bindHosts : []
            }
            let catalog = MCPTools.defs(
                MCPTools.Hints(httpHosts: httpHosts, sshHosts: hostsRef.names()))
                + managerRef.namespacedToolDefs()
            // Recheck the lifecycle before publishing decrypted metadata.
            guard await storeRef.lifecycleIsCurrent(epoch, phase: .ready) else {
                return staticTools
            }
            return catalog
        })
    }

    /// Archives a log with corrupt authenticated rows and starts a new one. Other
    /// failures remain fatal. The integrity gate still detects rollback.
    private static func openAudit(dir: URL, recipient: Data, signer: (any AuditSigner)?) throws -> AuditLog {
        do {
            return try AuditLog(dir: dir, recipientX963: recipient, signer: signer)
        } catch let error as AuditError {
            // Archive only authenticated-row corruption. Propagate access, link,
            // ownership, and ordinary I/O failures.
            guard case .corruptRow = error else { throw error }
            archiveAside(dir.path)
            return try AuditLog(dir: dir, recipientX963: recipient, signer: signer)
        }
    }

    private static func archiveAside(_ path: String) {
        let fm = FileManager.default
        guard fm.fileExists(atPath: path) else { return }
        let dest = path + ".corrupt-\(UUID().uuidString.lowercased())"
        try? fm.moveItem(atPath: path, toPath: dest)
    }

    private static func encode<T: Encodable>(_ value: T) throws -> Data {
        let enc = JSONEncoder()
        enc.outputFormatting = [.sortedKeys]
        return try enc.encode(value)
    }

    public func start() throws { try server.start() }

    public func stop() {
        server.stop()
        watcher?.close()
        upstreamManager.killAll()
        try? audit.close()
    }

    /// Forwards each audit event to the live UI feed.
    public func onActivity(_ sink: @escaping @Sendable (AuditEvent) -> Void) async {
        await engine.setActivitySink(sink)
    }

    /// The `sallyport.request_credential` handler (the app's add-key sheet).
    public func onCredentialAsk(_ prompter: any CredentialPrompter) async {
        await engine.setCredentialPrompter(prompter)
    }

    /// Expires sessions missed by the process watcher.
    public func sweepSessions() { _ = sessions.sweep(alive: { Provenance.alive(pid: $0, startedAt: $1) }) }

    private struct UnlockedSnapshot: Sendable {
        var settings: SettingsState
        var hosts: [HostsStore.Entry]
        var upstreams: [UpstreamsStore.Entry]
        var allowlist: [AllowlistEntry]
    }

    /// Decode into locals first. A corrupt authenticated blob is not "missing"
    /// and must not silently weaken settings to defaults.
    private func readUnlockedSnapshot(expectedEpoch: Int64) async throws -> UnlockedSnapshot {
        func decode<T: Decodable>(_ type: T.Type, _ data: Data?, or value: T) throws -> T {
            guard let data else { return value }
            return try JSONDecoder().decode(type, from: data)
        }
        let settingsData = try await store.blob(key: VaultStore.settingsBlobKey)
        let hostsData = try await store.blob(key: VaultStore.hostsBlobKey)
        let upstreamsData = try await store.blob(key: VaultStore.upstreamsBlobKey)
        let allowlistData = try await store.blob(key: VaultStore.allowlistBlobKey)
        guard await store.lifecycleIsCurrent(expectedEpoch, phase: .unlocking) else {
            throw VaultStoreError.locked
        }
        return try UnlockedSnapshot(
            settings: decode(SettingsState.self, settingsData, or: SettingsState()),
            hosts: decode([HostsStore.Entry].self, hostsData, or: []),
            upstreams: decode([UpstreamsStore.Entry].self, upstreamsData, or: []),
            allowlist: decode([AllowlistEntry].self, allowlistData, or: []))
    }

    private func hydrateUnlockedLocked(expectedEpoch: Int64) async throws {
        let snapshot = try await readUnlockedSnapshot(expectedEpoch: expectedEpoch)
        if let hook = hooksLock.withLock({ lifecycleTestHooks.beforeHydrationCommit }) {
            await hook()
        }
        guard await store.lifecycleIsCurrent(expectedEpoch, phase: .unlocking) else {
            throw VaultStoreError.locked
        }
        // Publish the decoded state as one synchronous snapshot.
        settings.hydrate(snapshot.settings, lifecycleEpoch: expectedEpoch)
        hosts.hydrate(snapshot.hosts, lifecycleEpoch: expectedEpoch)
        upstreams.hydrate(snapshot.upstreams, lifecycleEpoch: expectedEpoch)
        allowlist.hydrate(snapshot.allowlist, lifecycleEpoch: expectedEpoch)
        let ttl = settings.autoLockTTL()
        guard await store.setAutoLockTTL(ttl, expectedEpoch: expectedEpoch) else {
            throw VaultStoreError.locked
        }
    }

    /// Test entry point for hydration without a configured signer.
    @discardableResult
    public func onVaultUnlocked() async -> Bool {
        guard let expectedEpoch = try? await store.deferReadinessForHost() else { return false }
        return await integrityTransactions.withLock { [self] in
            do {
                try await hydrateUnlockedLocked(expectedEpoch: expectedEpoch)
                if signer == nil {
                    _ = try await store.configurationGeneration(expectedEpoch: expectedEpoch)
                    let digest = try await store.trustDigest(expectedEpoch: expectedEpoch)
                    generationLock.withLock {
                        cachedStateDigest = digest
                    }
                    guard await store.markReady(expectedEpoch: expectedEpoch) else { return false }
                }
                return true
            } catch {
                return false
            }
        }
    }

    /// Warms upstream MCP servers after the vault reaches `.ready`.
    public func warmUpstreams() async {
        guard await store.operational() else { return }
        let manager = upstreamManager
        let entries = upstreams.list()
        Task.detached { await manager.warmUp(entries) }
    }

    /// Applies post-unlock effects only to the matching vault epoch.
    @discardableResult
    public func finishPostUnlock(expectedEpoch: Int64) async -> Bool {
        await integrityTransactions.withLock { [self] in
            if let hook = hooksLock.withLock({ lifecycleTestHooks.beforePostGateEffects }) {
                await hook()
            }
            guard await store.lifecycleIsCurrent(expectedEpoch, phase: .ready) else { return false }
            if let events = try? await readAuditEvents() {
                guard await store.lifecycleIsCurrent(expectedEpoch, phase: .ready) else { return false }
                for orphan in SessionJournal.orphans(in: events) {
                    _ = try? audit.append(SessionJournal.orphanedEvent(
                        key: orphan.key, identity: orphan.identity, name: orphan.name))
                }
            }
            guard await store.lifecycleIsCurrent(expectedEpoch, phase: .ready) else { return false }
            _ = try? audit.append(SessionJournal.boundaryEvent(locked: false))
            await warmUpstreams()
            return await store.lifecycleIsCurrent(expectedEpoch, phase: .ready)
        }
    }

    /// On lock, clears active sessions and hydrated data, then stops upstream and
    /// SSH child processes that may hold secrets.
    public func lockVault() async {
        await integrityTransactions.withLock { [self] in
            let expectedEpoch = await store.epoch()
            let phase = await store.phaseNow()
            if phase == .ready, await store.beginLock(expectedEpoch: expectedEpoch) {
                // Block Engine/mgmt first, then make the session boundary durable.
                onVaultLocked()
                do {
                    let generation = try await store.configurationGeneration(expectedEpoch: expectedEpoch)
                    let digest = try await store.trustDigest(expectedEpoch: expectedEpoch)
                    let floor = try await store.anchorCounterFloor(expectedEpoch: expectedEpoch) ?? 0
                    try await checkpointAnchorLocked(expectedEpoch: expectedEpoch,
                                                     generation: generation, digest: digest,
                                                     minimumCounter: floor)
                } catch {
                    // Locking is a safety action and cannot be refused. The last
                    // previously paired anchor+floor remains valid; this tail will
                    // not be falsely claimed as checkpointed.
                }
                await store.lock()
                return
            }
            // Already quarantined/auto-locked/stale: never sign that state.
            await store.lock()
            onVaultLocked()
        }
    }

    public func onVaultLocked() {
        // Record session ends and the lock boundary before clearing memory.
        for s in sessions.clear() {
            _ = try? audit.append(SessionJournal.endedEvent(s))
        }
        _ = try? audit.append(SessionJournal.boundaryEvent(locked: true))
        settings.clear()
        hosts.clear()
        upstreams.clear()
        allowlist.clear()
        upstreamManager.killAll()
        sshLifecycle.killAll()   // kill in-flight ssh.exec groups and revoke agents
    }

    /// Durable `session.ended` row for a session the sweeper retired.
    public func recordSessionEnd(_ s: SessionInfo) {
        _ = try? audit.append(SessionJournal.endedEvent(s))
    }

    // MARK: - Integrity

    /// Audit signer and anchor storage. Both may be nil in test hosts.
    public let signer: (any AuditSigner)?
    public let anchorStore: (any AnchorStore)?
    /// Protects the last committed digest and highest observed anchor counter.
    private let generationLock = NSLock()
    /// Used to detect an operation that threw after partially changing disk.
    private var cachedStateDigest = ""
    /// Highest anchor this process has durably saved or verified. It is combined
    /// with the sealed floor before every mint, so a deleted anchor can never
    /// reset the counter while this process is alive.
    private var cachedAnchorCounter: Int64 = 0

    public enum IntegrityTransactionError: Error, Equatable, Sendable {
        case staleLifecycle
        case generationExhausted
    }

    /// Hydrates state, verifies integrity, checkpoints the anchor, and publishes `.ready`.
    /// Returns nil when superseded by a newer lock or unlock.
    public func activateUnlockedVault(expectedEpoch: Int64) async -> [IntegrityIssue]? {
        await integrityTransactions.withLock { [self] in
            if Task.isCancelled { return nil }
            do {
                try await hydrateUnlockedLocked(expectedEpoch: expectedEpoch)
            } catch {
                guard await store.lifecycleIsCurrent(expectedEpoch, phase: .unlocking) else {
                    return nil
                }
                let issues = [IntegrityIssue("hydration-unreadable",
                    "The sealed vault configuration could not be decoded (\(error)).")]
                _ = await freezeLocked(issues, expectedEpoch: expectedEpoch)
                return issues
            }
            return await runIntegrityGateLocked(expectedEpoch: expectedEpoch,
                                                expectedPhase: .unlocking)
        }
    }

    /// The unlock-time integrity gate. First unlock under integrity protection
    /// Adopts the current signer (seals its public key under the DEK) and arms
    /// the anchor; afterwards every unlock verifies journal + vault freshness
    /// against the anchor and the head signature against the adopted key.
    @discardableResult
    public func runIntegrityGate() async -> [IntegrityIssue] {
        let expectedEpoch = await store.epoch()
        let phase = await store.phaseNow()
        if phase == .ready { return [] }
        guard phase == .unlocking else {
            return [IntegrityIssue("integrity-gate-unavailable",
                "The integrity gate can run only during an active unlock.")]
        }
        return await integrityTransactions.withLock { [self] in
            await runIntegrityGateLocked(expectedEpoch: expectedEpoch,
                                         expectedPhase: phase)
                ?? [IntegrityIssue("lifecycle-superseded",
                    "A newer vault lifecycle superseded this integrity check.")]
        }
    }

    private func runIntegrityGateLocked(expectedEpoch: Int64,
                                        expectedPhase: VaultPhase) async -> [IntegrityIssue]? {
        guard await store.lifecycleIsCurrent(expectedEpoch, phase: expectedPhase) else { return nil }
        guard let signer, let anchorStore else {
            do {
                _ = try await store.configurationGeneration(expectedEpoch: expectedEpoch)
                let digest = try await store.trustDigest(expectedEpoch: expectedEpoch)
                generationLock.withLock { cachedStateDigest = digest }
            } catch {
                let issues = [IntegrityIssue("trust-state-unreadable",
                    "Vault integrity state is unreadable: \(error)")]
                _ = await freezeLocked(issues, expectedEpoch: expectedEpoch)
                return issues
            }
            guard await store.markReady(expectedEpoch: expectedEpoch) else { return nil }
            return []
        }

        let gen: Int64
        let sealed: Data?
        do {
            gen = try await store.configurationGeneration(expectedEpoch: expectedEpoch)
            sealed = try await store.blob(key: VaultStore.auditSignerBlobKey)
        } catch {
            let issues = [IntegrityIssue("trust-state-unreadable",
                "Sealed integrity metadata is unreadable: \(error)")]
            _ = await freezeLocked(issues, expectedEpoch: expectedEpoch)
            return issues
        }
        guard let sealed, !sealed.isEmpty else {
            // Adopt a signer root only for a vault created during this launch.
            guard store.createdThisLaunch else {
                let issues = [IntegrityIssue("signer-root-missing",
                    "The audit trust root is missing. The vault may have been altered or restored. Accept the current state only if you expect this change.")]
                _ = await freezeLocked(issues, expectedEpoch: expectedEpoch)
                return issues
            }
            do {
                try await store.setBlob(key: VaultStore.auditSignerBlobKey, data: signer.publicKeyX963,
                                        expectedEpoch: expectedEpoch)
                // A new vault must not reuse an anchor from an older vault.
                try anchorStore.reset()
                let digest = try await store.trustDigest(expectedEpoch: expectedEpoch)
                try await publishReadyLocked(expectedEpoch: expectedEpoch, generation: gen,
                                             digest: digest, minimumCounter: 0)
            } catch {
                let issues = [IntegrityIssue("signer-root-unsealed",
                    "Could not seal the audit trust root. The vault remains quarantined: \(error)")]
                _ = await freezeLocked(issues, expectedEpoch: expectedEpoch)
                return issues
            }
            return []
        }
        // Once a signer root is adopted, the sealed replay counter is required.
        let floor: Int64
        let anchor: AnchorState?
        let digest: String
        do {
            guard let decodedFloor = try await store.anchorCounterFloor(expectedEpoch: expectedEpoch) else {
                let issues = [IntegrityIssue("anchor-floor-missing",
                    "The replay counter is missing. The vault may have been altered or restored. Accept the current state only if you expect this change.")]
                _ = await freezeLocked(issues, expectedEpoch: expectedEpoch)
                return issues
            }
            floor = decodedFloor
            anchor = try anchorStore.load()
            digest = try await store.trustDigest(expectedEpoch: expectedEpoch)
        } catch {
            let issues = [IntegrityIssue("trust-state-unreadable",
                "Vault rollback state is unreadable: \(error)")]
            _ = await freezeLocked(issues, expectedEpoch: expectedEpoch)
            return issues
        }
        var issues = IntegrityCheck.run(anchor: anchor, anchorExpected: true,
                                        signerPub: sealed, currentSignerPub: signer.publicKeyX963,
                                        auditDir: auditDir, dbGeneration: gen,
                                        currentStateDigest: digest,
                                        anchorCounterFloor: floor)
        // The writer's recipient must match the vault-sealed audit identity.
        if !(await store.auditRecipientMatches(audit.recipientX963)) {
            issues.append(IntegrityIssue("audit-recipient-swapped",
                "The audit recipient does not match the sealed identity. Audit encryption may have been redirected."))
        }
        if let hook = hooksLock.withLock({ lifecycleTestHooks.beforeGateCommit }) {
            await hook()
        }
        guard await store.lifecycleIsCurrent(expectedEpoch, phase: expectedPhase) else { return nil }
        if issues.isEmpty {
            do {
                try await publishReadyLocked(expectedEpoch: expectedEpoch, generation: gen,
                                             digest: digest, minimumCounter: floor)
                return []
            } catch {
                issues.append(IntegrityIssue("anchor-checkpoint-failed",
                    "The verified state could not be checkpointed durably (\(error))."))
            }
        }
        _ = await freezeLocked(issues, expectedEpoch: expectedEpoch)
        return issues
    }

    /// Checkpoints integrity state before publishing readiness.
    private func publishReadyLocked(expectedEpoch: Int64, generation: Int64,
                                    digest: String, minimumCounter: Int64) async throws {
        try await checkpointAnchorLocked(expectedEpoch: expectedEpoch, generation: generation,
                                         digest: digest, minimumCounter: minimumCounter)
        guard await store.markReady(expectedEpoch: expectedEpoch) else {
            throw IntegrityTransactionError.staleLifecycle
        }
    }

    @discardableResult
    private func freezeLocked(_ issues: [IntegrityIssue], expectedEpoch: Int64) async -> Bool {
        guard await store.quarantine(expectedEpoch: expectedEpoch) else { return false }
        return true
    }

    /// Accepts the current state by sealing the current signer as the trust root,
    /// appending an audit event, and creating a new anchor. The app requires Touch ID.
    @discardableResult
    public func readoptIntegrity() async -> Bool {
        let expectedEpoch = await store.epoch()
        return await integrityTransactions.withLock { [self] in
            if Task.isCancelled { return false }
            guard let signer, let anchorStore,
                  await store.lifecycleIsCurrent(expectedEpoch, phase: .quarantined) else {
                return false
            }
            if let hook = hooksLock.withLock({ lifecycleTestHooks.beforeReadoptCommit }) {
                await hook()
            }
            guard await store.lifecycleIsCurrent(expectedEpoch, phase: .quarantined) else {
                return false
            }
            do {
                let cachedMinimum = generationLock.withLock { cachedAnchorCounter }
                let sealedMinimum = try await store.anchorCounterFloor(expectedEpoch: expectedEpoch) ?? 0
                let minimum = max(cachedMinimum, sealedMinimum)
                try await store.setBlob(key: VaultStore.auditSignerBlobKey,
                                        data: signer.publicKeyX963, expectedEpoch: expectedEpoch)
                let gen = try await store.configurationGeneration(expectedEpoch: expectedEpoch)
                _ = try audit.append(AuditEvent(
                    channel: SessionJournal.vaultChannel, tool: "integrity.readopt",
                    argsPreview: "Accepted the current vault and audit state",
                    decision: "info", rule: "vault.lifecycle"))
                let digest = try await store.trustDigest(expectedEpoch: expectedEpoch)
                // Explicit re-adopt is the one operation allowed to replace an
                // unreadable/forged anchor; preserve monotonicity from memory.
                try anchorStore.reset()
                try await checkpointAnchorLocked(expectedEpoch: expectedEpoch,
                                                 generation: gen, digest: digest,
                                                 minimumCounter: minimum)
                guard await store.auditRecipientMatches(audit.recipientX963),
                      await store.clearQuarantine(expectedEpoch: expectedEpoch) else {
                    throw IntegrityTransactionError.staleLifecycle
                }
                return true
            } catch {
                _ = await store.quarantine(expectedEpoch: expectedEpoch)
                return false
            }
        }
    }

    /// The sealed configuration generation (0 for a fresh vault). Requires the
    /// vault unlocked and rejects malformed/negative state.
    public func dbGeneration(expectedEpoch: Int64? = nil) async throws -> Int64 {
        try await store.configurationGeneration(expectedEpoch: expectedEpoch)
    }

    /// Serialize a complete management mutation with its generation and freshness
    /// checkpoint. A successful reply means all four landed in order. If an
    /// operation throws after partially changing disk, digest comparison detects
    /// it and freezes the vault instead of continuing on unanchored state.
    public func commitMutation<T: Sendable>(
        expectedEpoch suppliedEpoch: Int64? = nil,
        _ operation: @escaping @Sendable () async throws -> T
    ) async throws -> T {
        try await integrityTransactions.withLock { [self] in
            try Task.checkCancellation()
            let expectedEpoch: Int64
            if let suppliedEpoch {
                expectedEpoch = suppliedEpoch
            } else {
                expectedEpoch = await store.epoch()
            }
            guard await store.lifecycleIsCurrent(expectedEpoch, phase: .ready) else {
                throw VaultStoreError.locked
            }

            // Exhaustion and unreadable freshness state are knowable before the
            // user operation. Refuse before touching durable configuration; it
            // is not enough to let the mutation land and quarantine afterward.
            let currentGeneration: Int64
            let nextGeneration: Int64
            do {
                currentGeneration = try await store.configurationGeneration(
                    expectedEpoch: expectedEpoch)
                let (next, overflow) = currentGeneration.addingReportingOverflow(1)
                guard !overflow, next > currentGeneration else {
                    throw IntegrityTransactionError.generationExhausted
                }
                nextGeneration = next

                let floor = try await store.anchorCounterFloor(expectedEpoch: expectedEpoch) ?? 0
                if signer != nil, let anchorStore {
                    let previousCounter = try anchorStore.load()?.counter ?? 0
                    let cachedCounter = generationLock.withLock { cachedAnchorCounter }
                    let highestCounter = max(max(previousCounter, floor), cachedCounter)
                    guard previousCounter >= 0, floor >= 0, cachedCounter >= 0,
                          highestCounter < Int64.max else {
                        throw AnchorStoreError.invalidState
                    }
                }
            } catch {
                _ = await freezeLocked([IntegrityIssue("mutation-preflight-failed",
                    "Could not advance integrity state. The configuration change was not applied: \(error)")],
                    expectedEpoch: expectedEpoch)
                throw error
            }

            let value: T
            do {
                value = try await operation()
            } catch {
                let currentDigest = try? await store.trustDigest(expectedEpoch: expectedEpoch)
                let priorDigest = generationLock.withLock { cachedStateDigest }
                if currentDigest == nil || currentDigest != priorDigest {
                    _ = await freezeLocked([IntegrityIssue("mutation-partial",
                        "A failed configuration change modified integrity state.")],
                        expectedEpoch: expectedEpoch)
                }
                throw error
            }

            do {
                guard await store.lifecycleIsCurrent(expectedEpoch, phase: .ready) else {
                    throw IntegrityTransactionError.staleLifecycle
                }
                let observedGeneration = try await store.configurationGeneration(
                    expectedEpoch: expectedEpoch)
                guard observedGeneration == currentGeneration else {
                    throw VaultStoreError.invalidIntegrityState(
                        "configuration generation changed during its mutation")
                }
                let data = try JSONEncoder().encode(nextGeneration)
                try await store.setBlob(key: VaultStore.generationBlobKey, data: data,
                                        expectedEpoch: expectedEpoch)
                let digest = try await store.trustDigest(expectedEpoch: expectedEpoch)
                let floor = try await store.anchorCounterFloor(expectedEpoch: expectedEpoch) ?? 0
                try await checkpointAnchorLocked(expectedEpoch: expectedEpoch, generation: nextGeneration,
                                                 digest: digest, minimumCounter: floor)
                return value
            } catch {
                _ = await freezeLocked([IntegrityIssue("mutation-checkpoint-failed",
                    "A configuration change could not be checkpointed durably (\(error)).")],
                    expectedEpoch: expectedEpoch)
                throw error
            }
        }
    }

    private func checkpointAnchorLocked(expectedEpoch: Int64, generation: Int64,
                                        digest: String, minimumCounter: Int64) async throws {
        guard await store.lifecycleIsCurrent(expectedEpoch) else {
            throw IntegrityTransactionError.staleLifecycle
        }
        guard let signer, let anchorStore else {
            generationLock.withLock { cachedStateDigest = digest }
            return
        }
        let previous = try anchorStore.load()
        let cached = generationLock.withLock { cachedAnchorCounter }
        let anchor = try IntegrityCheck.mintAnchor(
            previous: previous, signer: signer, auditDir: auditDir,
            dbGeneration: generation, stateDigest: digest,
            minimumCounter: max(minimumCounter, cached))
        try anchorStore.save(anchor)
        // The file is already durable. Remember its counter even if sealing the
        // paired floor fails, so an explicit recovery cannot reuse/decrease it.
        generationLock.withLock { cachedAnchorCounter = anchor.counter }
        let floorData = try JSONEncoder().encode(anchor.counter)
        try await store.setBlob(key: VaultStore.anchorFloorBlobKey, data: floorData,
                                expectedEpoch: expectedEpoch)
        generationLock.withLock {
            cachedStateDigest = digest
            cachedAnchorCounter = anchor.counter
        }
    }

    public enum RecordingError: Error, Equatable, Sendable {
        case invalidPath
        case notRegularFile
        case tooLarge
        case io(Int32)
    }

    /// Maximum sealed SSH recording size accepted by the UI read path.
    private static let maxRecordingBytes: off_t = 64 * 1024 * 1024

    /// Decrypts a direct, regular `*.cast.sealed` child of `recordDir` while the
    /// vault is open. The filename is authenticated with the recording.
    public func readRecording(path: String) async throws -> Data {
        guard !path.isEmpty else { throw RecordingError.invalidPath }
        let requested = URL(fileURLWithPath: path).standardizedFileURL
        let root = recordDir.resolvingSymlinksInPath().standardizedFileURL
        let parent = requested.deletingLastPathComponent()
            .resolvingSymlinksInPath().standardizedFileURL
        let filename = requested.lastPathComponent
        guard parent.path == root.path,
              filename.hasSuffix(".cast.sealed"),
              filename != ".cast.sealed" else {
            throw RecordingError.invalidPath
        }

        let dirFD = Darwin.open(root.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard dirFD >= 0 else { throw RecordingError.io(errno) }
        defer { Darwin.close(dirFD) }

        // O_NOFOLLOW rejects a final symlink. Opening relative to the pinned
        // directory descriptor means a concurrent rename cannot redirect this
        // lookup outside the recordings directory. O_NONBLOCK prevents a FIFO
        // planted in the directory from hanging before fstat can reject it.
        let fd = filename.withCString {
            Darwin.openat(dirFD, $0, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        }
        guard fd >= 0 else {
            if errno == ELOOP { throw RecordingError.notRegularFile }
            throw RecordingError.io(errno)
        }
        defer { Darwin.close(fd) }

        var info = stat()
        guard Darwin.fstat(fd, &info) == 0 else { throw RecordingError.io(errno) }
        // nlink==1 rejects hardlink-based location-boundary bypasses. A valid
        // recording is atomically created as one private file and never needs
        // multiple names; backups should copy ciphertext, not hardlink it.
        guard (info.st_mode & S_IFMT) == S_IFREG, info.st_nlink == 1 else {
            throw RecordingError.notRegularFile
        }
        guard info.st_size >= 0, info.st_size <= Self.maxRecordingBytes,
              let byteCount = Int(exactly: info.st_size) else {
            throw RecordingError.tooLarge
        }

        var sealed = Data(count: byteCount)
        try sealed.withUnsafeMutableBytes { raw in
            guard byteCount > 0 else { return }
            guard let base = raw.baseAddress else { throw RecordingError.io(EIO) }
            var offset = 0
            while offset < byteCount {
                let n = Darwin.read(fd, base.advanced(by: offset), byteCount - offset)
                if n < 0 {
                    if errno == EINTR { continue }
                    throw RecordingError.io(errno)
                }
                guard n > 0 else { throw RecordingError.io(EIO) }
                offset += n
            }
        }
        // Refuse a file replaced/truncated/grown during the read. AEAD would
        // reject altered bytes too; this keeps the resource contract explicit.
        var after = stat()
        guard Darwin.fstat(fd, &after) == 0 else { throw RecordingError.io(errno) }
        guard after.st_size == info.st_size, after.st_nlink == 1 else {
            throw RecordingError.io(EIO)
        }
        return try await store.openRecording(sealed, filename: filename)
    }

    /// Decrypts and verifies audit entries while the vault is open.
    public func readAuditEvents() async throws -> [AuditEvent] {
        var identity = try await store.auditIdentity()
        defer { identity.resetBytes(in: 0..<identity.count) }
        // Audit reads require the adopted signer key and verify every row.
        guard let signerPub = try await store.blob(key: VaultStore.auditSignerBlobKey),
              !signerPub.isEmpty else {
            throw AuditError.signerUnavailable
        }
        return try AuditLog.read(dir: auditDir, identityRaw: identity, signerPublicKeyX963: signerPub)
    }
}

/// Async-to-sync bridge used by the synchronous SSH recording callback.
private final class SyncBox<U>: @unchecked Sendable { var v: U? }

/// Preserves recording-seal errors across the async-to-sync bridge.
func syncAwaitResult<T: Sendable>(_ op: @Sendable @escaping () async throws -> T,
                                  timeout: TimeInterval = 2) -> Result<T, any Error> {
    let sem = DispatchSemaphore(value: 0)
    let box = SyncBox<Result<T, any Error>>()
    let task = Task {
        do { box.v = .success(try await op()) } catch { box.v = .failure(error) }
        sem.signal()
    }
    let bounded = timeout.isFinite ? max(0, min(timeout, 60)) : 0
    guard sem.wait(timeout: .now() + bounded) == .success else {
        task.cancel()
        return .failure(VaultStoreError.io("sync bridge timed out"))
    }
    return box.v ?? .failure(VaultStoreError.io("sync bridge returned nothing"))
}
