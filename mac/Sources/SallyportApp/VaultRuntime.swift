import Foundation
import CryptoKit
import SallyportKit
import SallyportVault

/// Owns the vault host, keystore, and lifecycle used by the app.
@MainActor
final class VaultRuntime {
    let paths: OnboardingPaths

    /// Set before the host is created.
    var approver: (any Approver)?
    /// Forwarded to the engine's activity sink once the host is built.
    var onActivity: (@Sendable (AuditEvent) -> Void)?

    private(set) var host: VaultHost?
    /// Integrity issues found during the last unlock.
    private(set) var integrityIssues: [IntegrityIssue] = []
    /// Keystore instance shared with the open store.
    private var keystore: (any Keystore)?
    /// True when vault files exist but cannot be opened.
    private(set) var incompatibleVault = false

    init(paths: OnboardingPaths) { self.paths = paths }

    // MARK: - Integrity plumbing

    /// Uses the Secure Enclave in release builds and a software key in debug builds.
    private lazy var auditSigner: (any AuditSigner)? = {
        if let se = SecureEnclaveAuditSigner.makeAvailable() { return se }
        #if DEBUG
        return try? SoftwareAuditSigner.persistent()
        #else
        return nil
        #endif
    }()

    /// Default vaults keep the rollback anchor outside the vault directory.
    /// Custom homes keep it inside the custom directory for isolation.
    private lazy var anchorStore: any AnchorStore = {
        let name = "integrity-anchor.json"
        let isDefaultHome = paths.home == NSHomeDirectory()
        if isDefaultHome, let dir = Keychain.storeDirectory() {
            return FileAnchorStore(url: dir.appendingPathComponent(name))
        }
        return FileAnchorStore(url: URL(fileURLWithPath: paths.sallyportHome).appendingPathComponent(name))
    }()

    // MARK: - Derived paths

    var socketPath: String { paths.sallyportHome + "/sallyport.sock" }
    private var auditDir: String { paths.sallyportHome + "/audit" }
    private var knownHostsPath: String { paths.sallyportHome + "/known_hosts" }
    private var recordDir: String { paths.sallyportHome + "/recordings" }
    private var vaultURL: URL { URL(fileURLWithPath: paths.vaultDB) }
    private var keystoreURL: URL { URL(fileURLWithPath: paths.keystore) }

    // MARK: - Facts

    var hasVaultOnDisk: Bool {
        let fm = FileManager.default
        return fm.fileExists(atPath: paths.vaultDB) && fm.fileExists(atPath: paths.keystore)
    }

    /// Whether the parsed keystore uses the hardware-gated backend.
    var isGated: Bool {
        ((try? KeystoreLoader.load(from: keystoreURL)) as? SEDelegatedKeystore) != nil
    }

    // MARK: - Lifecycle

    /// Opens an existing vault in its locked state and starts the agent socket.
    /// Only unreadable vault files set `incompatibleVault`.
    func start() async {
        guard host == nil, hasVaultOnDisk else { return }
        let ks: any Keystore
        let store: VaultStore
        do {
            ks = try KeystoreLoader.load(from: keystoreURL)
            // Release builds accept only a hardware-gated keystore.
            #if !DEBUG
            // Check the parsed keystore type.
            guard ks is SEDelegatedKeystore else {
                Log.line("VaultRuntime: refusing a non-hardware keystore in a release build")
                incompatibleVault = true
                return
            }
            #endif
            store = try VaultStore(openingAt: vaultURL, keystore: ks)
        } catch {
            Log.line("VaultRuntime: cannot open existing vault: \(error)")
            incompatibleVault = true
            return
        }
        incompatibleVault = false
        self.keystore = ks
        do {
            try await buildAndStartHost(store: store)
        } catch {
            // Keep readable vault files after a host startup failure.
            Log.line("ERROR: VaultRuntime: vault opened but the host failed to start: \(error)")
            await store.close()
            self.keystore = nil
        }
    }

    /// Creates an unlocked vault. Release builds require the hardware gate.
    /// Incompatible files are archived before creation.
    /// - Parameter hardwareGate: Pass `false` only in tests and development builds.
    func createVault(hardwareGate: Bool, signer: any KeyCustodian, gate: IdentityGate?) async throws {
        // Release builds never create software-gated vaults.
        #if !DEBUG
        guard hardwareGate else { throw RuntimeError.noSecureEnclave }
        #endif
        if hardwareGate {
            guard signer.backend == .secureEnclave, gate != nil else {
                throw RuntimeError.noSecureEnclave
            }
        }
        // Never replace a readable vault.
        if hasVaultOnDisk && !incompatibleVault {
            throw RuntimeError.vaultExists
        }
        archiveIncompatibleVaultIfNeeded()

        let ks: any Keystore
        if hardwareGate, let gate {
            let (delegated, identity) = try SEDelegatedKeystore.generate()
            try delegated.save(to: keystoreURL)
            // Seal the identity for future Touch ID unlocks. There is no recovery
            // if the Secure Enclave key is lost.
            try gate.seal(identity: identity, using: signer)
            ks = delegated
        } else {
            let fileAge = FileAgeKeystore()
            try fileAge.save(to: keystoreURL)
            ks = fileAge
        }
        let store = try VaultStore(creatingAt: vaultURL, keystore: ks)
        self.keystore = ks
        try await buildAndStartHost(store: store)
        incompatibleVault = false
    }

    /// Moves an unlocked software vault to the hardware-gated keystore.
    /// The existing keystore remains usable until the replacement is ready.
    func enableHardwareGate(signer: any KeyCustodian, gate: IdentityGate) async throws {
        guard let store = host?.store else { throw RuntimeError.noVault }
        guard !(await store.locked()) else { throw RuntimeError.mustBeUnlocked }
        guard !isGated else { return }
        guard signer.backend == .secureEnclave else { throw RuntimeError.noSecureEnclave }

        let (delegated, identity) = try SEDelegatedKeystore.generate()
        try gate.seal(identity: identity, using: signer)
        try await store.rekey(to: delegated)
        self.keystore = delegated
        try delegated.save(to: keystoreURL)
        try await store.finalizeRekey()
        Log.line("VaultRuntime: hardware gate enabled")
    }

    /// Deletes the vault and its data, then creates a hardware-gated vault.
    /// Secure Enclave key blobs remain because the new vault uses them.
    func resetVault(signer: any KeyCustodian, gate: IdentityGate?) async throws {
        if let store = host?.store { await store.close() }
        host?.stop()
        host = nil
        keystore = nil
        incompatibleVault = false

        let fm = FileManager.default
        // Remove all vault data.
        if fm.fileExists(atPath: paths.sallyportHome) {
            try fm.removeItem(atPath: paths.sallyportHome)
            Log.line("resetVault: erased \(paths.sallyportHome)")
        }
        // The sealed identity is stored outside the vault directory.
        if let gate, fm.fileExists(atPath: gate.blobURL.path) {
            try fm.removeItem(at: gate.blobURL)
            Log.line("resetVault: erased \(gate.blobURL.lastPathComponent)")
        }
        // Reset the anchor for the new vault.
        try anchorStore.reset()
        integrityIssues = []

        // Create the replacement vault.
        try await createVault(hardwareGate: true, signer: signer, gate: gate)
    }

    /// Unlocks the vault and loads its encrypted configuration.
    func unlock(identity: String) async throws {
        guard let host else { throw RuntimeError.noVault }
        if let sealer = keystore as? Sealer {
            guard !identity.isEmpty else { throw RuntimeError.sealedNoIdentity }
            try sealer.deliver(identity: identity)
        }
        let epoch = try await host.store.unlock(deferReady: true)
        guard let issues = await host.activateUnlockedVault(expectedEpoch: epoch),
              await postUnlockIntegrity(host, expectedEpoch: epoch, issues: issues) else {
            throw RuntimeError.lifecycleSuperseded
        }
    }

    /// Verifies integrity after unlock and publishes the ready state.
    private func postUnlockIntegrity(_ host: VaultHost, expectedEpoch: Int64,
                                     issues: [IntegrityIssue]) async -> Bool {
        guard await host.store.lifecycleIsCurrent(expectedEpoch) else { return false }
        if !issues.isEmpty {
            integrityIssues = issues
            Log.line("INTEGRITY: quarantined: \(issues.map(\.code).joined(separator: ", "))")
            return true
        }
        guard await host.finishPostUnlock(expectedEpoch: expectedEpoch) else { return false }
        integrityIssues = []
        return true
    }

    /// Replaces the integrity anchor after Touch ID confirmation.
    @discardableResult
    func readoptIntegrity() async -> Bool {
        guard let host else { return false }
        let ok = await host.readoptIntegrity()
        integrityIssues = ok ? [] : integrityIssues
        return ok
    }

    /// Reads the decrypted audit journal from an unlocked vault.
    func auditEvents() async throws -> [AuditEvent] {
        guard let host else { throw RuntimeError.noVault }
        return try await host.readAuditEvents()
    }

    /// Decrypt one sealed SSH session recording (unlocked vault only).
    func recording(path: String) async throws -> Data {
        guard let host else { throw RuntimeError.noVault }
        return try await host.readRecording(path: path)
    }

    /// Locks the vault and ends active sessions.
    func lock() async {
        guard let host else { return }
        await host.lockVault()
        (keystore as? Sealer)?.seal()
    }

    /// The authoritative vault snapshot for the UI countdown.
    func vaultState() async -> VaultState {
        guard let store = host?.store else { return VaultState(locked: true, ttlSec: 0) }
        let locked = await store.locked()
        return VaultState(locked: locked, ttlSec: locked ? 0 : await store.remaining())
    }

    /// Expires dead sessions and reports an auto-lock event once.
    func tick() async -> (autoLocked: Bool, endedSessions: [SallyportVault.SessionInfo]) {
        guard let host else { return (false, []) }
        let ended = host.sessions.sweep(alive: { SallyportVault.Provenance.alive(pid: $0, startedAt: $1) })
        for s in ended { host.recordSessionEnd(s) }
        let auto = await host.store.takeAutoLockEvent()
        if auto {
            (keystore as? Sealer)?.seal()
            host.onVaultLocked()
        }
        return (auto, ended)
    }

    // MARK: - Internals

    private func buildAndStartHost(store: VaultStore) async throws {
        guard let approver else { throw RuntimeError.noApprover }
        // Release builds require a hardware-backed audit signer.
        guard let signer = auditSigner else { throw RuntimeError.noSecureEnclave }
        let hosts = HostsStore()
        let sshHelper = SallyportSetup.bundledBinary("sp-ssh")?.path ?? ""
        let hostPaths = VaultHost.Paths(
            socket: socketPath, auditDir: auditDir,
            knownHosts: knownHostsPath, recordDir: recordDir, sshHelper: sshHelper)
        let h = try await VaultHost(store: store, hosts: hosts, paths: hostPaths,
                                    approver: approver, signer: signer,
                                    anchorStore: anchorStore)
        if let onActivity { await h.onActivity(onActivity) }
        if let prompter = approver as? CredentialPrompter { await h.onCredentialAsk(prompter) }
        // Load configuration immediately for a newly created vault.
        if await !h.store.locked() {
            let epoch = try await h.store.deferReadinessForHost()
            guard let issues = await h.activateUnlockedVault(expectedEpoch: epoch),
                  await postUnlockIntegrity(h, expectedEpoch: epoch, issues: issues) else {
                throw RuntimeError.lifecycleSuperseded
            }
        }
        try h.start()
        self.host = h
        Log.line("VaultRuntime: host up on \(socketPath) (ssh helper: \(sshHelper.isEmpty ? "none" : sshHelper))")
    }

    /// Archives incompatible vault files and obsolete plaintext sidecars.
    private func archiveIncompatibleVaultIfNeeded() {
        let fm = FileManager.default
        let stamp = UUID().uuidString.lowercased()
        var legacy = [paths.vaultDB, paths.keystore]
        legacy += ["settings.json", "hosts.json", "activity.jsonl"]
            .map { paths.sallyportHome + "/" + $0 }
        for path in legacy where fm.fileExists(atPath: path) {
            let dest = path + ".pre-v2-\(stamp)"
            try? fm.moveItem(atPath: path, toPath: dest)
            Log.line("VaultRuntime: archived \(path) -> \(dest)")
        }
    }

    enum RuntimeError: LocalizedError {
        case noVault, noApprover, sealedNoIdentity, vaultExists, mustBeUnlocked, noSecureEnclave
        case lifecycleSuperseded
        var errorDescription: String? {
            switch self {
            case .noVault: return "No vault is open."
            case .noApprover: return "Approval handling is unavailable."
            case .sealedNoIdentity: return "The hardware-gated vault has no identity."
            case .vaultExists: return "A readable vault already exists."
            case .mustBeUnlocked: return "Unlock the vault first."
            case .lifecycleSuperseded: return "The vault was locked or unlocked again before this operation finished."
            case .noSecureEnclave:
                return "Sallyport hardware protection requires Apple Silicon and the signed app."
            }
        }
    }
}
