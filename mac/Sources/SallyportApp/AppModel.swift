import Foundation
import Observation
import AppKit
import SallyportKit
import SallyportVault

enum ConnectionState: Sendable, Equatable {
    case disconnected
    case connecting
    case connected
    case waiting
}

enum MainTab: String, CaseIterable, Identifiable {
    // Monitor
    case approvals, activity, sessions
    // Configure (the management surface)
    case keys, hosts, mcp, agents
    // System
    case integrations, vault, settings, setup, about

    var id: String { rawValue }

    var title: LocalizedStringResource {
        switch self {
        case .approvals: return LocalizedStringResource("Approvals")
        case .activity: return LocalizedStringResource("Activity")
        case .sessions: return LocalizedStringResource("Sessions")
        case .keys: return LocalizedStringResource("Keys and APIs")
        case .hosts: return LocalizedStringResource("SSH hosts")
        case .mcp: return LocalizedStringResource("MCP servers")
        case .agents: return LocalizedStringResource("Agent allowlist")
        case .integrations: return LocalizedStringResource("Integrations")
        case .vault: return LocalizedStringResource("Vault and keys")
        case .settings: return LocalizedStringResource("Settings")
        case .setup: return LocalizedStringResource("Setup")
        case .about: return LocalizedStringResource("About")
        }
    }
    var symbol: String {
        switch self {
        case .approvals: return "checkmark.shield"
        case .activity: return "list.bullet.rectangle"
        case .sessions: return "person.badge.shield.checkmark"
        case .keys: return "key.fill"
        case .hosts: return "server.rack"
        case .mcp: return "puzzlepiece.extension.fill"
        case .agents: return "person.2.badge.key.fill"
        case .integrations: return "puzzlepiece.extension"
        case .vault: return "lock.rectangle.stack"
        case .settings: return "gearshape"
        case .setup: return "sparkles"
        case .about: return "info.circle"
        }
    }

    /// Sidebar groups.
    enum Section: String, CaseIterable, Identifiable {
        case monitor
        case configure
        case system
        var id: String { rawValue }
        var title: LocalizedStringResource {
            switch self {
            case .monitor: LocalizedStringResource("Monitor")
            case .configure: LocalizedStringResource("Configure")
            case .system: LocalizedStringResource("System")
            }
        }
        var tabs: [MainTab] {
            switch self {
            case .monitor: return [.approvals, .activity, .sessions]
            case .configure: return [.keys, .hosts, .mcp, .agents]
            case .system: return [.integrations, .vault, .settings, .setup, .about]
            }
        }
    }
}

/// Setup completion state.
struct OnboardingState: Sendable, Equatable {
    var agentInstalled = false
    var vaultCreated = false
    var agentConnected = false
    var allDone: Bool { agentInstalled && vaultCreated && agentConnected }
}

/// Main-actor application state for the UI, vault runtime, approvals, and management operations.
@MainActor
@Observable
final class AppModel: Approver, CredentialPrompter {
    // Live state rendered by the UI.
    var vault = VaultState(locked: true, ttlSec: 0)
    /// Wall-clock instant `vault.ttlSec` was last refreshed, anchoring the live
    /// auto-lock countdown.
    var vaultUpdatedAt = Date()
    var pending: [ApprovalRequest] = []
    /// An agent-requested credential shown in the add-key sheet.
    var credentialRequest: CredentialRequest?
    var activity = ActivityLog()
    /// Integrity findings from the last unlock.
    var integrityIssues: [IntegrityIssue] = []
    var filter = ActivityFilter()
    var connection: ConnectionState = .disconnected
    var onboarding = OnboardingState()
    var selectedTab: MainTab = .approvals
    var isDemo = false
    /// Last vault-unlock failure to surface in the UI. Cleared at the start of
    /// every `unlock()`.
    var vaultUnlockError: String?
    /// Changes when another view modifies secrets so configuration screens can reload.
    private(set) var secretsRevision = UUID()

    func secretsDidChange() { secretsRevision = UUID() }

    /// Opens or raises the main window for flows that present a sheet.
    @ObservationIgnored var openMainWindow: (() -> Void)?

    let backend: KeystoreBackend
    /// True in debug headless auto-approval mode.
    let autoApprove: Bool

    /// Vault store, engine, sessions, and agent socket.
    let runtime: VaultRuntime
    /// Backs management operations with the live runtime.
    private let vaultDaemon: VaultMgmtDaemon

    /// Custodian for the vault wrapping key. Approval decisions are not signed.
    private let signer: any KeyCustodian
    /// Seals the vault identity with the Secure Enclave K-wrap key.
    private let identityGate: IdentityGate?
    private let enricher = ProvenanceEnricher()
    private let authenticator: any Authenticator
    @ObservationIgnored private let approvalPanel = ApprovalPanelController()
    @ObservationIgnored private let notifier = ApprovalNotifier()
    @ObservationIgnored private var notifAuthRequested = false

    private struct ApprovalWaiter {
        let token: UUID
        let continuation: CheckedContinuation<ApprovalOutcome, Never>
    }
    private struct ApprovalPreResolution {
        let token: UUID
        let outcome: ApprovalOutcome
    }
    /// In-flight approvals keyed by request ID.
    /// The private token prevents a delayed timeout/cancellation for an old use
    /// of an ID from resolving a later request that happens to reuse that ID.
    @ObservationIgnored private var approvalWaiters: [String: ApprovalWaiter] = [:]
    @ObservationIgnored private var approvalTimeouts: [String: Task<Void, Never>] = [:]
    @ObservationIgnored private var approvalTokens: [String: UUID] = [:]

    private var runtimeStarted = false
    /// Ticks the auto-lock countdown + session sweep while the runtime is up.
    private var autoLockTask: Task<Void, Never>?
    @ObservationIgnored private var sleepObservers: [NSObjectProtocol] = []

    let setup: SallyportSetup

    /// Typed management client. Demo mode replaces it with a mock.
    private(set) var mgmt: MgmtClient

    var currentApproval: ApprovalRequest? { pending.first }
    var hasPendingApproval: Bool { !pending.isEmpty }
    var socketPath: String { runtime.socketPath }
    /// True when this vault uses the Secure Enclave backend.
    var isHardwareGated: Bool { runtime.isGated }
    /// Localized backend name shown in app chrome and vault status.
    var backendDisplayName: LocalizedStringResource {
        switch backend {
        case .secureEnclave: LocalizedStringResource("Secure Enclave")
        case .software: LocalizedStringResource("Software (development)")
        }
    }

    init(signer: (any KeyCustodian)? = nil,
         authenticator: (any Authenticator)? = nil,
         setup: SallyportSetup = SallyportSetup(),
         identityGate: IdentityGate? = nil) {
        self.setup = setup
        self.identityGate = identityGate ?? IdentityGate.live()
        let auto = SallyportRuntime.devAutoApprove
        self.autoApprove = auto
        let resolvedSigner = signer
            ?? KeystoreFactory.make(policy: auto ? .deviceUnlocked : .biometric)
        self.signer = resolvedSigner
        self.backend = resolvedSigner.backend
        if let authenticator {
            self.authenticator = authenticator
        } else if auto {
            self.authenticator = AutoApproveAuthenticator()
        } else {
            self.authenticator = AuthenticatorFactory.make()
        }

        // Wire the management client to the runtime backend.
        let runtime = VaultRuntime(paths: setup.paths)
        let daemon = VaultMgmtDaemon(runtime: runtime)
        self.runtime = runtime
        self.vaultDaemon = daemon
        self.mgmt = MgmtClient(sender: { _ in },
                               loopback: { [daemon] message in await daemon.handle(message) },
                               timeout: .seconds(15))

        if let se = resolvedSigner as? SecureEnclaveKeyCustodian {
            Log.line("signer=secure-enclave policy=\(se.policy.rawValue) reused=\(se.reused)")
        } else {
            Log.line("signer=\(resolvedSigner.backend.rawValue)")
        }

        // Connect approvals, activity, and configuration confirmation after initialization.
        notifier.model = self
        daemon.confirmChange = { [weak self] reason in
            guard let self else { return false }
            return await self.confirmConfigChange(reason)
        }
        // Only debug auto-approval bypasses biometric confirmation.
        daemon.allowChangesWithoutBiometrics = auto
        runtime.approver = self
        runtime.onActivity = { [weak self] event in
            Task { @MainActor in self?.recordAudit(event) }
        }
    }

    // MARK: Runtime lifecycle

    /// Reports when the Secure Enclave key for a gated vault has been replaced.
    private func checkGateIntegrity() {
        guard !isDemo, runtime.isGated, let gate = identityGate, gate.isSealed else { return }
        guard let se = signer as? SecureEnclaveKeyCustodian else { return }
        guard !se.reused else { return }
        vaultUnlockError = String(localized:
            "The Secure Enclave key for this vault is missing. The vault cannot be recovered. Create a new vault and reissue its credentials.")
        Log.line("ERROR: the Secure Enclave wrapping key changed; the sealed identity cannot be opened")
    }

    /// Starts the vault runtime, agent socket, and auto-lock timer.
    func startConnecting() {
        guard !runtimeStarted, !isDemo else { return }
        runtimeStarted = true
        checkGateIntegrity()
        connection = .connecting
        Log.line("startConnecting: hosting vault core; socket=\(socketPath) autoApprove=\(autoApprove) backend=\(backend.rawValue)")
        Task { [weak self] in
            guard let self else { return }
            await self.runtime.start()
            // Create a vault automatically only when the home is empty.
            if !self.runtime.hasVaultOnDisk {
                _ = try? await self.ensureVaultCreated()
            }
            self.connection = self.runtime.host != nil ? .connected : .waiting
            self.refreshOnboardingState()
            await self.refreshVaultFromStatus()
            await self.requestNotificationPermissionOnce()
        }
        startAutoLockTicker()
        observeSleepLock()
    }

    func connect() { startConnecting() }

    /// Every ~5s: sweep dead sessions, honor a TTL auto-lock, and re-anchor the
    /// countdown. Cheap; the kqueue watcher is the primary session-exit signal.
    private func startAutoLockTicker() {
        autoLockTask?.cancel()
        autoLockTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(5))
                guard let self, !self.isDemo else { continue }
                let (auto, ended) = await self.runtime.tick()
                for s in ended { self.recordSessionEnd(s) }
                if auto {
                    // Clear decrypted activity and pending approvals after auto-lock.
                    self.activity = ActivityLog()
                    self.cancelPendingApprovals()
                    Log.line("vault auto-locked after its timeout; sessions, activity, and approvals cleared")
                }
                await self.refreshVaultFromStatus()
            }
        }
    }

    /// Locks on sleep. Screen lock follows `lockOnScreenLock`.
    private func observeSleepLock() {
        guard sleepObservers.isEmpty, !isDemo else { return }
        let sleepLock: @Sendable (Notification) -> Void = { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self, !self.vault.locked else { return }
                Log.line("sleep: locking vault")
                self.lockNow()
            }
        }
        let ws = NSWorkspace.shared.notificationCenter
        sleepObservers.append(ws.addObserver(forName: NSWorkspace.willSleepNotification,
                                             object: nil, queue: .main, using: sleepLock))
        let dn = DistributedNotificationCenter.default()
        let screenLock: @Sendable (Notification) -> Void = { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self, !self.vault.locked else { return }
                guard self.runtime.host?.settings.lockOnScreenLock() ?? true else {
                    Log.line("screen locked; vault remains open by user setting")
                    return
                }
                Log.line("screen lock: locking vault")
                self.lockNow()
            }
        }
        sleepObservers.append(dn.addObserver(forName: Notification.Name("com.apple.screenIsLocked"),
                                             object: nil, queue: .main, using: screenLock))
        // Close the unlocked state synchronously on quit so upstream MCP child
        // processes are terminated instead of being reparented to launchd.
        sleepObservers.append(NotificationCenter.default.addObserver(
            forName: NSApplication.willTerminateNotification, object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated {
                // A locked vault already recorded session ends and its boundary.
                guard let self, !self.vault.locked else { return }
                self.runtime.host?.onVaultLocked()
            }
        })
    }

    // MARK: Activity

    /// Rebuilds the activity feed from the encrypted audit journal after unlock.
    private func hydrateActivityFromAudit() async {
        guard !isDemo else { return }
        guard let events = try? await runtime.auditEvents() else { return }
        let rows = events.filter { $0.channel != SessionJournal.vaultChannel }
            .suffix(activity.capacity).map(Self.activityRow(from:))
        activity = ActivityLog(capacity: activity.capacity, rows: Array(rows.reversed()))
    }

    /// Adds a row to the in-memory feed. The encrypted audit log is durable.
    private func record(_ row: ActivityRow) {
        activity.append(row)
    }

    /// Adds an engine audit event to the in-memory feed. Unlock reloads the journal.
    private func recordAudit(_ e: AuditEvent) {
        markAgentSeen()   // an engine event = a real agent call (onboarding step ③)
        record(Self.activityRow(from: e))
    }

    /// Maps an audit event to an activity row.
    private static func activityRow(from e: AuditEvent) -> ActivityRow {
        let origin = e.origin.map {
            ActivityOrigin(name: $0.name, path: $0.path, app: $0.app.isEmpty ? nil : $0.app,
                           pid: $0.pid, signed: $0.signed,
                           signedBy: $0.signedBy.isEmpty ? nil : $0.signedBy,
                           chain: $0.chain.isEmpty ? nil : $0.chain)
        }
        return ActivityRow(
            ts: e.ts.isEmpty ? Self.timestamp() : e.ts,
            identity: e.origin?.app.nonEmpty ?? e.origin?.name.nonEmpty ?? e.identity,
            channel: e.channel, tool: e.tool, argsPreview: e.argsPreview,
            target: e.target.isEmpty ? String(localized: "None") : e.target, decision: e.decision,
            rule: e.rule.isEmpty ? nil : e.rule, isError: e.isError,
            bytesOut: e.bytesOut == 0 ? nil : e.bytesOut,
            durationMs: e.durationMs == 0 ? nil : Int(e.durationMs),
            grantId: e.grantId.isEmpty ? nil : e.grantId,
            recording: e.recording.isEmpty ? nil : e.recording,
            origin: origin)
    }

    /// Note an ended session in the feed (the kqueue/sweep exit trail).
    private func recordSessionEnd(_ s: SallyportVault.SessionInfo) {
        record(ActivityRow(
            ts: Self.timestamp(), identity: s.app.nonEmpty ?? s.name,
            channel: "session", tool: "session.end", argsPreview: "pid \(s.pid)",
            target: String(localized: "None"), decision: "session \(s.reason?.rawValue ?? "ended")",
            rule: "session", isError: false))
    }

    /// Decrypt one sealed SSH session recording (unlocked vault only) for the
    /// Activity detail sheet's "Save recording…" action.
    func decryptRecording(path: String) async throws -> Data {
        try await runtime.recording(path: path)
    }

    /// Returns the decrypted audit log as JSONL, or an empty string while locked.
    func exportActivityJSONL() async -> String {
        guard !isDemo, let events = try? await runtime.auditEvents() else { return "" }
        let enc = JSONEncoder()
        enc.outputFormatting = [.sortedKeys]
        return events
            .compactMap { e in (try? enc.encode(e)).map { String(decoding: $0, as: UTF8.self) } }
            .joined(separator: "\n")
    }

    // MARK: Onboarding

    /// Records whether an agent has completed at least one call.
    @ObservationIgnored private var agentSeen = UserDefaults.standard.bool(forKey: "sp.agentSeen")

    private func markAgentSeen() {
        guard !agentSeen else { return }
        agentSeen = true
        UserDefaults.standard.set(true, forKey: "sp.agentSeen")
        onboarding.agentConnected = true
    }

    /// Updates setup state from the vault, runtime, and first-call marker.
    func refreshOnboardingState() {
        guard !isDemo else { return }
        onboarding = OnboardingState(
            agentInstalled: runtime.host != nil,
            vaultCreated: runtime.hasVaultOnDisk && !runtime.incompatibleVault,
            agentConnected: agentSeen)
    }

    /// Creates the vault if needed and starts its host.
    @discardableResult
    func ensureVaultCreated() async throws -> Bool {
        if runtime.hasVaultOnDisk && !runtime.incompatibleVault {
            await runtime.start()
            if runtime.host != nil {
                connection = .connected
                refreshOnboardingState()
                await refreshVaultFromStatus()
                return false
            }
        }
        // Release builds protect the vault identity with a Secure Enclave key.
        // Losing that key makes the vault unrecoverable.
        try await runtime.createVault(hardwareGate: true, signer: signer, gate: identityGate)
        connection = runtime.host != nil ? .connected : .waiting
        refreshOnboardingState()
        await refreshVaultFromStatus()
        return true
    }

    /// Rekeys an unlocked vault to a Secure Enclave-protected identity.
    func enableHardwareGate() async throws {
        guard let identityGate else {
            throw SetupError.gateEnable(String(localized:
                "No Secure Enclave store is available for the sealed identity on this Mac."))
        }
        if vault.locked {
            guard await unlockForEditing() else {
                throw SetupError.gateEnable(String(localized:
                    "Unlock the vault before enabling the hardware gate."))
            }
        }
        try await runtime.enableHardwareGate(signer: signer, gate: identityGate)
        await refreshVaultFromStatus()
    }

    // MARK: Approvals (the engine's in-process Approver)

    /// Presents a session or per-call approval request.
    /// Enqueue the card and suspend until `approve`/`deny` (or the timeout) lands.
    /// Fail-closed: an unresolved ask times out to a denial.
    nonisolated func requestApproval(_ req: EngineApproval) async -> ApprovalOutcome {
        guard !Task.isCancelled else { return .denied }
        let token = UUID()
        let accepted = await MainActor.run { self.beginApproval(req, token: token) }
        guard accepted else { return .denied }
        let outcome = await withTaskCancellationHandler(operation: {
            await withCheckedContinuation { (cont: CheckedContinuation<ApprovalOutcome, Never>) in
                Task { @MainActor in self.registerWaiter(req.id, token: token, cont) }
            }
        }, onCancel: {
            Task { @MainActor in self.cancelApproval(req.id, token: token) }
        })
        return Task.isCancelled ? .denied : outcome
    }

    private func cancelApproval(_ id: String, token: UUID) {
        guard approvalTokens[id] == token else { return }
        let request = pending.first { $0.id == id }
        resolve(id, .denied, token: token)
        if let request { finishDecision(request, decision: "ask→cancelled") }
    }

    private func beginApproval(_ req: EngineApproval, token: UUID) -> Bool {
        // Bind each visible card to one suspended operation. Reject a duplicate
        // ID before it can replace the text for an existing continuation.
        guard approvalTokens[req.id] == nil,
              !pending.contains(where: { $0.id == req.id }),
              approvalWaiters[req.id] == nil,
              preResolved[req.id] == nil else {
            Log.line("approval_request id=\(req.id) rejected: duplicate in-flight id")
            return false
        }
        approvalTokens[req.id] = token
        let request = Self.approvalRequest(from: req)
        let enriched = enricher.enrich(request.provenance)
        let ui = ApprovalRequest(id: request.id, action: request.action, why: request.why,
                                 provenance: enriched, mode: request.mode)
        enqueue(ui)
        if autoApprove {
            Log.line("approval_request id=\(req.id) tool=\(req.tool): auto-approving in development")
            finishDecision(ui, decision: "ask→approved (auto)")
        } else {
            Log.line("approval_request id=\(req.id) mode=\(req.mode) tool=\(req.tool) host=\(req.host): awaiting user")
        }
        return true
    }

    /// Register the suspended continuation (or resolve immediately if the card was
    /// already acted on / auto-approved between `beginApproval` and here).
    private func registerWaiter(_ id: String, token: UUID,
                                _ cont: CheckedContinuation<ApprovalOutcome, Never>) {
        guard approvalTokens[id] == token else {
            cont.resume(returning: .denied)
            return
        }
        if autoApprove {
            approvalTokens[id] = nil
            cont.resume(returning: .approved)
            return
        }
        guard pending.contains(where: { $0.id == id }) else {
            // A fast click resolved this before approve or deny found a waiter,
            // so honor it here. Default closed.
            let prior = preResolved[id]
            if let prior, prior.token == token {
                cont.resume(returning: prior.outcome)
            } else {
                cont.resume(returning: .denied)
            }
            preResolved[id] = nil
            approvalTokens[id] = nil
            return
        }
        approvalWaiters[id] = ApprovalWaiter(token: token, continuation: cont)
        let timeout = Task { [weak self] in
            do { try await Task.sleep(for: .seconds(120)) }
            catch { return }
            self?.timeoutApproval(id, token: token)
        }
        approvalTimeouts[id] = timeout
    }

    /// Verdicts received between enqueue and continuation registration.
    @ObservationIgnored private var preResolved: [String: ApprovalPreResolution] = [:]

    private func resolve(_ id: String, _ outcome: ApprovalOutcome, token expectedToken: UUID? = nil) {
        guard let token = approvalTokens[id], expectedToken == nil || expectedToken == token else { return }
        approvalTimeouts[id]?.cancel()
        approvalTimeouts[id] = nil
        if let waiter = approvalWaiters[id] {
            guard waiter.token == token else { return }
            approvalWaiters[id] = nil
            approvalTokens[id] = nil
            waiter.continuation.resume(returning: outcome)
        } else if !autoApprove, pending.contains(where: { $0.id == id }) {
            // Fast-click only (card visible, waiter not yet registered). A
            // verdict for an already-finished request (e.g. Touch ID finishing
            // after the 120-second timeout is dropped.
            preResolved[id] = ApprovalPreResolution(token: token, outcome: outcome)
        }
    }

    private func timeoutApproval(_ id: String, token: UUID) {
        guard approvalTokens[id] == token else { return }
        guard let request = pending.first(where: { $0.id == id }) else { return }
        resolve(id, .timedOut, token: token)
        finishDecision(request, decision: "ask→timeout")
    }

    private func enqueue(_ request: ApprovalRequest) {
        if let idx = pending.firstIndex(where: { $0.id == request.id }) {
            pending[idx] = request
        } else {
            pending.append(request)
        }
        guard !isDemo, !autoApprove else {
            approvalPanel.sync(model: self)
            return
        }
        Task { [weak self] in await self?.presentApprovalSurface(forID: request.id) }
    }

    private func presentApprovalSurface(forID requestID: String) async {
        guard !isDemo, !autoApprove else { return }
        guard pending.contains(where: { $0.id == requestID }) else { return }
        var status = await notifier.authorizationStatus()
        if status == .notDetermined {
            _ = await notifier.requestAuthorization()
            status = await notifier.authorizationStatus()
        }
        guard let request = pending.first(where: { $0.id == requestID }) else { return }
        switch ApprovalNotification.surface(for: status) {
        case .notification: notifier.present(request)
        case .panel: approvalPanel.sync(model: self)
        }
    }

    func handleNotificationDecision(_ decision: ApprovalNotification.Decision,
                                    requestID: String) async {
        guard let request = pending.first(where: { $0.id == requestID }) else { return }
        switch decision {
        case .approve: await approve(request)
        case .deny: await deny(request)
        case .detail: showApprovalDetail()
        case .ignore: break
        }
    }

    func showApprovalDetail() {
        guard !isDemo else { return }
        approvalPanel.sync(model: self)
        NSApp.activate(ignoringOtherApps: true)
    }

    // MARK: Notification permission

    private func requestNotificationPermissionOnce() async {
        guard !isDemo, !notifAuthRequested else { return }
        notifAuthRequested = true
        _ = await notifier.requestAuthorization()
    }

    @discardableResult
    func requestNotificationPermission() async -> Bool {
        await notifier.requestAuthorization()
    }

    func notificationAuthorization() async -> ApprovalNotification.Authorization {
        await notifier.authorizationStatus()
    }

    func notificationAlertStyle() async -> ApprovalNotification.AlertStyle {
        await notifier.alertStyle()
    }

    func sendTestNotification() { notifier.presentTest() }

    // MARK: Decisions

    /// Approve: resolve the engine's in-flight ask. A per-call Touch ID request
    /// authenticates first. Other requests need one click because vault unlock
    /// already required biometrics.
    func approve(_ request: ApprovalRequest) async {
        let strict = ApprovalRequest.biometricModes.contains(request.mode)
        if strict {
            let outcome = await authenticator.authenticate(reason: ApprovalCopy.touchIDReason(for: request))
            guard outcome == .approved else { return }   // keep the card pending
        }
        resolve(request.id, .approved)
        finishDecision(request, decision: "ask→approved (you)")
    }

    /// Resolves the request as a denial with a structured agent error.
    func deny(_ request: ApprovalRequest) async {
        resolve(request.id, .denied)
        finishDecision(request, decision: "ask→denied (you)")
    }

    private func finishDecision(_ request: ApprovalRequest, decision: String) {
        pending.removeAll { $0.id == request.id }
        approvalPanel.sync(model: self)
        if !isDemo { notifier.clear(requestID: request.id) }
        // Show a local timeout row immediately. The engine writes its audited
        // outcome separately after the waiter resumes.
        if decision.contains("timeout") {
            record(ActivityRow(
                ts: Self.timestamp(),
                identity: request.provenance.origin.appName ?? request.provenance.origin.name,
                channel: request.action.channel, tool: request.action.tool,
                argsPreview: ApprovalPresentation.primaryActionText(request.action),
                target: request.action.host ?? String(localized: "None"), decision: decision,
                rule: request.why.rule, isError: true))
        }
    }

    /// Build the UI card from the engine's approval ask (maps the vault-side
    /// provenance to the Kit's).
    private static func approvalRequest(from req: EngineApproval) -> ApprovalRequest {
        let o = req.origin
        let label = o.name.isEmpty
            ? (o.path.split(separator: "/").last.map(String.init) ?? String(localized: "process"))
            : o.name
        let originHop = ProcessHop(
            pid: o.pid, name: label,
            path: o.path.isEmpty ? nil : o.path, ppid: nil,
            appName: o.appName.isEmpty ? nil : o.appName,
            validSignature: o.validSignature, signedBy: o.signedBy.isEmpty ? nil : o.signedBy)
        let chain = req.chain.map { h in
            ProcessHop(pid: h.pid, name: h.name, path: h.path.isEmpty ? nil : h.path,
                       ppid: h.ppid == 0 ? nil : h.ppid)
        }
        let prov = SallyportKit.Provenance(origin: originHop, chain: chain, intact: o.validSignature)
        let action = ActionDescriptor(channel: req.channel, tool: req.tool,
                                      summary: req.summary, host: req.host.isEmpty ? nil : req.host,
                                      bodyPreview: req.bodyPreview,
                                      bodyByteCount: req.bodyByteCount,
                                      bodyPreviewTruncated: req.bodyPreviewTruncated)
        let why = WhyDescriptor(rule: req.rule, reason: req.reason)
        return ApprovalRequest(id: req.id, action: action, why: why,
                               provenance: prov, mode: req.mode)
    }

    // MARK: Credential requests (agent proposes, you add the key)

    private struct CredentialWaiter {
        let token: UUID
        let continuation: CheckedContinuation<CredentialAnswer, Never>
    }
    /// In-flight `sallyport.request_credential` requests keyed by ID.
    @ObservationIgnored private var credentialWaiters: [String: CredentialWaiter] = [:]
    @ObservationIgnored private var credentialTimeouts: [String: Task<Void, Never>] = [:]
    /// Cancellation can win the hop onto MainActor before registration. Keep the
    /// private instance token, never the caller-controlled ID, so the imminent
    /// registration declines without touching another request that reused an ID.
    @ObservationIgnored private var preCancelledCredentials: Set<UUID> = []
    /// Requests queued behind the current credential sheet.
    @ObservationIgnored private var credentialQueue: [CredentialRequest] = []

    /// The engine's credential bridge: surface the pre-filled add-key sheet and
    /// suspend until the user saves a key or dismisses it. The request times out
    /// closed after 15 minutes.
    nonisolated func requestCredential(_ ask: CredentialAsk) async -> CredentialAnswer {
        guard !Task.isCancelled else { return .declined }
        let token = UUID()
        let answer = await withTaskCancellationHandler(operation: {
            await withCheckedContinuation { (cont: CheckedContinuation<CredentialAnswer, Never>) in
                Task { @MainActor in self.beginCredential(ask, token: token, cont) }
            }
        }, onCancel: {
            Task { @MainActor in self.cancelCredential(ask.id, token: token) }
        })
        return Task.isCancelled ? .declined : answer
    }

    private func beginCredential(_ ask: CredentialAsk, token: UUID,
                                 _ cont: CheckedContinuation<CredentialAnswer, Never>) {
        if preCancelledCredentials.remove(token) != nil {
            cont.resume(returning: .declined)
            return
        }
        // Decline duplicate request IDs instead of replacing a continuation.
        guard credentialWaiters[ask.id] == nil else {
            Log.line("credential_request id=\(ask.id) rejected: duplicate in-flight id")
            cont.resume(returning: .declined)
            return
        }
        let o = ask.origin
        let hop = ProcessHop(pid: o.pid, name: o.name, path: o.path.isEmpty ? nil : o.path,
                             appName: o.appName.isEmpty ? nil : o.appName,
                             validSignature: o.validSignature,
                             signedBy: o.signedBy.isEmpty ? nil : o.signedBy)
        let req = CredentialRequest(
            id: ask.id, host: ask.host, hosts: ask.hosts, purpose: ask.purpose,
            kind: ask.kind, header: ask.header, format: ask.format,
            suggestedName: ask.suggestedName, docsURL: ask.docsURL,
            scopes: ask.scopes,
            provenance: SallyportKit.Provenance(origin: hop, chain: [], intact: o.validSignature))
        credentialWaiters[ask.id] = CredentialWaiter(token: token, continuation: cont)
        credentialTimeouts[ask.id] = Task { [weak self] in
            do { try await Task.sleep(for: .seconds(15 * 60)) }
            catch { return }
            self?.timeoutCredential(ask.id, token: token)
        }
        // One sheet at a time; later asks wait their turn instead of silently
        // replacing the visible one (their agents stay parked on the socket).
        if credentialRequest == nil {
            credentialRequest = req
        } else {
            credentialQueue.append(req)
        }
        selectedTab = .keys
        // NSApp is nil in a windowless test host; never force it, never in demo.
        if !isDemo {
            NSApp?.activate(ignoringOtherApps: true)
            openMainWindow?()            // the sheet has to have somewhere to appear
            notifier.presentCredentialRequest(req)
        }
        Log.line("credential_request id=\(req.id) host=\(req.host) bindings=\(req.hosts.joined(separator: ",")): opening add-key sheet")
    }

    /// Returns whether a key was saved, with its vault name, or whether the
    /// sheet was dismissed. Resolves the engine's in-flight ask either way and
    /// presents the next queued ask, if any.
    func respondCredential(_ req: CredentialRequest, provisioned: Bool, name: String?) {
        credentialTimeouts[req.id]?.cancel()
        credentialTimeouts[req.id] = nil
        credentialWaiters.removeValue(forKey: req.id)?
            .continuation.resume(returning: CredentialAnswer(provisioned: provisioned, name: name))
        if provisioned { secretsDidChange() }   // the Keys table must not go stale
        if !isDemo { notifier.clear(requestID: req.id) }
        advanceCredentialQueue(past: req.id)
    }

    private func timeoutCredential(_ id: String, token: UUID) {
        guard credentialWaiters[id]?.token == token else { return }
        credentialTimeouts[id] = nil
        credentialWaiters.removeValue(forKey: id)?.continuation.resume(returning: .declined)
        if !isDemo { notifier.clear(requestID: id) }
        advanceCredentialQueue(past: id)
    }

    private func cancelCredential(_ id: String, token: UUID) {
        guard let waiter = credentialWaiters[id] else {
            preCancelledCredentials.insert(token)
            return
        }
        // A duplicate/reused caller-controlled ID does not own the first ask.
        guard waiter.token == token else { return }
        credentialTimeouts[id]?.cancel()
        credentialTimeouts[id] = nil
        credentialWaiters[id] = nil
        waiter.continuation.resume(returning: .declined)
        if !isDemo { notifier.clear(requestID: id) }
        advanceCredentialQueue(past: id)
    }

    private func advanceCredentialQueue(past id: String) {
        credentialQueue.removeAll { $0.id == id }
        if credentialRequest?.id == id {
            credentialRequest = credentialQueue.isEmpty ? nil : credentialQueue.removeFirst()
        }
    }

    // MARK: Vault

    private func setVault(_ state: VaultState) {
        vault = state
        vaultUpdatedAt = Date()
    }

    func lockNow() {
        setVault(VaultState(locked: true, ttlSec: 0))   // optimistic
        guard !isDemo else { return }
        activity = ActivityLog()
        cancelPendingApprovals()
        Task { [weak self] in
            await self?.runtime.lock()
            await self?.refreshVaultFromStatus()
        }
    }

    /// Cancels pending approvals and credential requests when the vault locks.
    private func cancelPendingApprovals() {
        let cardIDs = pending.map(\.id) + Array(credentialWaiters.keys)
        for waiter in approvalWaiters.values { waiter.continuation.resume(returning: .denied) }
        approvalWaiters.removeAll()
        for t in approvalTimeouts.values { t.cancel() }
        approvalTimeouts.removeAll()
        approvalTokens.removeAll()
        preResolved.removeAll()
        for (id, waiter) in credentialWaiters {
            waiter.continuation.resume(returning: .declined)
            credentialTimeouts[id]?.cancel()
        }
        credentialWaiters.removeAll()
        credentialTimeouts.removeAll()
        preCancelledCredentials.removeAll()
        credentialQueue.removeAll()
        credentialRequest = nil
        pending.removeAll()
        if !isDemo { for id in cardIDs { notifier.clear(requestID: id) } }
        approvalPanel.sync(model: self)
    }

    func unlock() async {
        vaultUnlockError = nil
        guard !isDemo else { setVault(VaultState(locked: false, ttlSec: 21_600)); return }

        // Unlocking stored credentials requires user presence.
        let outcome = await authenticator.authenticate(
            reason: String(localized: "Unlock the Sallyport vault"))
        guard outcome == .approved else { return }

        // Open the sealed vault identity after Touch ID.
        var identity = ""
        if runtime.isGated {
            guard let gate = identityGate, gate.isSealed else {
                let msg = String(localized:
                    "The key required to unlock this vault is missing from this Mac. Recreate the vault.")
                Log.line("ERROR: gated unlock aborted: \(msg)")
                vaultUnlockError = msg
                return
            }
            var effectiveSigner = signer
            if let se = signer as? SecureEnclaveKeyCustodian,
               let ctx = authenticator.lastAuthenticatedContext {
                effectiveSigner = se.authenticated(with: ctx)
            }
            do {
                identity = try gate.unseal(using: effectiveSigner)
            } catch {
                vaultUnlockError = String(localized:
                    "Could not unseal the vault identity: \(error.localizedDescription)",
                    comment: "Vault unlock error followed by a system error description.")
                Log.line("ERROR: gated unlock failed: \(error)")
                return
            }
            guard !identity.isEmpty else {
                vaultUnlockError = String(localized: "The stored vault identity is empty.")
                return
            }
        }

        do {
            try await runtime.unlock(identity: identity)
        } catch {
            vaultUnlockError = String(localized:
                "Could not unlock the vault: \(error.localizedDescription)",
                comment: "Vault unlock error followed by a system error description.")
            Log.line("ERROR: vault unlock failed: \(error)")
            return
        }
        await refreshVaultFromStatus()
        integrityIssues = runtime.integrityIssues
        // Reload audit history after unlock.
        await hydrateActivityFromAudit()
        secretsDidChange()
    }

    /// Requires Touch ID before accepting the current vault and audit state.
    func readoptIntegrity() async {
        guard !isDemo else { integrityIssues = []; return }
        let outcome = await authenticator.authenticate(
            reason: String(localized: "Accept the current vault and audit state"))
        guard outcome == .approved else { return }
        await runtime.readoptIntegrity()
        integrityIssues = []
    }

    /// Phrase required to confirm a reset in the active app language.
    static var resetConfirmationPhrase: String {
        String(localized: "ERASE MY KEYS",
               comment: "Destructive confirmation phrase the user must type before erasing the vault.")
    }

    /// Compares the typed phrase without assuming the active language has letter case.
    static func resetConfirmationMatches(_ confirmation: String, phrase: String = resetConfirmationPhrase) -> Bool {
        confirmation.trimmingCharacters(in: .whitespacesAndNewlines)
            .localizedCaseInsensitiveCompare(phrase) == .orderedSame
    }

    /// Permanently erases the vault after validating the reset phrase and Touch ID.
    func resetVault(confirmation: String) async throws {
        guard Self.resetConfirmationMatches(confirmation) else {
            throw SetupError.reset(String(localized:
                "The confirmation phrase did not match. Sallyport did not erase any data."))
        }
        // Require Touch ID in addition to the typed phrase.
        guard await confirmConfigChange(String(localized: "Erase all Sallyport data and start over")) else {
            throw SetupError.reset(String(localized:
                "Touch ID did not confirm the reset. Sallyport did not erase any data."))
        }
        Log.line("resetVault confirmed; erasing all Sallyport data")
        try await runtime.resetVault(signer: signer, gate: identityGate)

        // Clear app state associated with the old vault.
        activity = ActivityLog()
        pending.removeAll()
        credentialRequest = nil
        vaultUnlockError = nil
        secretsDidChange()
        agentSeen = false
        UserDefaults.standard.removeObject(forKey: "sp.agentSeen")
        connection = runtime.host != nil ? .connected : .waiting
        refreshOnboardingState()
        await refreshVaultFromStatus()
    }

    /// Confirms configuration changes with a prompt naming the requested action.
    /// Demo and debug auto-approval bypass the check; release builds deny without biometrics.
    func confirmConfigChange(_ reason: String) async -> Bool {
        if isDemo || autoApprove { return true }
        return await authenticator.authenticate(reason: reason) == .approved
    }

    /// Unlocks the vault for an editing flow and reports success.
    @Sendable func unlockForEditing() async -> Bool {
        await unlock()
        return !vault.locked
    }

    /// Refreshes lock state and remaining auto-lock time.
    func refreshVaultFromStatus() async {
        guard !isDemo else { return }
        setVault(await runtime.vaultState())
    }

    // MARK: Demo / preview seeding

    func loadDemo() {
        isDemo = true
        mgmt = MgmtClient.mock(daemon: MockMgmtDaemon(seeded: true))
        setVault(VaultState(locked: false, ttlSec: 21_600))
        activity = ActivityLog()
        for row in Fixtures.activityRows { activity.append(row) }
        pending = [Fixtures.sshRestartNginx, Fixtures.httpCloudflareDNS]
        onboarding = OnboardingState(agentInstalled: true, vaultCreated: true, agentConnected: true)
        connection = .connected
        selectedTab = .approvals
    }

    private static func timestamp() -> String {
        ISO8601DateFormatter().string(from: Date())
    }
}

private extension String {
    /// Returns nil for an empty string.
    var nonEmpty: String? { isEmpty ? nil : self }
}

#if DEBUG
extension AppModel {
    /// A demo-seeded model wired to the software signer + auto-approver, for
    /// SwiftUI previews (no Secure Enclave / Touch ID needed).
    static func previewModel() -> AppModel {
        let model = AppModel(signer: SoftwareKeyCustodian(), authenticator: DevAuthenticator())
        model.loadDemo()
        return model
    }
}
#endif
