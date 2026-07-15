import SwiftUI
import SallyportKit

@MainActor
@Observable
final class SettingsViewModel {
    let mgmt: MgmtClient
    var status: StatusInfo?
    var posture = PostureSettings()
    var isLoading = false
    var error: String?

    init(mgmt: MgmtClient) { self.mgmt = mgmt }

    /// Status remains available while locked. Security settings do not.
    func load(locked: Bool = false) async {
        isLoading = true; error = nil
        do {
            status = try await mgmt.status()
            if !locked { posture = try await mgmt.settings() }
        }
        catch { self.error = describe(error) }
        isLoading = false
    }

    /// Reverts an optimistic settings update if persistence fails.
    func setSessionAuth(_ v: String) async { await apply { try await self.mgmt.updateSettings(sessionAuth: v) } }
    func setRequireTouchIDForChanges(_ v: Bool) async {
        await apply { try await self.mgmt.updateSettings(requireTouchIDForChanges: v) }
    }
    func setLogBodies(_ v: Bool) async { await apply { try await self.mgmt.updateSettings(logBodies: v) } }
    func setAutoLockMinutes(_ v: Int) async { await apply { try await self.mgmt.updateSettings(autoLockMinutes: v) } }
    func setLockOnScreenLock(_ v: Bool) async { await apply { try await self.mgmt.updateSettings(lockOnScreenLock: v) } }

    private func apply(_ op: @escaping () async throws -> PostureSettings) async {
        let previous = posture
        do { posture = try await op() }
        catch { posture = previous; self.error = describe(error) }
    }
}

/// Vault, security, connection, notification, and key-storage settings.
struct SettingsView: View {
    @Bindable var model: AppModel
    @State private var vm: SettingsViewModel
    @State private var notifStatus: ApprovalNotification.Authorization?
    @State private var alertStyle: ApprovalNotification.AlertStyle?
    @State private var languageSelection: AppLanguageSelection
    @Environment(\.openURL) private var openURL

    init(model: AppModel,
         runningLanguage: AppLanguage = AppLanguagePreference.current) {
        self.model = model
        _vm = State(initialValue: SettingsViewModel(mgmt: model.mgmt))
        _languageSelection = State(initialValue: AppLanguageSelection(
            running: runningLanguage,
            selected: AppLanguagePreference.current
        ))
    }

    var body: some View {
        ManagementScaffold(
            title: "Settings",
            subtitle: "Vault, agent connections, and security settings.",
            symbol: "gearshape",
            isLoading: false,
            error: nil,
            onRefresh: { Task { await vm.load(locked: model.vault.locked) } },
            toolbar: { EmptyView() },
            content: { content }
        )
        // Reload settings after the vault unlocks.
        .task(id: model.vault.locked) { await vm.load(locked: model.vault.locked) }
    }

    @ViewBuilder private var content: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Theme.Spacing.lg) {
                applicationCard
                vaultCard
                postureCard
                connectionCard
                notificationsCard
                trustCard
            }
            .padding(Theme.screenPadding)
        }
    }

    private var applicationCard: some View {
        Card {
            SectionHeader("Application", systemImage: "globe")
            HStack(alignment: .center, spacing: Theme.Spacing.md) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Language").font(.callout.weight(.medium))
                    Text("System Default follows Language & Region in System Settings.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .frame(maxWidth: .infinity, alignment: .leading)

                Picker("Language", selection: languageBinding) {
                    Text("System Default").tag(AppLanguage.system)
                    ForEach(AppLanguage.allCases.filter { $0 != .system }) { language in
                        Text(verbatim: language.nativeName).tag(language)
                    }
                }
                .labelsHidden()
                .fixedSize(horizontal: true, vertical: false)
            }

            if languageSelection.requiresRestart {
                Divider()
                HStack(spacing: Theme.Spacing.md) {
                    Text("Restart Sallyport to apply the language change.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Spacer(minLength: Theme.Spacing.sm)
                    Button("Restart Now", systemImage: "arrow.clockwise") {
                        AppLanguagePreference.restart()
                    }
                    .buttonStyle(.borderedProminent)
                }
            }
        }
    }

    private var languageBinding: Binding<AppLanguage> {
        Binding(
            get: { languageSelection.selected },
            set: { language in
                languageSelection.selected = language
                AppLanguagePreference.set(language)
            }
        )
    }

    private var vaultCard: some View {
        Card {
            SectionHeader("Vault", systemImage: "lock.rectangle.stack")
            HStack(spacing: Theme.Spacing.md) {
                Image(systemName: model.vault.symbol).font(.title).foregroundStyle(model.vault.tint).frame(width: 36)
                VStack(alignment: .leading, spacing: 2) {
                    if model.vault.locked {
                        Text("Vault locked").font(.headline)
                    } else {
                        Text("Vault unlocked").font(.headline)
                    }
                    TimelineView(.periodic(from: .now, by: 1)) { context in
                        if model.vault.locked {
                            Text("Stored credentials are unavailable while the vault is locked.")
                                .font(.caption).foregroundStyle(.secondary)
                        } else if model.vault.ttlSec > 0 {
                            Text("Auto-locks in \(model.vault.ttlClock(anchoredAt: model.vaultUpdatedAt, now: context.date)).")
                                .font(.caption).foregroundStyle(.secondary)
                        } else {
                            Text("Auto-lock is off. Manual lock, sleep, or app exit still closes the vault.")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
                Spacer()
                if model.vault.locked {
                    Button("Unlock", systemImage: "touchid") { Task { await model.unlock() } }.buttonStyle(.borderedProminent)
                } else {
                    Button("Lock now", systemImage: "lock.fill") { model.lockNow() }
                }
            }
        }
    }

    /// Session and lock settings. Per-key approval is configured on each key.
    @ViewBuilder private var postureCard: some View {
        Card {
            SectionHeader("Approval and locking", systemImage: "slider.horizontal.3")
            if model.vault.locked {
                HStack(spacing: Theme.Spacing.md) {
                    Image(systemName: "lock.fill").foregroundStyle(.secondary)
                    Text("Security settings are encrypted. Unlock the vault to view or change them.")
                        .font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            } else {
                sessionAuthRow
                Divider()
                postureToggle(
                    title: "Require Touch ID for changes",
                    subtitle: "When on, changes to keys, hosts, and MCP servers require Touch ID. Security settings and allowlist changes always require Touch ID.",
                    isOn: requireTouchIDBinding)
                Divider()
                autoLockRow
                Divider()
                postureToggle(
                    title: "Lock when the screen locks",
                    subtitle: "When on, locking the screen also locks the vault and ends active sessions. Sleep always locks the vault.",
                    isOn: lockOnScreenLockBinding)
            }
        }
    }

    /// A zero-minute timeout disables automatic locking.
    private var autoLockRow: some View {
        HStack(alignment: .center, spacing: Theme.Spacing.md) {
            VStack(alignment: .leading, spacing: 2) {
                Text("Auto-lock the vault").font(.callout.weight(.medium))
                if vm.posture.autoLockMinutes > 0 {
                    Text("Locks \(Self.minutesLabel(vm.posture.autoLockMinutes)) after unlock. Locking ends active sessions.")
                        .font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                } else {
                    Text("Off. Manual lock, sleep, or app exit still closes the vault.")
                        .font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            if vm.posture.autoLockMinutes > 0 {
                Picker("Auto-lock after", selection: autoLockMinutesBinding) {
                    ForEach(autoLockChoices, id: \.self) { m in
                        Text(Self.minutesLabel(m)).tag(m)
                    }
                }
                .labelsHidden()
                .fixedSize()
            }
            Toggle("Auto-lock", isOn: autoLockEnabledBinding)
                .labelsHidden()
                .toggleStyle(AccentSwitchStyle())
        }
    }

    /// Includes the current value when it is not a preset.
    private var autoLockChoices: [Int] {
        var choices = [5, 15, 30, 60, 240, 480]
        let current = vm.posture.autoLockMinutes
        if current > 0, !choices.contains(current) {
            choices.append(current)
            choices.sort()
        }
        return choices
    }

    private static func minutesLabel(_ minutes: Int, locale: Locale = .autoupdatingCurrent) -> String {
        Duration.seconds(Double(minutes) * 60).formatted(
            .units(allowed: [.hours, .minutes], width: .wide, maximumUnitCount: 1)
                .locale(locale)
        )
    }

    private var autoLockEnabledBinding: Binding<Bool> {
        Binding(get: { vm.posture.autoLockMinutes > 0 },
                set: { on in Task { await vm.setAutoLockMinutes(on ? 480 : 0) } })
    }

    private var autoLockMinutesBinding: Binding<Int> {
        Binding(get: { vm.posture.autoLockMinutes },
                set: { m in Task { await vm.setAutoLockMinutes(m) } })
    }

    private var lockOnScreenLockBinding: Binding<Bool> {
        Binding(get: { vm.posture.lockOnScreenLock },
                set: { v in Task { await vm.setLockOnScreenLock(v) } })
    }

    /// Aligns settings switches in one trailing column.
    private func postureToggle(title: LocalizedStringResource,
                               subtitle: LocalizedStringResource,
                               isOn: Binding<Bool>) -> some View {
        HStack(alignment: .center, spacing: Theme.Spacing.md) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.callout.weight(.medium))
                Text(subtitle).font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            Toggle(title, isOn: isOn)
                .labelsHidden()
                // Preserve the switch tint when the window is inactive.
                .toggleStyle(AccentSwitchStyle())
        }
    }


    /// Approval required when a new agent process starts.
    private var sessionAuthRow: some View {
        HStack(alignment: .center, spacing: Theme.Spacing.md) {
            VStack(alignment: .leading, spacing: 2) {
                Text("New agent process").font(.callout.weight(.medium))
                Text(sessionAuthSubtitle)
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            Picker("New agent process", selection: sessionAuthBinding) {
                Text("Off").tag("off")
                Text("One click").tag("click")
                Text("Touch ID").tag("touchid")
            }
            .labelsHidden()
            .pickerStyle(.segmented)
            .frame(minWidth: 260)
        }
    }

    private var sessionAuthSubtitle: LocalizedStringResource {
        switch vm.posture.sessionAuth {
        case "off":
            return "New processes start without session approval. Calls are still logged, and per-call settings still apply."
        case "touchid":
            return "Each new process requires Touch ID. Approval lasts until the process exits, you revoke it, or the vault locks."
        default:
            return "Each new process requires one click. Approval lasts until the process exits, you revoke it, or the vault locks."
        }
    }

    private var sessionAuthBinding: Binding<String> {
        Binding(get: { vm.posture.sessionAuth }, set: { v in Task { await vm.setSessionAuth(v) } })
    }

    private var requireTouchIDBinding: Binding<Bool> {
        Binding(get: { vm.posture.requireTouchIDForChanges },
                set: { v in Task { await vm.setRequireTouchIDForChanges(v) } })
    }

    private var connectionCard: some View {
        Card {
            SectionHeader("Agent socket", systemImage: "bolt.horizontal.circle")
            KeyValueRow("Status") {
                HStack(spacing: Theme.Spacing.xs + 2) {
                    Circle().fill(connectionColor).frame(width: 8, height: 8)
                    Text(connectionLabel)
                }
            }
            KeyValueRow("Socket") {
                    Text(verbatim: model.socketPath).font(Theme.Typography.monoSmall).textSelection(.enabled).foregroundStyle(.secondary)
            }
            if let core = vm.status?.daemon {
                KeyValueRow("Version") { Text(verbatim: core.version).font(Theme.Typography.monoSmall).foregroundStyle(.secondary) }
                KeyValueRow("Home") { Text(verbatim: core.home).font(Theme.Typography.monoSmall).textSelection(.enabled).foregroundStyle(.secondary) }
            }
            if let error = vm.error {
                Label {
                    Text(verbatim: error)
                } icon: {
                    Image(systemName: "exclamationmark.triangle.fill")
                }
                    .font(.caption).foregroundStyle(Theme.warning)
            }
            if model.autoApprove {
                Label("Development auto-approval is on. Approval decisions are not signed; audit rows use a separate signer.",
                      systemImage: "exclamationmark.triangle.fill")
                    .font(.caption).foregroundStyle(Theme.warning)
            }
        }
    }

    /// Notification authorization and delivery style for approval requests.
    private var notificationsCard: some View {
        Card {
            SectionHeader("Notifications", systemImage: "bell.badge")
            HStack(spacing: Theme.Spacing.md) {
                Image(systemName: notifOn ? "bell.badge.fill" : "bell.slash")
                    .font(.title).foregroundStyle(notifOn ? Theme.verified : Theme.warning).frame(width: 36)
                VStack(alignment: .leading, spacing: 2) {
                    if notifOn {
                        Text("Approval notifications on").font(.headline)
                        Text("Notifications include Approve and Deny actions.")
                            .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    } else {
                        Text("Notifications off").font(.headline)
                        Text("Approval requests use the in-app panel instead.")
                            .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    }
                }
                Spacer()
                if notifOn {
                    Button("Test", systemImage: "paperplane") { model.sendTestNotification() }
                } else {
                    // After denial, macOS requires the user to change this in System Settings.
                    if notifStatus == .denied {
                        Button("Open Settings", systemImage: "bell") {
                            if let url = Self.notificationsSettingsURL { openURL(url) }
                        }
                    } else {
                        Button("Enable", systemImage: "bell") {
                            Task { _ = await model.requestNotificationPermission(); await loadNotifStatus() }
                        }
                    }
                }
            }
            // Banners disappear automatically. Alerts remain until dismissed.
            if notifOn, let alertStyle {
                Divider().padding(.vertical, 2)
                if ApprovalNotification.willPersist(alertStyle) {
                    Label("Alerts stay visible until dismissed.",
                          systemImage: "checkmark.seal.fill")
                        .font(.caption).foregroundStyle(Theme.verified)
                } else {
                    HStack(alignment: .top, spacing: Theme.Spacing.md) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundStyle(Theme.warning).frame(width: 20)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Notifications use banners").font(.callout.weight(.medium))
                            Text("Banners disappear automatically. Select Alerts for Sallyport in System Settings to keep approvals visible.")
                                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                        }
                        Spacer()
                        Button("Open notification settings", systemImage: "gearshape") {
                            if let url = Self.notificationsSettingsURL { openURL(url) }
                        }
                        .buttonStyle(.borderedProminent)
                    }
                }
            }
        }
        .task { await loadNotifStatus() }
    }

    /// Opens the Notifications pane in System Settings.
    private static let notificationsSettingsURL = URL(
        string: "x-apple.systempreferences:com.apple.Notifications-Settings.extension")

    private var notifOn: Bool {
        switch notifStatus {
        case .authorized, .provisional, .ephemeral: return true
        case .denied, .notDetermined, .none: return false
        }
    }

    private func loadNotifStatus() async {
        notifStatus = await model.notificationAuthorization()
        alertStyle = await model.notificationAlertStyle()
    }

    private var trustCard: some View {
        Card {
            SectionHeader("Key storage", systemImage: "checkmark.seal")
            HStack(spacing: Theme.Spacing.sm) {
                Image(systemName: model.backend == .secureEnclave ? "cpu.fill" : "desktopcomputer")
                    .foregroundStyle(model.backend == .secureEnclave ? Theme.verified : Theme.warning)
                if model.backend == .secureEnclave {
                    Text("Secure Enclave").fontWeight(.medium)
                } else {
                    Text("Software key").fontWeight(.medium)
                }
                Spacer()
                if model.backend == .secureEnclave {
                    StatusPill("Hardware", tint: Theme.verified)
                } else {
                    StatusPill("Software", tint: Theme.warning)
                }
            }
            if model.backend == .software {
                Text("Development software keys are in use. Release builds on Apple Silicon use Secure Enclave and Touch ID.")
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
        }
    }


    private var connectionColor: Color {
        switch model.connection {
        case .connected: return Theme.verified
        case .connecting: return Theme.warning
        case .waiting: return Theme.danger
        case .disconnected: return .secondary
        }
    }
    private var connectionLabel: LocalizedStringResource {
        switch model.connection {
        case .connected: return "Connected"
        case .connecting: return "Starting…"
        case .waiting: return "Setup needed"
        case .disconnected: return model.isDemo ? "Demo" : "Offline"
        }
    }
}

#if DEBUG && !SP_NO_PREVIEWS
#Preview("Settings (light)") {
    SettingsView(model: AppModel.previewModel())
        .frame(width: 820, height: 560)
        .preferredColorScheme(.light)
}

#if !SP_NO_PREVIEWS
#Preview("Settings (dark)") {
    SettingsView(model: AppModel.previewModel())
        .frame(width: 820, height: 560)
        .preferredColorScheme(.dark)
}
#endif
#endif
