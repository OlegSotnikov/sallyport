import SwiftUI
import SallyportKit

/// Main window with a sidebar and detail pane.
struct RootWindowView: View {
    @Bindable var model: AppModel
    var updater: SoftwareUpdater? = nil
    var runningLanguage: AppLanguage = AppLanguagePreference.current

    var body: some View {
        // A fixed HStack avoids sidebar collapse in a menu-bar accessory window.
        HStack(spacing: 0) {
            sidebar
            Divider()
            detail
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .frame(minWidth: 820, minHeight: 560)
        // Use an opaque title bar so content remains below it.
        .background(WindowChrome())
        // Show a prefilled editor for an agent credential request.
        .sheet(item: $model.credentialRequest) { req in
            CredentialRequestSheet(request: req, model: model)
        }
    }

    /// Scrollable section list with vault status pinned below it.
    private var sidebar: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: Theme.Spacing.md) {
                    ForEach(MainTab.Section.allCases) { section in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(section.title)
                                .font(.caption2.weight(.semibold))
                                .foregroundStyle(.secondary)
                                .padding(.horizontal, Theme.Spacing.sm + 6)
                                .padding(.bottom, 2)
                            ForEach(section.tabs) { tab in
                                SidebarRow(tab: tab,
                                           selected: model.selectedTab == tab,
                                           badge: tab == .approvals ? model.pending.count : 0)
                                { model.selectedTab = tab }
                            }
                        }
                    }
                }
                .padding(.vertical, Theme.Spacing.md)
                .padding(.horizontal, Theme.Spacing.xs)
            }
            VaultFootnote(model: model)
        }
        .frame(width: 240)
        .background(.bar)
    }

    @ViewBuilder private var detail: some View {
        VStack(spacing: 0) {
            // Keep integrity findings visible above every tab.
            if !model.integrityIssues.isEmpty {
                IntegrityBanner(model: model)
                Divider()
            }
            detailTab
        }
    }

    @ViewBuilder private var detailTab: some View {
        switch model.selectedTab {
        case .approvals: approvals
        case .activity: ActivityFeedView(model: model, locked: model.vault.locked,
                                         onUnlock: model.unlockForEditing)
        case .sessions: SessionsView(mgmt: model.mgmt, locked: model.vault.locked,
                                     onUnlock: model.unlockForEditing)
        case .keys: KeysAPIsView(model: model)
        case .hosts: SSHHostsView(mgmt: model.mgmt, locked: model.vault.locked,
                                  onUnlock: model.unlockForEditing)
        case .mcp: UpstreamsView(mgmt: model.mgmt, locked: model.vault.locked,
                                 onUnlock: model.unlockForEditing,
                                 openKeys: { model.selectedTab = .keys })
        case .agents: AllowlistView(mgmt: model.mgmt, locked: model.vault.locked,
                                    onUnlock: model.unlockForEditing)
        case .integrations: IntegrationsView()
        case .vault: VaultStatusView(model: model)
        case .settings: SettingsView(model: model, runningLanguage: runningLanguage)
        case .setup: SetupView(model: model)
        case .about: AboutView(updater: updater)
        }
    }

    @ViewBuilder private var approvals: some View {
        VStack(spacing: 0) {
            ScreenHeader(
                title: LocalizedStringResource("Approvals"),
                subtitle: approvalsSubtitle,
                symbol: "checkmark.shield"
            ) {
                if !model.pending.isEmpty {
                    StatusPill(pendingStatus, tint: Theme.warning)
                }
            }
            Divider()
            if model.pending.isEmpty {
                EmptyStateView(
                    title: LocalizedStringResource("No approvals waiting"),
                    message: LocalizedStringResource("Requests that require approval appear here and in the menu bar."),
                    symbol: "checkmark.shield")
            } else {
                ScrollView {
                    VStack(spacing: Theme.Spacing.sm) {
                        ForEach(model.pending) { request in
                            // Expand a single request and collapse a queue.
                            ApprovalRow(request: request, model: model,
                                        startsExpanded: model.pending.count == 1)
                        }
                    }
                    .frame(maxWidth: 640)
                    .frame(maxWidth: .infinity)
                    .padding(Theme.screenPadding)
                }
            }
        }
    }

    private var approvalsSubtitle: LocalizedStringResource {
        guard !model.pending.isEmpty else {
            return LocalizedStringResource("No requests are waiting.")
        }
        let count = model.pending.count
        return LocalizedStringResource(
            "\(count) requests waiting for your decision.",
            comment: "Approval queue count. Configure plural variations for the request count.")
    }

    private var pendingStatus: LocalizedStringResource {
        let count = model.pending.count
        return LocalizedStringResource(
            "\(count) pending requests",
            comment: "Compact approval queue count. Configure plural variations for the request count.")
    }
}

/// Configures an opaque title bar for the hosting window.
private struct WindowChrome: NSViewRepresentable {
    func makeNSView(context: Context) -> NSView {
        let v = NSView()
        DispatchQueue.main.async { [weak v] in
            guard let w = v?.window else { return }
            w.titlebarAppearsTransparent = false
            w.titleVisibility = .visible
            w.styleMask.insert(.titled)
            w.isMovableByWindowBackground = false
        }
        return v
    }
    func updateNSView(_ nsView: NSView, context: Context) {}
}

/// A full-width sidebar button with selected and hover states.
private struct SidebarRow: View {
    let tab: MainTab
    let selected: Bool
    let badge: Int
    let action: () -> Void

    @State private var hovered = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: Theme.Spacing.sm + 2) {
                Image(systemName: tab.symbol)
                    .frame(width: 20)
                    .foregroundStyle(selected ? Color.accentColor : .secondary)
                Text(tab.title)
                    .fontWeight(selected ? .medium : .regular)
                    .lineLimit(2)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: Theme.Spacing.xs)
                if badge > 0 {
                    Text(verbatim: "\(badge)")
                        .font(.caption2.weight(.semibold))
                        .padding(.horizontal, 6).padding(.vertical, 1)
                        .background(Capsule().fill(Theme.danger))
                        .foregroundStyle(.white)
                }
            }
            .padding(.horizontal, Theme.Spacing.sm + 2)
            .padding(.vertical, Theme.Spacing.xs + 3)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                RoundedRectangle(cornerRadius: Theme.Radius.md, style: .continuous)
                    .fill(selected ? Theme.Surface.selection
                          : (hovered ? Theme.Surface.hover : .clear))
            )
            .contentShape(RoundedRectangle(cornerRadius: Theme.Radius.md, style: .continuous))
        }
        .buttonStyle(.plain)
        .padding(.horizontal, Theme.Spacing.sm)
        .onHover { hovered = $0 }
        .animation(.easeOut(duration: 0.12), value: hovered)
        .animation(.easeOut(duration: 0.14), value: selected)
    }
}

private struct VaultFootnote: View {
    let model: AppModel
    var body: some View {
        HStack(spacing: Theme.Spacing.xs + 2) {
            Image(systemName: model.vault.symbol).foregroundStyle(model.vault.tint).font(.caption)
            TimelineView(.periodic(from: .now, by: 1)) { context in
                if model.vault.locked {
                    Text("Locked")
                        .font(.caption).foregroundStyle(.secondary)
                } else if model.vault.ttlSec > 0 {
                    let remaining = model.vault.ttlClock(anchoredAt: model.vaultUpdatedAt,
                                                         now: context.date)
                    Text(LocalizedStringResource(
                        "Unlocked · \(remaining)",
                        comment: "Vault state followed by a localized remaining-time value."))
                        .font(.caption).foregroundStyle(.secondary)
                } else {
                    Text("Unlocked · no auto-lock")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            Spacer()
            Text(model.backendDisplayName).font(.caption2).foregroundStyle(.tertiary)
        }
        .padding(.horizontal, Theme.Spacing.md).padding(.vertical, Theme.Spacing.sm)
        .background(.bar)
    }
}

#if DEBUG && !SP_NO_PREVIEWS
#Preview("Main window (light)") {
    RootWindowView(model: AppModel.previewModel())
        .frame(width: 900, height: 600)
        .preferredColorScheme(.light)
}

#if !SP_NO_PREVIEWS
#Preview("Main window (dark)") {
    RootWindowView(model: AppModel.previewModel())
        .frame(width: 900, height: 600)
        .preferredColorScheme(.dark)
}
#endif
#endif


/// Raises the existing main window or opens one when needed.
@MainActor
func raiseOrOpenMainWindow(_ openWindow: OpenWindowAction) {
    NSApp.activate(ignoringOtherApps: true)
    for window in NSApp.windows where window.canBecomeMain && window.isVisible {
        window.makeKeyAndOrderFront(nil)
        return
    }
    openWindow(id: "main")
}
