import SwiftUI
import SallyportKit

/// Menu-bar status, pending approvals, active sessions, and navigation.
struct MenuBarContentView: View {
    @Bindable var model: AppModel
    /// Hides update controls when Sparkle is unavailable.
    var updater: SoftwareUpdater?
    @Environment(\.openWindow) private var openWindow
    /// Live agent sessions for the menu (refreshed each time the popover opens).
    @State private var sessions: [SessionInfo] = []
    /// Session whose process has no visible window.
    @State private var revealMiss: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            if !model.pending.isEmpty {
                if model.pending.count > 1 {
                    HStack(spacing: Theme.Spacing.xs + 2) {
                        Image(systemName: "square.stack.3d.up.fill")
                            .font(.caption2)
                            .accessibilityHidden(true)
                        Text("\(model.pending.count) requests waiting",
                             comment: "Number of approval requests waiting in the menu bar. Configure plural variations for the request count.")
                            .fontWeight(.medium)
                        Spacer()
                        Text("newest first").font(.caption2).foregroundStyle(.tertiary)
                    }
                    .font(.caption).foregroundStyle(.secondary)
                    .padding(.horizontal, Theme.Spacing.lg)
                    .padding(.top, Theme.Spacing.sm)
                }
                ScrollView {
                    VStack(spacing: Theme.Spacing.sm) {
                        // Expand a single request and collapse a queue.
                        ForEach(model.pending) { request in
                            ApprovalRow(request: request, model: model,
                                        startsExpanded: model.pending.count == 1)
                        }
                    }
                    .padding(Theme.Spacing.md)
                }
                .frame(maxHeight: 560)
            } else {
                calmBody
            }
            Divider()
            footer
        }
        .frame(width: 480)
        .onAppear { refreshSessions() }
    }

    private func refreshSessions() {
        Task {
            if let list = try? await model.mgmt.listSessions() {
                sessions = list
            }
        }
    }

    private var header: some View {
        HStack(spacing: Theme.Spacing.sm) {
            Image(systemName: model.menuBarSymbol)
                .font(.headline)
                .foregroundStyle(model.vault.locked ? Theme.warning
                                 : (model.hasPendingApproval ? Theme.warning : Theme.accent))
            Text(verbatim: "Sallyport").font(.headline)
            Spacer()
            connectionDot
        }
        .padding(.horizontal, Theme.Spacing.lg).padding(.vertical, Theme.Spacing.md)
    }

    private var connectionDot: some View {
        HStack(spacing: 5) {
            Circle().fill(connectionColor).frame(width: 7, height: 7)
            Text(connectionLabel).font(.caption2).foregroundStyle(.secondary)
        }
        .padding(.horizontal, Theme.Spacing.sm).padding(.vertical, 3)
        .background(Theme.Surface.inset, in: Capsule())
    }

    private var calmBody: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: Theme.Spacing.sm) {
                Image(systemName: model.vault.symbol).foregroundStyle(model.vault.tint)
                if model.vault.locked {
                    Text("Vault locked").font(.callout)
                    if let err = model.vaultUnlockError {
                        Text(verbatim: err).font(.caption2).foregroundStyle(Theme.danger)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Spacer()
                    Button("Unlock") { Task { await model.unlock() } }.controlSize(.small)
                } else {
                    Text("Vault unlocked").font(.callout)
                    // Refresh the auto-lock countdown each second.
                    TimelineView(.periodic(from: .now, by: 1)) { context in
                        StatusPill(verbatim: model.vault.ttlClock(anchoredAt: model.vaultUpdatedAt, now: context.date),
                                   systemImage: "timer", tint: Theme.verified, style: .mono)
                    }
                    Spacer()
                    Button("Lock now") { model.lockNow() }.controlSize(.small)
                }
            }
            .padding(.horizontal, Theme.Spacing.lg).padding(.vertical, Theme.Spacing.md)

            if !sessions.isEmpty {
                Divider().padding(.horizontal, Theme.Spacing.md)

                HStack {
                    SectionHeader(LocalizedStringResource("Active sessions"))
                    Spacer()
                    Button("All…") { open(.sessions) }
                        .buttonStyle(.plain).font(.caption).foregroundStyle(Theme.accent)
                }
                .padding(.horizontal, Theme.Spacing.lg)
                .padding(.top, Theme.Spacing.md).padding(.bottom, Theme.Spacing.xs)

                VStack(spacing: 0) {
                    ForEach(sessions.prefix(4)) { s in
                        MenuSessionRow(session: s, missed: revealMiss == s.key) {
                            reveal(s)
                        }
                    }
                }
                .padding(.bottom, Theme.Spacing.xs)
            }

            Divider().padding(.horizontal, Theme.Spacing.md)

            SectionHeader(LocalizedStringResource("Live activity"))
                .padding(.horizontal, Theme.Spacing.lg)
                .padding(.top, Theme.Spacing.md).padding(.bottom, Theme.Spacing.sm)

            if model.activity.rows.isEmpty {
                Text("No activity yet.")
                    .font(.caption).foregroundStyle(.tertiary)
                    .padding(.horizontal, Theme.Spacing.lg).padding(.bottom, Theme.Spacing.md)
            } else {
                VStack(spacing: 0) {
                    ForEach(model.activity.rows.prefix(4)) { row in
                        MenuActivityRow(row: row)
                    }
                }
                .padding(.bottom, Theme.Spacing.sm)
            }
        }
    }

    /// Raises the nearest GUI application for a session process.
    private func reveal(_ s: SessionInfo) {
        switch AgentFocus.reveal(pid: s.pid) {
        case .exact, .appOnly:
            dismissMenuBarPopover()   // raised the terminal (exact tab when scriptable)
        case .none:
            revealMiss = s.key
            Task {
                try? await Task.sleep(for: .seconds(2))
                if revealMiss == s.key { revealMiss = nil }
            }
        }
    }

    private var footer: some View {
        VStack(spacing: 0) {
            MenuRowButton(title: LocalizedStringResource("Open activity feed…"),
                          symbol: "list.bullet.rectangle", shortcut: "L") { open(.activity) }
            MenuRowButton(title: LocalizedStringResource("Manage…"),
                          symbol: "slider.horizontal.3", shortcut: "M") { open(.keys) }
            MenuRowButton(title: LocalizedStringResource("Settings…"),
                          symbol: "gearshape") { open(.settings) }
            MenuRowButton(title: LocalizedStringResource("Integrations…"),
                          symbol: "puzzlepiece.extension") { open(.integrations) }
            // Hide onboarding after setup completes.
            if !model.onboarding.allDone {
                MenuRowButton(title: LocalizedStringResource("Setup…"),
                              symbol: "sparkles") { open(.setup) }
            }
            Divider().padding(.horizontal, Theme.Spacing.md).padding(.vertical, Theme.Spacing.xs)
            if updater?.isAvailable == true {
                MenuRowButton(title: LocalizedStringResource("Check for Updates…"),
                              symbol: "arrow.down.circle") {
                    updater?.checkForUpdates()
                    dismissMenuBarPopover()
                }
                .disabled(updater?.canCheck != true)
            }
            MenuRowButton(title: LocalizedStringResource("About Sallyport"), symbol: "info.circle") {
                open(.about)
            }
            MenuRowButton(title: LocalizedStringResource("Quit Sallyport"), symbol: "power") {
                NSApplication.shared.terminate(nil)
            }
        }
        .padding(.vertical, Theme.Spacing.xs)
    }

    private func open(_ tab: MainTab) {
        model.selectedTab = tab
        NSApp.activate(ignoringOtherApps: true)
        // Reuse the main window when it is already open.
        if !raiseExistingMainWindow() {
            openWindow(id: "main")
        }
        dismissMenuBarPopover()
    }

    /// Raises the titled main window when one exists.
    @discardableResult
    private func raiseExistingMainWindow() -> Bool {
        for window in NSApp.windows where window.canBecomeMain {
            let cls = String(describing: type(of: window))
            if cls.contains("MenuBarExtra") || cls.contains("StatusBar") { continue }
            if window.identifier == ApprovalPanelController.windowIdentifier { continue }
            window.makeKeyAndOrderFront(nil)
            return true
        }
        return false
    }

    /// Hides the menu-bar popover without destroying its backing window.
    private func dismissMenuBarPopover() {
        DispatchQueue.main.async {
            for window in NSApp.windows where window.isVisible {
                let cls = String(describing: type(of: window))
                let isMenuBarExtra = cls.contains("MenuBarExtra") || cls.contains("StatusBar")
                let isBorderlessPanel = window is NSPanel && !window.styleMask.contains(.titled)
                if isMenuBarExtra || isBorderlessPanel {
                    window.orderOut(nil)
                }
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
        case .connected: return LocalizedStringResource("Connected")
        case .connecting: return LocalizedStringResource("Starting…")
        case .waiting: return LocalizedStringResource("Setup needed")
        case .disconnected: return LocalizedStringResource("Offline")
        }
    }
}

/// Menu navigation row with a hover state and optional shortcut.
private struct MenuRowButton: View {
    let title: LocalizedStringResource
    let symbol: String
    var shortcut: Character?
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: Theme.Spacing.sm) {
                Image(systemName: symbol).frame(width: 18).foregroundStyle(.secondary)
                Text(title)
                Spacer()
                if let shortcut {
                    Text(verbatim: "⌘\(String(shortcut))").foregroundStyle(.tertiary).font(.caption)
                }
            }
            .padding(.horizontal, Theme.Spacing.sm)
            .padding(.vertical, Theme.Spacing.xs + 3)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                RoundedRectangle(cornerRadius: Theme.Radius.md, style: .continuous)
                    .fill(hovering ? Theme.Surface.hover : .clear)
            )
            .contentShape(RoundedRectangle(cornerRadius: Theme.Radius.md, style: .continuous))
        }
        .buttonStyle(.plain)
        .padding(.horizontal, Theme.Spacing.sm)
        .onHover { hovering = $0 }
        .animation(.easeOut(duration: 0.1), value: hovering)
    }
}

/// Active session row that can raise its application window.
private struct MenuSessionRow: View {
    let session: SessionInfo
    let missed: Bool
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: Theme.Spacing.sm) {
                Image(systemName: session.signed ? "checkmark.seal.fill" : "exclamationmark.shield.fill")
                    .font(.caption)
                    .foregroundStyle(session.signed ? Theme.verified : Theme.danger)
                    .frame(width: 18)
                Text(verbatim: session.displayName).font(.callout).lineLimit(1)
                if let localizedStatus {
                    StatusPill(localizedStatus, tint: statusTint)
                } else {
                    StatusPill(verbatim: session.status, tint: statusTint)
                }
                Spacer()
                if missed {
                    Text("no window (headless)").font(.caption2).foregroundStyle(.tertiary)
                } else {
                    Text("\(session.calls) calls",
                         comment: "Number of calls made during an agent session. Configure plural variations for the call count.")
                        .font(.caption2.monospacedDigit()).foregroundStyle(.tertiary)
                    Image(systemName: "macwindow.and.cursorarrow")
                        .font(.caption)
                        .foregroundStyle(hovering ? Theme.accent : Color.secondary.opacity(0.5))
                        .help("Bring the window this agent runs in to the front")
                }
            }
            .padding(.horizontal, Theme.Spacing.sm)
            .padding(.vertical, Theme.Spacing.xs + 2)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                RoundedRectangle(cornerRadius: Theme.Radius.md, style: .continuous)
                    .fill(hovering ? Theme.Surface.hover : .clear)
            )
            .contentShape(RoundedRectangle(cornerRadius: Theme.Radius.md, style: .continuous))
        }
        .buttonStyle(.plain)
        .padding(.horizontal, Theme.Spacing.sm)
        .onHover { hovering = $0 }
        .animation(.easeOut(duration: 0.1), value: hovering)
    }

    /// Keeps protocol status tokens stable while presenting known states in the user's language.
    private var localizedStatus: LocalizedStringResource? {
        switch session.status {
        case "approved":
            LocalizedStringResource("Approved", comment: "Agent session status")
        case "per-call":
            LocalizedStringResource("Per call", comment: "Agent session status: every call needs approval")
        case "observed":
            LocalizedStringResource("Observed", comment: "Agent session status: activity is recorded without approval")
        default: nil
        }
    }

    private var statusTint: Color {
        switch session.status {
        case "approved": Theme.verified
        case "per-call": Theme.warning
        default: .secondary
        }
    }
}

private struct MenuActivityRow: View {
    let row: ActivityRow
    var body: some View {
        HStack(spacing: Theme.Spacing.sm) {
            Text(verbatim: TimeFormat.clock(row.ts)).font(.caption2.monospaced()).foregroundStyle(.secondary)
                .frame(width: 54, alignment: .leading)
            Text(verbatim: row.identity.replacingOccurrences(of: "agent://", with: ""))
                .font(.caption).lineLimit(1).frame(width: 92, alignment: .leading)
            Text(verbatim: row.tool).font(.caption).foregroundStyle(.secondary).lineLimit(1)
            Spacer()
            DecisionBadge(decision: row.decision, isError: row.isError)
        }
        .padding(.horizontal, Theme.Spacing.lg).padding(.vertical, 3)
    }
}

extension AppModel {
    var menuBarSymbol: String {
        if vault.locked { return Theme.gateLocked }
        if hasPendingApproval { return Theme.gateWaiting }
        return Theme.gateCalm
    }
}

#if DEBUG && !SP_NO_PREVIEWS
#Preview("Menu bar approval (light)") {
    MenuBarContentView(model: AppModel.previewModel())
        .preferredColorScheme(.light)
}

#if !SP_NO_PREVIEWS
#Preview("Menu bar calm (dark)") {
    let model = AppModel.previewModel()
    model.pending = []
    return MenuBarContentView(model: model).preferredColorScheme(.dark)
}
#endif
#endif
