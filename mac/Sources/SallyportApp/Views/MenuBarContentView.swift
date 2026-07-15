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
                        Image(systemName: "square.stack.3d.up.fill").font(.caption2)
                        Text("\(model.pending.count) requests waiting").fontWeight(.medium)
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
            Text("Sallyport").font(.headline)
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
                        Text(err).font(.caption2).foregroundStyle(Theme.danger)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Spacer()
                    Button("Unlock") { Task { await model.unlock() } }.controlSize(.small)
                } else {
                    Text("Vault unlocked").font(.callout)
                    // Refresh the auto-lock countdown each second.
                    TimelineView(.periodic(from: .now, by: 1)) { context in
                        StatusPill(model.vault.ttlClock(anchoredAt: model.vaultUpdatedAt, now: context.date),
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
                    SectionHeader("Active sessions")
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

            SectionHeader("Live activity")
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
            MenuRowButton(title: "Open activity feed…", symbol: "list.bullet.rectangle", shortcut: "L") { open(.activity) }
            MenuRowButton(title: "Manage…", symbol: "slider.horizontal.3", shortcut: "M") { open(.keys) }
            MenuRowButton(title: "Settings…", symbol: "gearshape") { open(.settings) }
            MenuRowButton(title: "Integrations…", symbol: "puzzlepiece.extension") { open(.integrations) }
            // Hide onboarding after setup completes.
            if !model.onboarding.allDone {
                MenuRowButton(title: "Setup…", symbol: "sparkles") { open(.setup) }
            }
            Divider().padding(.horizontal, Theme.Spacing.md).padding(.vertical, Theme.Spacing.xs)
            if updater?.canCheck == true {
                MenuRowButton(title: "Check for Updates…", symbol: "arrow.down.circle") {
                    updater?.checkForUpdates()
                    dismissMenuBarPopover()
                }
            }
            MenuRowButton(title: "About Sallyport", symbol: "info.circle") {
                showAbout()
                dismissMenuBarPopover()
            }
            MenuRowButton(title: "Quit Sallyport", symbol: "power") {
                NSApplication.shared.terminate(nil)
            }
        }
        .padding(.vertical, Theme.Spacing.xs)
    }

    /// Opens the standard macOS About panel.
    private func showAbout() {
        // Credits support links; the copyright field does not.
        let centered: NSMutableParagraphStyle = { let p = NSMutableParagraphStyle(); p.alignment = .center; return p }()
        let credits = NSMutableAttributedString(
            string: "Stores credentials and uses them for configured agent actions without returning them to the agent.\n\n",
            attributes: [
                .font: NSFont.systemFont(ofSize: 11),
                .foregroundColor: NSColor.secondaryLabelColor,
                .paragraphStyle: centered,
            ])
        var authorAttributes: [NSAttributedString.Key: Any] = [
            .font: NSFont.systemFont(ofSize: 11),
            .paragraphStyle: centered,
        ]
        if let authorURL = AboutView.authorURL {
            authorAttributes[.link] = authorURL
        }
        credits.append(NSAttributedString(
            string: "Oleg Sotnikov",
            attributes: authorAttributes))
        var sourceAttributes: [NSAttributedString.Key: Any] = [
            .font: NSFont.systemFont(ofSize: 11),
            .paragraphStyle: centered,
        ]
        if let sourceURL = AboutView.sourceURL {
            sourceAttributes[.link] = sourceURL
        }
        credits.append(NSAttributedString(
            string: "\n",
            attributes: [.font: NSFont.systemFont(ofSize: 11), .paragraphStyle: centered]))
        credits.append(NSAttributedString(
            string: "Source code",
            attributes: sourceAttributes))
        let options: [NSApplication.AboutPanelOptionKey: Any] = [
            .applicationName: "Sallyport",
            .credits: credits,
            NSApplication.AboutPanelOptionKey(rawValue: "Copyright"): "© 2025-2026 AppMaster",
        ]
        NSApp.activate(ignoringOtherApps: true)
        NSApp.orderFrontStandardAboutPanel(options: options)
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
            if window.title.localizedCaseInsensitiveContains("approval") { continue }
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
    private var connectionLabel: String {
        switch model.connection {
        case .connected: return "Connected"
        case .connecting: return "Starting…"
        case .waiting: return "Setup needed"
        case .disconnected: return "Offline"
        }
    }
}

/// Menu navigation row with a hover state and optional shortcut.
private struct MenuRowButton: View {
    let title: String
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
                    Text("⌘\(String(shortcut))").foregroundStyle(.tertiary).font(.caption)
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
                Text(session.displayName).font(.callout).lineLimit(1)
                StatusPill(session.status,
                           tint: session.status == "approved" ? Theme.verified
                               : (session.status == "per-call" ? Theme.warning : .secondary))
                Spacer()
                if missed {
                    Text("no window (headless)").font(.caption2).foregroundStyle(.tertiary)
                } else {
                    Text("\(session.calls) \(session.calls == 1 ? "call" : "calls")")
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
}

private struct MenuActivityRow: View {
    let row: ActivityRow
    var body: some View {
        HStack(spacing: Theme.Spacing.sm) {
            Text(TimeFormat.clock(row.ts)).font(.caption2.monospaced()).foregroundStyle(.secondary)
                .frame(width: 54, alignment: .leading)
            Text(row.identity.replacingOccurrences(of: "agent://", with: ""))
                .font(.caption).lineLimit(1).frame(width: 92, alignment: .leading)
            Text(row.tool).font(.caption).foregroundStyle(.secondary).lineLimit(1)
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
