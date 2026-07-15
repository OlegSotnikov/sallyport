import SwiftUI
import SallyportKit

/// Lists active and ended agent processes kept during this app run.
@MainActor
@Observable
final class SessionsViewModel {
    let mgmt: MgmtClient
    var sessions: [SessionInfo] = []
    var history: [SessionInfo] = []
    var isLoading = false
    var error: String?
    var toast: Toast?

    init(mgmt: MgmtClient) { self.mgmt = mgmt }

    func load() async {
        isLoading = true; error = nil
        do {
            sessions = try await mgmt.listSessions()
            history = try await mgmt.sessionsHistory()
        }
        catch { self.error = describe(error) }
        isLoading = false
    }

    /// Refreshes without replacing the current data on failure.
    func refresh() async {
        if let s = try? await mgmt.listSessions() { sessions = s }
        if let h = try? await mgmt.sessionsHistory() { history = h }
    }

    func captureForAllowlist(pid: Int) async -> AllowlistCapturePreview? {
        do { return try await mgmt.captureAllowlist(pid: pid) }
        catch { toast = .bad(describe(error)); return nil }
    }
    func addToAllowlist(_ item: AllowlistItem) async -> Bool {
        do { try await mgmt.addAllowlist(item); toast = .ok("Allowlisted \(item.label)"); return true }
        catch { toast = .bad(describe(error)); return false }
    }

    func revoke(_ s: SessionInfo) async {
        do {
            try await mgmt.revokeSession(key: s.key)
            toast = .ok("Revoked session for \(s.displayName)")
            await load()
        } catch {
            toast = .bad(describe(error))
        }
    }
}

struct SessionsView: View {
    @State private var vm: SessionsViewModel
    @State private var pendingRevoke: SessionInfo?
    /// Code identity captured for an allowlist entry.
    @State private var pendingCapture: AllowlistCapturePreview?
    /// Session whose process has no visible window.
    @State private var revealMiss: String?
    let locked: Bool
    let onUnlock: (() async -> Bool)?

    init(mgmt: MgmtClient, locked: Bool = false, onUnlock: (() async -> Bool)? = nil) {
        _vm = State(initialValue: SessionsViewModel(mgmt: mgmt))
        self.locked = locked
        self.onUnlock = onUnlock
    }

    var body: some View {
        ManagementScaffold(
            title: "Sessions",
            subtitle: "Agent processes seen during this app run. Locking the vault ends active sessions.",
            symbol: "person.badge.shield.checkmark",
            isLoading: vm.isLoading,
            error: vm.error,
            locked: locked,
            onUnlock: onUnlock,
            onRefresh: { Task { await vm.load() } },
            toolbar: { EmptyView() },
            content: { content }
        )
        .toast($vm.toast)
        .sheet(item: $pendingCapture) { cap in
            AllowlistConfirmSheet(capture: cap) { item in await vm.addToAllowlist(item) }
        }
        .task(id: locked) { if !locked { await vm.load() } }
        .task {
            // Refresh while the tab is visible.
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(5))
                if !locked { await vm.refresh() }
            }
        }
        .confirmationDialog(
            "Revoke \(pendingRevoke?.displayName ?? "")?",
            isPresented: Binding(get: { pendingRevoke != nil }, set: { if !$0 { pendingRevoke = nil } }),
            titleVisibility: .visible
        ) {
            Button("Revoke", role: .destructive) {
                if let s = pendingRevoke { Task { await vm.revoke(s) } }
                pendingRevoke = nil
            }
            Button("Cancel", role: .cancel) { pendingRevoke = nil }
        } message: {
            Text("The current session ends immediately. The next call starts a new session.")
        }
    }

    @ViewBuilder private var content: some View {
        if vm.sessions.isEmpty && vm.history.isEmpty && !vm.isLoading {
            EmptyStateView(
                title: "No sessions yet",
                message: "Agent processes appear here after their first call.",
                symbol: "person.badge.shield.checkmark"
            ) { EmptyView() }
        } else {
            ScrollView {
                LazyVStack(alignment: .leading, spacing: Theme.Spacing.lg) {
                    if !vm.sessions.isEmpty {
                        sectionCard("Active", count: vm.sessions.count) {
                            ForEach(vm.sessions) { s in
                                sessionRow(s, live: true)
                                if s.id != vm.sessions.last?.id { Divider() }
                            }
                        }
                    }
                    if !vm.history.isEmpty {
                        sectionCard("History", count: vm.history.count) {
                            ForEach(vm.history) { s in
                                sessionRow(s, live: false)
                                if s.id != vm.history.last?.id { Divider() }
                            }
                        }
                    }
                }
                .padding(Theme.screenPadding)
            }
        }
    }

    private func sectionCard(_ title: String, count: Int, @ViewBuilder rows: @escaping () -> some View) -> some View {
        Card {
            HStack {
                SectionHeader(title)
                Spacer()
                Text("\(count)").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
            }
            rows()
        }
    }

    @ViewBuilder private func sessionRow(_ s: SessionInfo, live: Bool) -> some View {
        let row = HStack(spacing: Theme.Spacing.md) {
            Image(systemName: s.signed ? "checkmark.seal.fill" : "exclamationmark.shield.fill")
                .foregroundStyle(s.signed ? Theme.verified : Theme.danger)
                .help(s.signed ? (s.signedBy ?? "Valid code signature") : "Unsigned or not verified")
                .frame(width: 18)

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: Theme.Spacing.sm) {
                    Text(s.displayName).fontWeight(.medium).textSelection(.enabled)
                    statusPill(s.status)
                }
                Text(subtitle(s, live: live))
                    .font(.caption).foregroundStyle(.secondary)
                    .lineLimit(1).truncationMode(.middle)
            }

            Spacer()

            VStack(alignment: .trailing, spacing: 2) {
                Text("\(s.calls) \(s.calls == 1 ? "call" : "calls")")
                    .font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                Text(live ? "since \(TimeFormat.clock(s.approvedAt))" : endLine(s))
                    .font(.caption2).foregroundStyle(.tertiary)
            }

            if live {
                Button {
                    Task { if let cap = await vm.captureForAllowlist(pid: s.pid) { pendingCapture = cap } }
                } label: {
                    Image(systemName: "person.badge.key")
                }
                .buttonStyle(.borderless)
                .accessibilityLabel("Always allow \(s.displayName)")
                .help("Add this process identity to the allowlist")
                Button(role: .destructive) { pendingRevoke = s } label: {
                    Image(systemName: "xmark.circle")
                }
                .buttonStyle(.borderless)
                .accessibilityLabel("Revoke session for \(s.displayName)")
                .help("Revoke this session")
            }
        }
        .padding(.vertical, Theme.Spacing.xs)

        if live {
            Button { reveal(s) } label: { row.contentShape(Rectangle()) }
                .buttonStyle(.plain)
                .help("Show the window this agent is running in")
                .accessibilityHint("Reveals the terminal window hosting this agent")
                .overlay(alignment: .trailing) {
                    if revealMiss == s.key {
                        Text("No window for this process")
                            .font(.caption2).foregroundStyle(.secondary)
                            .padding(.horizontal, Theme.Spacing.sm)
                            .padding(.vertical, 3)
                            .background(Theme.Surface.inset, in: Capsule())
                            .padding(.trailing, 34)
                            .transition(.opacity)
                    }
                }
        } else {
            row
        }
    }

    /// Raises the nearest GUI application for the process, including a terminal tab when available.
    private func reveal(_ s: SessionInfo) {
        switch AgentFocus.reveal(pid: s.pid) {
        case .exact, .appOnly:
            revealMiss = nil
        case .none:
            withAnimation { revealMiss = s.key }
            Task {
                try? await Task.sleep(for: .seconds(2))
                if revealMiss == s.key { withAnimation { revealMiss = nil } }
            }
        }
    }

    private func statusPill(_ status: String) -> some View {
        let (label, tint): (String, Color) = switch status {
        case "approved": ("approved", Theme.verified)
        case "per-call": ("per-call", Theme.warning)
        case "observed": ("observed", .secondary)
        default: (status, .secondary)
        }
        return StatusPill(label, tint: tint)
    }

    private func subtitle(_ s: SessionInfo, live: Bool) -> String {
        var parts: [String] = []
        if let by = s.signedBy, !by.isEmpty { parts.append(by) }
        parts.append("pid \(s.pid)")
        return parts.joined(separator: " · ")
    }

    private func endLine(_ s: SessionInfo) -> String {
        let when = s.endedAt.map(TimeFormat.clock) ?? "Unknown"
        let why = s.reason ?? "ended"
        return "\(why) · \(when)"
    }
}
