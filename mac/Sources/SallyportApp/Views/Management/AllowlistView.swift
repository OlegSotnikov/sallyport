import SwiftUI
import AppKit
import SallyportKit

@MainActor
@Observable
final class AllowlistViewModel {
    let mgmt: MgmtClient
    var items: [AllowlistItem] = []
    var isLoading = false
    var error: String?
    var toast: Toast?

    init(mgmt: MgmtClient) { self.mgmt = mgmt }

    func load() async {
        isLoading = true; error = nil
        do { items = try await mgmt.listAllowlist() }
        catch { self.error = describe(error) }
        isLoading = false
    }

    func capture(path: String) async -> AllowlistCapturePreview? {
        do { return try await mgmt.captureAllowlist(path: path) }
        catch { toast = .bad(describe(error)); return nil }
    }

    func add(_ item: AllowlistItem) async -> Bool {
        do {
            try await mgmt.addAllowlist(item)
            toast = .ok(String(localized: "Added \(item.label)"))
            await load()
            return true
        }
        catch { toast = .bad(describe(error)); return false }
    }

    func delete(_ item: AllowlistItem) async {
        do {
            try await mgmt.deleteAllowlist(id: item.id)
            toast = .ok(String(localized: "Removed \(item.label)"))
            await load()
        }
        catch { toast = .bad(describe(error)) }
    }
}

struct AllowlistView: View {
    @State private var vm: AllowlistViewModel
    let locked: Bool
    let onUnlock: (() async -> Bool)?

    @State private var pending: AllowlistCapturePreview?
    @State private var pendingDelete: AllowlistItem?

    init(mgmt: MgmtClient, locked: Bool = false, onUnlock: (() async -> Bool)? = nil) {
        _vm = State(initialValue: AllowlistViewModel(mgmt: mgmt))
        self.locked = locked
        self.onUnlock = onUnlock
    }

    var body: some View {
        ManagementScaffold(
            title: "Agent allowlist",
            subtitle: "Allowlisted agents skip session approval. Per-call approval and vault locking still apply.",
            symbol: "person.2.badge.key.fill",
            isLoading: vm.isLoading,
            error: vm.error,
            locked: locked,
            onUnlock: onUnlock,
            onRefresh: { Task { await vm.load() } },
            toolbar: {
                Button { pickFile() } label: { Label("Add from app…", systemImage: "plus") }
                    .buttonStyle(.borderedProminent)
            },
            content: { content }
        )
        .toast($vm.toast)
        .task(id: locked) { if !locked { await vm.load() } }
        .sheet(item: $pending) { cap in
            AllowlistConfirmSheet(capture: cap) { item in await vm.add(item) }
        }
        .confirmationDialog(
            "Remove '\(pendingDelete?.label ?? "")' from the allowlist?",
            isPresented: Binding(get: { pendingDelete != nil }, set: { if !$0 { pendingDelete = nil } }),
            titleVisibility: .visible
        ) {
            Button("Remove", role: .destructive) {
                if let it = pendingDelete { Task { await vm.delete(it) } }
                pendingDelete = nil
            }
            Button("Cancel", role: .cancel) { pendingDelete = nil }
        }
    }

    @ViewBuilder private var content: some View {
        if vm.items.isEmpty && !vm.isLoading {
            EmptyStateView(
                title: "No allowlisted agents",
                message: "Add an app or executable. Match its exact code hash or signing identity. A code signature identifies software; it does not prove intent.",
                symbol: "person.2.badge.key"
            ) {
                Button("Add from app…", systemImage: "plus") { pickFile() }.buttonStyle(.borderedProminent)
            }
        } else {
            VStack(spacing: Theme.Spacing.sm) {
                ForEach(vm.items) { item in
                    AllowlistRow(item: item) { pendingDelete = item }
                }
            }
            .padding(.horizontal, Theme.Spacing.md)
        }
    }

    private func pickFile() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.application, .unixExecutable, .executable]
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.prompt = String(localized: "Choose")
        panel.message = String(localized: "Choose the app or executable to allowlist. For scripts, add the running process from Sessions.")
        guard panel.runModal() == .OK, let url = panel.url else { return }
        Task { if let cap = await vm.capture(path: url.path) { pending = cap } }
    }
}

private struct AllowlistRow: View {
    let item: AllowlistItem
    let onDelete: () -> Void

    var body: some View {
        HStack(alignment: .top, spacing: Theme.Spacing.md) {
            Image(systemName: item.kind == "publisher" ? "checkmark.seal.fill" : "number")
                .foregroundStyle(Theme.accent)
            VStack(alignment: .leading, spacing: 2) {
                Text(verbatim: item.label).font(.callout.weight(.medium))
                Text(detail).font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if item.scopeHosts.isEmpty {
                    Text("Scope: any target").font(.caption2).foregroundStyle(.tertiary)
                } else {
                    Text("Scope: \(item.scopeHosts.joined(separator: ", "))")
                        .font(.caption2).foregroundStyle(.tertiary)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            Button(role: .destructive) { onDelete() } label: { Image(systemName: "trash") }
                .buttonStyle(.borderless)
        }
        .padding(Theme.Spacing.md)
        .cardSurface(radius: Theme.Radius.md)
    }

    private var detail: LocalizedStringResource {
        if item.kind == "publisher" {
            let team = item.teamID.isEmpty ? "?" : item.teamID
            if item.bundleID.isEmpty {
                return "Publisher · Team \(team) · includes updates"
            }
            return "Publisher · Team \(team) · \(item.bundleID) · includes updates"
        }
        let h = item.cdhashes.first.map { String($0.prefix(16)) } ?? "?"
        return "Pinned version · cdhash \(h)… · updates require a new entry"
    }
}

/// Confirms the code identity, match type, and host scope for an allowlist entry.
struct AllowlistConfirmSheet: View {
    let capture: AllowlistCapturePreview
    let onAdd: (AllowlistItem) async -> Bool

    @Environment(\.dismiss) private var dismiss
    @State private var usePublisher = false
    @State private var scope = ""
    @State private var isBusy = false

    private var canPublisher: Bool { capture.publisherRequirement != nil }

    var body: some View {
        SheetScaffold("Allowlist this agent", systemImage: "person.2.badge.key") {
            VStack(alignment: .leading, spacing: Theme.Spacing.md) {
                labeled("Agent", capture.label)
                labeled("Signed", capture.signed
                    ? String(localized: "Yes: \(capture.authority)")
                    : String(localized: "No (unsigned or ad hoc)"))
                if !capture.teamID.isEmpty { labeled("Team", capture.teamID) }
                if !capture.bundleID.isEmpty { labeled("Bundle", capture.bundleID) }
                labeled("From", capture.capturedFrom)

                if !capture.signed {
                    Label("This executable has no valid code signature. Verify it before allowlisting.",
                          systemImage: "exclamationmark.triangle.fill")
                        .font(.caption).foregroundStyle(Theme.danger).fixedSize(horizontal: false, vertical: true)
                }

                Divider()
                Picker("Match", selection: $usePublisher) {
                    Text("Exact version (code hash)").tag(false)
                    Text("Publisher (includes updates)").tag(true)
                }
                .pickerStyle(.radioGroup)
                .disabled(!canPublisher && usePublisher)
                if usePublisher {
                    let team = capture.teamID.isEmpty ? String(localized: "this team") : capture.teamID
                    if capture.bundleID.isEmpty {
                        Text("Matches future builds signed by \(team). Use only if you trust future updates from that signer.")
                            .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    } else {
                        Text("Matches future builds signed by \(team) with bundle \(capture.bundleID). Use only if you trust future updates from that signer.")
                            .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    }
                } else {
                    Text("Matches only this binary. An update requires session approval or a new allowlist entry.")
                        .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
                if !canPublisher {
                    Text("Publisher matching requires a Team ID.")
                        .font(.caption2).foregroundStyle(.tertiary)
                }

                Divider()
                Label {
                    Text("The allowlist verifies code identity, not who launched it or why. Another process running as your user can invoke the same executable. This entry skips only session approval; per-call settings still apply. Calls are recorded in the signed audit log.")
                        .font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                } icon: {
                    Image(systemName: "shield.lefthalf.filled").foregroundStyle(.secondary)
                }

                FormRow(label: "Scope hosts (optional)",
                        hint: "Comma-separated hosts. Leave empty for any target. Restrict hosts to limit an allowed process.") {
                    TextField("api.example.com, 10.0.0.5", text: $scope)
                        .textFieldStyle(.roundedBorder)
                }
            }
        } footer: {
            SheetButtons(saveTitle: "Add to allowlist (Touch ID)", isBusy: isBusy, isDisabled: false,
                         onCancel: { dismiss() }, onSave: submit)
        }
    }

    private func labeled(_ key: LocalizedStringResource, _ value: String) -> some View {
        HStack(alignment: .top) {
            Text(key).font(.caption.weight(.semibold)).foregroundStyle(.secondary).frame(width: 64, alignment: .leading)
            Text(verbatim: value).font(.caption).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
        }
    }

    private func submit() {
        isBusy = true
        let hosts = scope.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        let publisher = usePublisher && canPublisher
        let item = AllowlistItem(
            label: capture.label,
            kind: publisher ? "publisher" : "cdhash",
            teamID: capture.teamID, bundleID: capture.bundleID,
            cdhashes: publisher ? [] : capture.cdhashes,
            requirement: publisher ? (capture.publisherRequirement ?? "") : "",
            scopeHosts: hosts, capturedFrom: capture.capturedFrom)
        Task {
            let ok = await onAdd(item)
            isBusy = false
            if ok { dismiss() }
        }
    }
}

extension AllowlistCapturePreview: Identifiable {
    public var id: String { capturedFrom + cdhashes.joined() }
}
