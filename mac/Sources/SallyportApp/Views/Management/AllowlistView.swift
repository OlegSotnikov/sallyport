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
                HStack(spacing: Theme.Spacing.sm) {
                    knownAgentsMenu
                    Button { pickFile() } label: { Label("Add from app…", systemImage: "plus") }
                        .buttonStyle(.borderedProminent)
                }
            },
            content: { content }
        )
        .toast($vm.toast)
        .task(id: locked) { if !locked { await vm.load() } }
        .sheet(item: $pending) { cap in
            AllowlistConfirmSheet(capture: cap, existing: vm.items) { item in await vm.add(item) }
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

    /// One-click strict entries for agents found at their standard install
    /// paths. Each choice still runs the normal capture + Touch ID flow —
    /// the registry only locates the binary and cross-checks the signer.
    @ViewBuilder private var knownAgentsMenu: some View {
        let found = KnownAgents.installed()
        if !found.isEmpty {
            Menu {
                ForEach(found, id: \.agent.id) { pair in
                    Button {
                        Task { if let cap = await vm.capture(path: pair.path) { pending = cap } }
                    } label: {
                        Text(verbatim: pair.agent.label)
                    }
                }
            } label: {
                Label("Known agents", systemImage: "sparkles")
            }
            .help("Agents detected on this Mac. Their signing identity is verified at capture time.")
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
    /// Current entries, for recognizing a pinned agent that only updated.
    var existing: [AllowlistItem] = []
    /// Kernel process name when captured from a live session ("" otherwise).
    var originName: String = ""
    let onAdd: (AllowlistItem) async -> Bool

    @Environment(\.dismiss) private var dismiss
    @State private var usePublisher: Bool
    @State private var scope: String
    @State private var isBusy = false

    init(capture: AllowlistCapturePreview, existing: [AllowlistItem] = [],
         originName: String = "", onAdd: @escaping (AllowlistItem) async -> Bool) {
        self.capture = capture
        self.existing = existing
        self.originName = originName
        self.onAdd = onAdd
        // A known publisher pre-selects the rule that survives its updates;
        // an update of a pinned entry keeps that entry's scope and stays a pin.
        let stale = capture.stalePin(in: existing)
        let known = KnownAgents.match(teamID: capture.teamID, bundleID: capture.bundleID)
        _usePublisher = State(initialValue: stale == nil && known != nil
                              && capture.publisherRequirement != nil)
        _scope = State(initialValue: stale?.scopeHosts.joined(separator: ", ") ?? "")
    }

    private var canPublisher: Bool { capture.publisherRequirement != nil }
    private var knownAgent: KnownAgent? {
        capture.signed ? KnownAgents.match(teamID: capture.teamID, bundleID: capture.bundleID) : nil
    }
    /// An existing pinned entry this capture updates (see `stalePin(in:)`).
    private var stalePin: AllowlistItem? { capture.stalePin(in: existing) }

    private var runtimeClass: RuntimeClass? {
        let path = capture.capturedFrom.hasPrefix("live:") ? "" : capture.capturedFrom
        return RuntimeClassifier.classify(path: path,
                                          name: originName.isEmpty ? capture.label : originName)
    }

    var body: some View {
        SheetScaffold(stalePin == nil ? "Allowlist this agent" : "Update pinned agent",
                      systemImage: "person.2.badge.key") {
            VStack(alignment: .leading, spacing: Theme.Spacing.md) {
                labeled("Agent", capture.label)
                labeled("Signed", capture.signed
                    ? String(localized: "Yes: \(capture.authority)")
                    : String(localized: "No (unsigned or ad hoc)"))
                if !capture.teamID.isEmpty { labeled("Team", capture.teamID) }
                if !capture.bundleID.isEmpty { labeled("Bundle", capture.bundleID) }
                labeled("From", capture.capturedFrom)

                if let known = knownAgent {
                    Label("Signature matches the known publisher of \(known.label).",
                          systemImage: "checkmark.seal.fill")
                        .font(.caption).foregroundStyle(Theme.verified)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if let stale = stalePin {
                    Label("“\(stale.label)” is already pinned with an older build of this identity. Saving replaces that pin with this build and keeps its scope.",
                          systemImage: "arrow.triangle.2.circlepath")
                        .font(.caption).foregroundStyle(Theme.accent)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if runtimeClass != nil {
                    Label("This executable is a script runtime. Its identity covers every script it runs, not one agent.",
                          systemImage: "exclamationmark.triangle.fill")
                        .font(.caption).foregroundStyle(Theme.warning)
                        .fixedSize(horizontal: false, vertical: true)
                }

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
            SheetButtons(saveTitle: stalePin == nil
                            ? "Add to allowlist (Touch ID)" : "Update pin (Touch ID)",
                         isBusy: isBusy, isDisabled: false,
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
        // Reusing a stale pin's id makes this an in-place update (the store
        // upserts by id), so one Touch ID replaces the outdated pin.
        let item = AllowlistItem(
            id: stalePin?.id ?? "",
            label: stalePin?.label ?? capture.label,
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
