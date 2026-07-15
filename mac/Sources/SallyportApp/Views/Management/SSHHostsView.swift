import SwiftUI
import SallyportKit

// Disambiguate from any SDK `Host` visible via SwiftUI's transitive imports.
// A same-module alias wins over imported names, so `Host` resolves to ours.
typealias Host = SallyportKit.Host

@MainActor
@Observable
final class HostsViewModel {
    let mgmt: MgmtClient
    var hosts: [Host] = []
    var sshKeys: [SecretMetadata] = []   // kind ssh-ed25519, for the key picker
    var isLoading = false
    var error: String?
    var toast: Toast?

    init(mgmt: MgmtClient) { self.mgmt = mgmt }

    func load() async {
        isLoading = true; error = nil
        do {
            async let hostsCall = mgmt.listHosts()
            async let secretsCall = mgmt.listSecrets()
            hosts = try await hostsCall
            sshKeys = try await secretsCall.filter { $0.kind == "ssh-ed25519" }
        } catch {
            self.error = describe(error)
        }
        isLoading = false
    }

    func save(_ host: Host, isNew: Bool) async -> Bool {
        do {
            try await mgmt.setHost(host)
            toast = .ok(isNew ? "Added '\(host.name)'" : "Updated '\(host.name)'")
            await load()
            return true
        } catch {
            toast = .bad(describe(error)); return false
        }
    }

    func delete(_ name: String) async {
        do {
            try await mgmt.deleteHost(name: name)
            toast = .ok("Deleted '\(name)'")
            await load()
        } catch { toast = .bad(describe(error)) }
    }
}

/// SSH host inventory and key references.
struct SSHHostsView: View {
    @State private var vm: HostsViewModel
    @State private var selection = Set<Host.ID>()
    @State private var editing: Host?
    @State private var isAdding = false
    @State private var pendingDelete: Host?
    let locked: Bool
    let onUnlock: (() async -> Bool)?

    init(mgmt: MgmtClient, locked: Bool = false, onUnlock: (() async -> Bool)? = nil) {
        _vm = State(initialValue: HostsViewModel(mgmt: mgmt))
        self.locked = locked
        self.onUnlock = onUnlock
    }

    var body: some View {
        ManagementScaffold(
            title: "SSH hosts",
            subtitle: "SSH destinations and their stored key references.",
            symbol: "server.rack",
            isLoading: vm.isLoading,
            error: vm.error,
            locked: locked,
            onUnlock: onUnlock,
            onRefresh: { Task { await vm.load() } },
            toolbar: {
                Button { isAdding = true } label: { Label("Add host", systemImage: "plus") }
                    .buttonStyle(.borderedProminent)
            },
            content: { content }
        )
        .toast($vm.toast)
        // Load the encrypted inventory after unlock.
        .task(id: locked) { if !locked { await vm.load() } }
        .sheet(isPresented: $isAdding) {
            HostEditor(existing: nil, keys: vm.sshKeys, knownHosts: vm.hosts) { await vm.save($0, isNew: true) }
        }
        .sheet(item: $editing) { host in
            HostEditor(existing: host, keys: vm.sshKeys, knownHosts: vm.hosts) { await vm.save($0, isNew: false) }
        }
        .confirmationDialog(
            "Delete host \(pendingDelete?.name ?? "")?",
            isPresented: Binding(get: { pendingDelete != nil }, set: { if !$0 { pendingDelete = nil } }),
            titleVisibility: .visible
        ) {
            Button("Delete", role: .destructive) {
                if let host = pendingDelete { Task { await vm.delete(host.name) } }
                pendingDelete = nil
            }
            Button("Cancel", role: .cancel) { pendingDelete = nil }
        }
    }

    @ViewBuilder private var content: some View {
        if vm.hosts.isEmpty && !vm.isLoading {
            EmptyStateView(
                title: "No hosts yet",
                message: "Add a destination for ssh.exec.",
                symbol: "server.rack"
            ) {
                Button("Add host", systemImage: "plus") { isAdding = true }.buttonStyle(.borderedProminent)
            }
        } else {
            Table(vm.hosts, selection: $selection) {
                TableColumn("Name") { host in Text(host.name).fontWeight(.medium).textSelection(.enabled) }
                TableColumn("Address") { host in
                    Text("\(host.user)@\(host.addr):\(host.port)").font(.callout.monospaced())
                        .foregroundStyle(.secondary).textSelection(.enabled)
                }
                TableColumn("Key") { host in
                    if let key = host.key { MonoTag(text: key, tint: Theme.accent) }
                    else { Text("Not set").foregroundStyle(.tertiary) }
                }
                TableColumn("Host key") { host in
                    Text(host.hostkey)
                        .foregroundStyle(host.hostkey == "strict" ? Theme.verified : Theme.warning)
                        .font(.caption)
                }
                TableColumn("Tags") { host in
                    Text(host.tags.joined(separator: ", ")).foregroundStyle(.secondary).lineLimit(1).font(.caption)
                }
                TableColumn("") { host in
                    Menu {
                        Button("Edit…", systemImage: "pencil") { editing = host }
                        Divider()
                        Button("Delete", systemImage: "trash", role: .destructive) { pendingDelete = host }
                    } label: { Image(systemName: "ellipsis.circle") }
                    .menuStyle(.borderlessButton).fixedSize()
                    .accessibilityLabel("Actions for \(host.name)")
                }
                .width(36)
            }
            // Double-click opens the host editor; right-click mirrors the menu.
            .contextMenu(forSelectionType: Host.ID.self) { ids in
                if let host = host(for: ids) {
                    Button("Edit…", systemImage: "pencil") { editing = host }
                    Divider()
                    Button("Delete", systemImage: "trash", role: .destructive) { pendingDelete = host }
                }
            } primaryAction: { ids in
                editing = host(for: ids)
            }
        }
    }

    /// Returns the host selected by a table gesture.
    private func host(for ids: Set<Host.ID>) -> Host? {
        ids.first.flatMap { id in vm.hosts.first { $0.id == id } }
    }
}

private struct HostEditor: View {
    let existing: Host?
    let keys: [SecretMetadata]
    let knownHosts: [Host]
    let onSave: (Host) async -> Bool

    @Environment(\.dismiss) private var dismiss
    @State private var name: String
    @State private var addr: String
    @State private var user: String
    @State private var port: Int
    @State private var tags: [String]
    @State private var keyRef: String    // "" == none
    @State private var hostkey: String
    @State private var isBusy = false

    init(existing: Host?, keys: [SecretMetadata], knownHosts: [Host], onSave: @escaping (Host) async -> Bool) {
        self.existing = existing
        self.keys = keys
        self.knownHosts = knownHosts
        self.onSave = onSave
        _name = State(initialValue: existing?.name ?? "")
        _addr = State(initialValue: existing?.addr ?? "")
        _user = State(initialValue: existing?.user ?? "os")
        _port = State(initialValue: existing?.port ?? 442)
        _tags = State(initialValue: existing?.tags ?? [])
        _keyRef = State(initialValue: existing?.key ?? "")
        _hostkey = State(initialValue: existing?.hostkey ?? "accept-new")
    }

    private var isEditing: Bool { existing != nil }
    private var trimmedName: String { name.trimmingCharacters(in: .whitespaces) }
    private var nameCollision: Bool {
        !isEditing && knownHosts.contains { $0.name == trimmedName }
    }

    /// Same quiet-until-touched validation as the key form.
    @State private var touched: Set<String> = []
    @State private var didAttemptSave = false
    private func shows(_ f: String) -> Bool { didAttemptSave || touched.contains(f) }

    private var nameError: String? {
        guard shows("name") else { return nil }
        if trimmedName.isEmpty { return "Give the host a name. Agents use it as the target." }
        if nameCollision { return "A host named \(trimmedName) already exists." }
        if trimmedName.contains(" ") { return "Use letters, digits, _ or - (no spaces)." }
        return nil
    }
    private var addrError: String? {
        guard shows("addr"), addr.trimmingCharacters(in: .whitespaces).isEmpty else { return nil }
        return "Enter an IP address or DNS name."
    }
    private var userError: String? {
        guard shows("user"), user.trimmingCharacters(in: .whitespaces).isEmpty else { return nil }
        return "The SSH user to log in as."
    }
    /// Non-blocking: a host with no key can be added, but ssh.exec can't run on it.
    private var keyWarning: String? {
        keyRef.isEmpty ? "No key is selected. Agents cannot run commands on this host." : nil
    }
    private var missingFields: [String] {
        var out: [String] = []
        if trimmedName.isEmpty || nameCollision || trimmedName.contains(" ") { out.append("Name") }
        if addr.trimmingCharacters(in: .whitespaces).isEmpty { out.append("Address") }
        if user.trimmingCharacters(in: .whitespaces).isEmpty { out.append("User") }
        return out
    }
    private var canSave: Bool { missingFields.isEmpty }

    var body: some View {
        SheetScaffold(existing.map { "Edit host \($0.name)" } ?? "Add host",
                      systemImage: "server.rack", width: 480) {
            VStack(alignment: .leading, spacing: 12) {
                FormRow(label: "Name",
                        hint: "Agents target the host by this name.",
                        isRequired: !isEditing, error: nameError) {
                    TextField("ws-kz", text: $name).textFieldStyle(.roundedBorder).disabled(isEditing)
                        .invalidField(nameError != nil)
                        .onChange(of: name) { touched.insert("name") }
                }
                FormRow(label: "Address", isRequired: true, error: addrError) {
                    TextField("10.10.3.10", text: $addr).textFieldStyle(.roundedBorder)
                        .invalidField(addrError != nil)
                        .onChange(of: addr) { touched.insert("addr") }
                }
                FormRow(label: "User / port", isRequired: true, error: userError) {
                    HStack(spacing: 8) {
                        TextField("os", text: $user).textFieldStyle(.roundedBorder).frame(width: 120)
                            .invalidField(userError != nil)
                            .onChange(of: user) { touched.insert("user") }
                        Text(":").foregroundStyle(.secondary)
                        TextField("442", value: $port, format: .number).textFieldStyle(.roundedBorder).frame(width: 70)
                    }
                }
                FormRow(label: "SSH key",
                        hint: keys.isEmpty ? "Add an ssh-ed25519 key on Keys & APIs first." : "References a stored key by name.",
                        warning: keys.isEmpty ? nil : keyWarning) {
                    Picker("SSH key", selection: $keyRef) {
                        Text("None").tag("")
                        ForEach(keys) { Text($0.name).tag($0.name) }
                    }
                    .labelsHidden().fixedSize()
                }
                FormRow(label: "Host key", hint: "strict = pin; accept-new = trust on first use.") {
                    Picker("Host key policy", selection: $hostkey) {
                        Text("accept-new").tag("accept-new")
                        Text("strict").tag("strict")
                    }
                    .pickerStyle(.segmented).fixedSize()
                }
                FormRow(label: "Tags") {
                    TokenEditor(tokens: $tags, placeholder: "fleet")
                }
            }
        } footer: {
            VStack(alignment: .leading, spacing: Theme.Spacing.sm) {
                if didAttemptSave, !missingFields.isEmpty {
                    Label("Still needed: \(missingFields.joined(separator: ", "))",
                          systemImage: "exclamationmark.circle.fill")
                        .font(.caption).foregroundStyle(Theme.danger)
                }
                SheetButtons(saveTitle: isEditing ? "Save" : "Add", isBusy: isBusy, isDisabled: false,
                             onCancel: { dismiss() }, onSave: submit)
            }
        }
    }

    private func submit() {
        didAttemptSave = true
        guard canSave else { return }   // reveal the inline errors instead of a dead button
        isBusy = true
        Task {
            let host = Host(
                name: name.trimmingCharacters(in: .whitespaces),
                addr: addr.trimmingCharacters(in: .whitespaces),
                user: user.trimmingCharacters(in: .whitespaces),
                port: port, tags: tags,
                key: keyRef.isEmpty ? nil : keyRef, hostkey: hostkey)
            let ok = await onSave(host)
            isBusy = false
            if ok { dismiss() }
        }
    }
}

#if DEBUG && !SP_NO_PREVIEWS
#Preview("SSH Hosts (light)") {
    SSHHostsView(mgmt: AppModel.previewModel().mgmt)
        .frame(width: 820, height: 560).preferredColorScheme(.light)
}

#if !SP_NO_PREVIEWS
#Preview("SSH Hosts (dark)") {
    SSHHostsView(mgmt: AppModel.previewModel().mgmt)
        .frame(width: 820, height: 560).preferredColorScheme(.dark)
}
#endif
#endif
