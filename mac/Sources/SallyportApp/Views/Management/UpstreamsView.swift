import SwiftUI
import SallyportKit

@MainActor
@Observable
final class UpstreamsViewModel {
    let mgmt: MgmtClient
    var upstreams: [Upstream] = []
    var secrets: [SecretMetadata] = []
    var isLoading = false
    var error: String?
    var toast: Toast?

    init(mgmt: MgmtClient) { self.mgmt = mgmt }

    func load() async {
        isLoading = true; error = nil
        do {
            async let upstreamsCall = mgmt.listUpstreams()
            async let secretsCall = mgmt.listSecrets()
            upstreams = try await upstreamsCall
            secrets = try await secretsCall
        } catch {
            self.error = describe(error)
        }
        isLoading = false
    }

    func save(_ upstream: Upstream, isNew: Bool) async -> Bool {
        do {
            try await mgmt.setUpstream(upstream)
            toast = .ok(isNew
                ? String(localized: "Added \(upstream.name)")
                : String(localized: "Updated \(upstream.name)"))
            await load()
            return true
        } catch {
            toast = .bad(describe(error)); return false
        }
    }

    func delete(_ name: String) async {
        do {
            try await mgmt.deleteUpstream(name: name)
            toast = .ok(String(localized: "Deleted \(name)"))
            await load()
        } catch { toast = .bad(describe(error)) }
    }

    /// Opens browser sign-in with the management client's OAuth timeout.
    func connect(_ name: String) async -> Bool {
        do {
            _ = try await mgmt.authorizeUpstream(name: name)
            toast = .ok(String(localized: "Signed in to \(name)"))
            await load()
            return true
        } catch {
            toast = .bad(describe(error))
            await load()
            return false
        }
    }

    func disconnect(_ name: String) async {
        do {
            try await mgmt.disconnectUpstream(name: name)
            toast = .ok(String(localized: "Signed out of \(name)"))
            await load()
        } catch { toast = .bad(describe(error)) }
    }

    /// Finds the key bound to an endpoint by exact host or wildcard suffix.
    func boundKeyName(forURL raw: String) -> String? {
        guard let host = URL(string: raw.trimmingCharacters(in: .whitespaces))?.host?.lowercased(),
              !host.isEmpty else { return nil }
        return secrets.first { meta in
            meta.bind.contains { pattern in
                let p = pattern.lowercased()
                if p == host { return true }
                if p.hasPrefix("*."), host.hasSuffix(String(p.dropFirst())) { return true }
                return false
            }
        }?.name
    }
}

/// Configures local stdio and remote HTTP MCP servers.
struct UpstreamsView: View {
    @State private var vm: UpstreamsViewModel
    @State private var selection = Set<Upstream.ID>()
    @State private var editing: Upstream?
    @State private var isAdding = false
    @State private var pendingDelete: Upstream?
    let locked: Bool
    let onUnlock: (() async -> Bool)?
    /// Opens key settings when a remote endpoint has no bound key.
    let openKeys: (() -> Void)?

    init(mgmt: MgmtClient, locked: Bool = false, onUnlock: (() async -> Bool)? = nil,
         openKeys: (() -> Void)? = nil) {
        _vm = State(initialValue: UpstreamsViewModel(mgmt: mgmt))
        self.locked = locked
        self.onUnlock = onUnlock
        self.openKeys = openKeys
    }

    var body: some View {
        ManagementScaffold(
            title: "MCP servers",
            subtitle: "Local and remote MCP servers and their credential bindings.",
            symbol: "puzzlepiece.extension.fill",
            isLoading: vm.isLoading,
            error: vm.error,
            locked: locked,
            onUnlock: onUnlock,
            onRefresh: { Task { await vm.load() } },
            toolbar: {
                Button { isAdding = true } label: { Label("Add server", systemImage: "plus") }
                    .buttonStyle(.borderedProminent)
            },
            content: { content }
        )
        .toast($vm.toast)
        // The inventory is available only while the vault is unlocked.
        .task(id: locked) { if !locked { await vm.load() } }
        .sheet(isPresented: $isAdding) {
            UpstreamEditor(existing: nil, secrets: vm.secrets, known: vm.upstreams,
                           openKeys: openKeys,
                           connect: { await vm.connect($0) },
                           disconnect: { await vm.disconnect($0) },
                           live: { name in vm.upstreams.first { $0.name == name } }) {
                await vm.save($0, isNew: true)
            }
        }
        .sheet(item: $editing) { upstream in
            UpstreamEditor(existing: upstream, secrets: vm.secrets, known: vm.upstreams,
                           openKeys: openKeys,
                           connect: { await vm.connect($0) },
                           disconnect: { await vm.disconnect($0) },
                           live: { name in vm.upstreams.first { $0.name == name } }) {
                await vm.save($0, isNew: false)
            }
        }
        .confirmationDialog(
            "Delete MCP server \(pendingDelete?.name ?? "")?",
            isPresented: Binding(get: { pendingDelete != nil }, set: { if !$0 { pendingDelete = nil } }),
            titleVisibility: .visible
        ) {
            Button("Delete", role: .destructive) {
                if let u = pendingDelete { Task { await vm.delete(u.name) } }
                pendingDelete = nil
            }
            Button("Cancel", role: .cancel) { pendingDelete = nil }
        }
    }

    @ViewBuilder private var content: some View {
        if vm.upstreams.isEmpty && !vm.isLoading {
            EmptyStateView(
                title: "No MCP servers yet",
                message: "Add a local stdio server or a remote HTTP endpoint.",
                symbol: "puzzlepiece.extension"
            ) {
                Button("Add server", systemImage: "plus") { isAdding = true }.buttonStyle(.borderedProminent)
            }
        } else {
            Table(vm.upstreams, selection: $selection) {
                TableColumn("Name") { u in
                    HStack(spacing: 6) {
                        Image(systemName: u.transport == "http" ? "globe" : "terminal")
                            .font(.caption).foregroundStyle(.secondary)
                            .help(u.transport == "http"
                                  ? String(localized: "Remote (streamable HTTP)")
                                  : String(localized: "Local (stdio)"))
                        Text(verbatim: u.name).fontWeight(.medium).textSelection(.enabled)
                        if !u.enabled { StatusPill("Off", tint: .secondary) }
                    }
                }
                TableColumn("Runs") { u in
                    Text(verbatim: u.transport == "http" ? u.url : ([u.command] + u.args).joined(separator: " "))
                        .font(.callout.monospaced()).foregroundStyle(.secondary)
                        .lineLimit(1).truncationMode(.middle).textSelection(.enabled)
                }
                TableColumn("Key") { u in
                    if u.transport == "http", u.auth == "oauth" {
                        if u.oauthConnected {
                            HStack(spacing: 4) {
                                Image(systemName: "checkmark.seal.fill")
                                    .font(.caption).foregroundStyle(Theme.verified)
                                Text("Signed in").font(.caption).foregroundStyle(.secondary)
                            }
                        } else {
                            Text("Not signed in").font(.caption).foregroundStyle(Theme.warning)
                                .help("Open the editor and click Connect")
                        }
                    } else if u.transport == "http" {
                        if let key = vm.boundKeyName(forURL: u.url) {
                            MonoTag(text: key, tint: Theme.accent)
                        } else {
                            Text("Unauthenticated").font(.caption).foregroundStyle(Theme.warning)
                                .help("Bind a key to this endpoint's host in Keys and APIs")
                        }
                    } else if u.keys.isEmpty {
                        Text("None").foregroundStyle(.tertiary)
                    } else {
                        HStack(spacing: 4) {
                            ForEach(u.keys, id: \.self) { b in
                                MonoTag(text: "\(b.secret)→\(b.envVar)", tint: Theme.accent)
                            }
                        }
                    }
                }
                TableColumn("Tools") { u in
                    HStack(spacing: 4) {
                        Text(verbatim: "\(u.name).*").font(.caption.monospaced()).foregroundStyle(.secondary)
                        if u.confirm == "touchid" {
                            StatusPill("Touch ID per call", tint: Theme.warning)
                        } else if u.confirm == "click" {
                            StatusPill("Confirm per call", tint: Theme.warning)
                        }
                    }
                }
                TableColumn("") { u in
                    Menu {
                        Button("Edit…", systemImage: "pencil") { editing = u }
                        if u.transport == "http", u.auth == "oauth" {
                            Divider()
                            if u.oauthConnected {
                                Button("Sign in again", systemImage: "arrow.clockwise") {
                                    Task { await vm.connect(u.name) }
                                }
                                Button("Sign out", systemImage: "rectangle.portrait.and.arrow.right") {
                                    Task { await vm.disconnect(u.name) }
                                }
                            } else {
                                Button("Connect…", systemImage: "person.badge.key") {
                                    Task { await vm.connect(u.name) }
                                }
                            }
                        }
                        Divider()
                        Button("Delete", systemImage: "trash", role: .destructive) { pendingDelete = u }
                    } label: { Image(systemName: "ellipsis.circle") }
                    .menuStyle(.borderlessButton).fixedSize()
                    .accessibilityLabel("Actions for \(u.name)")
                }
                .width(36)
            }
            .contextMenu(forSelectionType: Upstream.ID.self) { ids in
                if let u = upstream(for: ids) {
                    Button("Edit…", systemImage: "pencil") { editing = u }
                    Divider()
                    Button("Delete", systemImage: "trash", role: .destructive) { pendingDelete = u }
                }
            } primaryAction: { ids in
                editing = upstream(for: ids)
            }
        }
    }

    private func upstream(for ids: Set<Upstream.ID>) -> Upstream? {
        ids.first.flatMap { id in vm.upstreams.first { $0.id == id } }
    }
}

private struct UpstreamEditor: View {
    let existing: Upstream?
    let secrets: [SecretMetadata]
    let known: [Upstream]
    let openKeys: (() -> Void)?
    let connect: (String) async -> Bool
    let disconnect: (String) async -> Void
    /// Returns the current saved row, including sign-in status.
    let live: (String) -> Upstream?
    let onSave: (Upstream) async -> Bool

    @Environment(\.dismiss) private var dismiss
    @State private var auth: String
    @State private var confirm: String
    @State private var isConnecting = false
    @State private var transport: String
    @State private var name: String
    @State private var command: String
    @State private var argsLine: String
    @State private var envLines: String
    @State private var keys: [UpstreamKeyBinding]
    @State private var urlString: String
    @State private var enabled: Bool
    @State private var isBusy = false

    init(existing: Upstream?, secrets: [SecretMetadata], known: [Upstream],
         openKeys: (() -> Void)?,
         connect: @escaping (String) async -> Bool,
         disconnect: @escaping (String) async -> Void,
         live: @escaping (String) -> Upstream?,
         onSave: @escaping (Upstream) async -> Bool) {
        self.existing = existing
        self.secrets = secrets
        self.known = known
        self.openKeys = openKeys
        self.connect = connect
        self.disconnect = disconnect
        self.live = live
        self.onSave = onSave
        _auth = State(initialValue: existing?.auth ?? "apikey")
        _confirm = State(initialValue: existing?.confirm ?? "")
        _transport = State(initialValue: existing?.transport ?? "stdio")
        _name = State(initialValue: existing?.name ?? "")
        _command = State(initialValue: existing?.command ?? "")
        _argsLine = State(initialValue: (existing?.args ?? []).joined(separator: " "))
        _envLines = State(initialValue: (existing?.env ?? [:])
            .sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }.joined(separator: "\n"))
        _keys = State(initialValue: existing?.keys ?? [])
        _urlString = State(initialValue: existing?.url ?? "")
        _enabled = State(initialValue: existing?.enabled ?? true)
    }

    private var isEditing: Bool { existing != nil }
    private var isRemote: Bool { transport == "http" }
    private var isOAuth: Bool { isRemote && auth == "oauth" }
    private var transportHint: LocalizedStringResource {
        isRemote
            ? LocalizedStringResource("A hosted MCP endpoint called over HTTPS.")
            : LocalizedStringResource("A local process launched and supervised by Sallyport.")
    }
    private var authenticationHint: LocalizedStringResource {
        isOAuth
            ? LocalizedStringResource("Signs in through the browser and stores OAuth tokens in the vault. Tool-call responses are scrubbed; upstream catalog metadata is not.")
            : LocalizedStringResource("Attaches the key bound to this endpoint's host to each request.")
    }
    private var localKeysHint: LocalizedStringResource {
        secrets.isEmpty
            ? LocalizedStringResource("Add the server's API key on Keys & APIs first, then bind it here.")
            : LocalizedStringResource("Selected keys are passed to the local server as environment variables.")
    }
    /// The saved row is unavailable until the server is created.
    private var saved: Upstream? { existing.flatMap { live($0.name) } ?? existing }
    private var trimmedName: String { name.trimmingCharacters(in: .whitespaces).lowercased() }
    private var trimmedURL: String { urlString.trimmingCharacters(in: .whitespaces) }
    private static let reserved: Set<String> = ["http", "ssh", "sallyport"]

    @State private var touched: Set<String> = []
    @State private var didAttemptSave = false
    private func shows(_ f: String) -> Bool { didAttemptSave || touched.contains(f) }

    private var nameError: String? {
        guard shows("name") else { return nil }
        if trimmedName.isEmpty { return String(localized: "Name the server. Its tools appear as name.<tool>.") }
        if !isEditing, known.contains(where: { $0.name == trimmedName }) {
            return String(localized: "An MCP server named \(trimmedName) already exists.")
        }
        if Self.reserved.contains(trimmedName) {
            return String(localized: "\(trimmedName) is reserved for a built-in channel.")
        }
        if !trimmedName.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "_" || $0 == "-" }) {
            return String(localized: "Use letters, digits, _ or - (no spaces or dots).")
        }
        return nil
    }
    private var commandError: String? {
        guard !isRemote, shows("command"), command.trimmingCharacters(in: .whitespaces).isEmpty else { return nil }
        return String(localized: "Enter an executable path or a name resolved through PATH.")
    }
    private var urlValid: Bool { RemoteURLRule.isValid(trimmedURL) }
    private var urlError: String? {
        guard isRemote, shows("url") else { return nil }
        if trimmedURL.isEmpty {
            return String(localized: "Enter the server’s MCP endpoint, for example https://mcp.linear.app/mcp.")
        }
        if !urlValid {
            return String(localized: "Use https://. Plain http:// is allowed only for localhost.")
        }
        return nil
    }

    /// The key currently bound to the remote endpoint's host.
    private var boundKey: SecretMetadata? {
        guard isRemote, let host = URL(string: trimmedURL)?.host?.lowercased(), !host.isEmpty else { return nil }
        return secrets.first { meta in
            meta.bind.contains { pattern in
                let p = pattern.lowercased()
                if p == host { return true }
                if p.hasPrefix("*."), host.hasSuffix(String(p.dropFirst())) { return true }
                return false
            }
        }
    }

    private var missingFields: [String] {
        var out: [String] = []
        if trimmedName.isEmpty || Self.reserved.contains(trimmedName)
            || !trimmedName.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "_" || $0 == "-" })
            || (!isEditing && known.contains { $0.name == trimmedName }) {
            out.append(String(localized: "Name"))
        }
        if isRemote {
            if !urlValid { out.append(String(localized: "Endpoint URL")) }
        } else if command.trimmingCharacters(in: .whitespaces).isEmpty {
            out.append(String(localized: "Command"))
        }
        return out
    }
    private var canSave: Bool { missingFields.isEmpty }
    private var missingFieldsList: String {
        missingFields.formatted(
            .list(type: .and, width: .standard).locale(.autoupdatingCurrent)
        )
    }

    var body: some View {
        SheetScaffold(existing.map { "Edit MCP server \($0.name)" } ?? "Add MCP server",
                      systemImage: "puzzlepiece.extension", width: 520) {
            VStack(alignment: .leading, spacing: 12) {
                FormRow(label: "Where", hint: transportHint) {
                    Picker("Transport", selection: $transport) {
                        Text("Local (stdio)").tag("stdio")
                        Text("Remote (HTTP)").tag("http")
                    }
                    .pickerStyle(.segmented)
                    .frame(minWidth: 250)
                    .disabled(isEditing)   // the transport is the entry's identity
                }
                FormRow(label: "Name",
                        hint: "Tools are exposed to agents as <name>.<tool>.",
                        isRequired: !isEditing, error: nameError) {
                    TextField(isRemote ? "linear" : "github", text: $name)
                        .textFieldStyle(.roundedBorder).disabled(isEditing)
                        .invalidField(nameError != nil)
                        .onChange(of: name) { touched.insert("name") }
                }

                if isRemote {
                    FormRow(label: "Endpoint", isRequired: true, error: urlError) {
                        TextField("https://mcp.linear.app/mcp", text: $urlString)
                            .textFieldStyle(.roundedBorder).font(.callout.monospaced())
                            .invalidField(urlError != nil)
                            .onChange(of: urlString) { touched.insert("url") }
                    }
                    FormRow(label: "Authentication", hint: authenticationHint) {
                        Picker("Authentication", selection: $auth) {
                            Text("API key").tag("apikey")
                            Text("OAuth (sign in)").tag("oauth")
                        }
                        .pickerStyle(.segmented)
                        .frame(minWidth: 250)
                    }

                    if isOAuth {
                        FormRow(label: "Account", hint: isEditing
                                ? nil
                                : "Add the server before signing in.") {
                            HStack(spacing: Theme.Spacing.sm) {
                                if let s = saved, s.oauthConnected {
                                    Image(systemName: "checkmark.seal.fill").foregroundStyle(Theme.verified)
                                    VStack(alignment: .leading, spacing: 1) {
                                        if s.oauthAccount.isEmpty {
                                            Text("Signed in").font(.caption)
                                        } else {
                                            Text("Signed in: \(s.oauthAccount)").font(.caption)
                                        }
                                        if !s.oauthExpiry.isEmpty {
                                            Text("Token renews automatically")
                                                .font(.caption2).foregroundStyle(.tertiary)
                                        }
                                    }
                                    Spacer()
                                    Button("Sign out") {
                                        Task { await disconnect(s.name) }
                                    }
                                    .controlSize(.small)
                                } else if isEditing, let s = saved {
                                    Image(systemName: "person.badge.key").foregroundStyle(Theme.warning)
                                    Text("Not signed in. The server's tools remain hidden until you connect.")
                                        .font(.caption).foregroundStyle(.secondary)
                                    Spacer()
                                    Button {
                                        isConnecting = true
                                        Task { _ = await connect(s.name); isConnecting = false }
                                    } label: {
                                        if isConnecting {
                                            Text("Waiting for browser…")
                                        } else {
                                            Text("Connect…")
                                        }
                                    }
                                    .buttonStyle(.borderedProminent).controlSize(.small)
                                    .disabled(isConnecting || !urlValid)
                                } else {
                                    Text("Save this server, then click Connect to sign in.")
                                        .font(.caption).foregroundStyle(.tertiary)
                                }
                            }
                        }
                    } else {
                        FormRow(label: "Key",
                                hint: "The key bound to this endpoint's host is attached to each request. It is not stored with the server entry.") {
                            HStack(spacing: Theme.Spacing.sm) {
                                if let key = boundKey {
                                    Image(systemName: "checkmark.seal.fill").foregroundStyle(Theme.verified)
                                    Text("\(key.name) is bound to this host and will be attached.")
                                        .font(.caption)
                                } else if urlValid {
                                    Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(Theme.warning)
                                    Text("No key is bound. Calls are unauthenticated.")
                                        .font(.caption).foregroundStyle(.secondary)
                                    if openKeys != nil {
                                        Button("Bind a key…") { openKeys?(); dismiss() }
                                            .controlSize(.small)
                                    }
                                } else {
                                    Text("Enter the endpoint to see which key applies.")
                                        .font(.caption).foregroundStyle(.tertiary)
                                }
                            }
                        }
                    }
                } else {
                    FormRow(label: "Command", isRequired: true, error: commandError) {
                        TextField("npx", text: $command).textFieldStyle(.roundedBorder)
                            .invalidField(commandError != nil)
                            .onChange(of: command) { touched.insert("command") }
                    }
                    FormRow(label: "Arguments", hint: "Space-separated.") {
                        TextField("-y @modelcontextprotocol/server-github", text: $argsLine)
                            .textFieldStyle(.roundedBorder).font(.callout.monospaced())
                    }
                    FormRow(label: "Keys", hint: localKeysHint) {
                        VStack(alignment: .leading, spacing: 6) {
                            ForEach(keys.indices, id: \.self) { i in
                                HStack(spacing: 8) {
                                    Picker("Secret", selection: $keys[i].secret) {
                                        ForEach(secrets) { Text(verbatim: $0.name).tag($0.name) }
                                    }
                                    .labelsHidden().frame(width: 160)
                                    Image(systemName: "arrow.right").font(.caption2).foregroundStyle(.secondary)
                                    TextField("GITHUB_TOKEN", text: $keys[i].envVar)
                                        .textFieldStyle(.roundedBorder).font(.callout.monospaced())
                                    Button { keys.remove(at: i) } label: { Image(systemName: "minus.circle") }
                                        .buttonStyle(.borderless)
                                }
                            }
                            Button {
                                keys.append(UpstreamKeyBinding(secret: secrets.first?.name ?? "", envVar: ""))
                            } label: { Label("Bind a key", systemImage: "plus") }
                            .buttonStyle(.borderless)
                            .disabled(secrets.isEmpty)

                            if !keys.isEmpty {
                                Label {
                                    Text("Local MCP servers receive bound credentials and inherit Sallyport’s process environment. Non-per-call servers start during vault unlock and may keep those values until lock, reconfiguration, or exit. Treat the server and its dependencies as trusted code.")
                                        .font(.caption).foregroundStyle(.secondary)
                                        .fixedSize(horizontal: false, vertical: true)
                                } icon: {
                                    Image(systemName: "eye.trianglebadge.exclamationmark")
                                        .foregroundStyle(Theme.warning)
                                }
                                .padding(.top, 2)
                            }
                        }
                    }
                    FormRow(label: "Environment", hint: "Additional non-secret variables, one VAR=value per line.") {
                        TextField("LOG_LEVEL=info", text: $envLines, axis: .vertical)
                            .textFieldStyle(.roundedBorder).font(.callout.monospaced())
                            .lineLimit(1...4)
                    }
                }

                FormRow(label: "Approval per call",
                        hint: "Require approval for each tool invocation. Initialization and tool discovery do not show a per-call prompt.") {
                    Picker("Approval per call", selection: $confirm) {
                        Text("Off").tag("")
                        Text("One click").tag("click")
                        Text("Touch ID").tag("touchid")
                    }
                    .pickerStyle(.segmented)
                    .frame(minWidth: 250)
                }
                FormRow(label: "Enabled", hint: "Off keeps the config but exposes no tools.") {
                    Toggle("Enabled", isOn: $enabled).labelsHidden().toggleStyle(AccentSwitchStyle())
                }
            }
        } footer: {
            VStack(alignment: .leading, spacing: Theme.Spacing.sm) {
                if didAttemptSave, !missingFields.isEmpty {
                    Label("Still needed: \(missingFieldsList)",
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
        guard canSave else { return }
        isBusy = true
        Task {
            var env: [String: String] = [:]
            for line in envLines.split(separator: "\n") {
                let parts = line.split(separator: "=", maxSplits: 1)
                guard parts.count == 2 else { continue }
                env[String(parts[0]).trimmingCharacters(in: .whitespaces)] =
                    String(parts[1]).trimmingCharacters(in: .whitespaces)
            }
            let upstream = Upstream(
                name: trimmedName,
                transport: transport,
                command: command.trimmingCharacters(in: .whitespaces),
                args: argsLine.split(separator: " ").map(String.init),
                env: env,
                keys: keys.filter { !$0.secret.isEmpty && !$0.envVar.isEmpty },
                url: trimmedURL,
                auth: auth,
                confirm: confirm,
                enabled: enabled)
            let ok = await onSave(upstream)
            isBusy = false
            if ok { dismiss() }
        }
    }
}

/// Accepts HTTPS endpoints and plain HTTP loopback endpoints.
enum RemoteURLRule {
    static func isValid(_ raw: String) -> Bool {
        guard let url = URL(string: raw), let host = url.host?.lowercased(), !host.isEmpty else { return false }
        switch url.scheme?.lowercased() {
        case "https": return true
        case "http": return host == "localhost" || host == "::1" || host.hasPrefix("127.")
        default: return false
        }
    }
}

#if DEBUG && !SP_NO_PREVIEWS
#Preview("MCP Servers (light)") {
    UpstreamsView(mgmt: AppModel.previewModel().mgmt)
        .frame(width: 860, height: 560).preferredColorScheme(.light)
}

#if !SP_NO_PREVIEWS
#Preview("MCP Servers (dark)") {
    UpstreamsView(mgmt: AppModel.previewModel().mgmt)
        .frame(width: 860, height: 560).preferredColorScheme(.dark)
}
#endif
#endif
