import SwiftUI
import AppKit
import Darwin
import SallyportKit

/// The result of saving a secret, including SSH passphrase handling.
enum SecretSaveOutcome: Equatable {
    case saved
    case needsPassphrase(String)
    case failed(String)
}

/// Manages secret metadata. Stored values are write-only in this view model.
@MainActor
@Observable
final class KeysViewModel {
    let mgmt: MgmtClient
    var secrets: [SecretMetadata] = []
    var isLoading = false
    var error: String?
    var toast: Toast?

    init(mgmt: MgmtClient) { self.mgmt = mgmt }

    func load() async {
        isLoading = true; error = nil
        do { secrets = try await mgmt.listSecrets() }
        catch { self.error = describe(error) }
        isLoading = false
    }

    /// Creates or updates a secret and maps passphrase errors to the editor state.
    func save(_ input: SecretInput, isNew: Bool) async -> SecretSaveOutcome {
        do {
            if isNew {
                try await mgmt.setSecret(input)
            } else {
                try await mgmt.updateSecret(name: input.name, bind: input.bind,
                                            header: input.header, format: input.format,
                                            confirm: input.confirm, insecureTLS: input.insecureTLS)
                if !input.value.isEmpty {
                    try await mgmt.rotateSecret(name: input.name, value: input.value)
                }
            }
            toast = .ok(isNew ? "Added \(input.name)" : "Updated \(input.name)")
            await load()
            return .saved
        } catch let error as MgmtError where error.isPassphraseRequired {
            return .needsPassphrase(error.message)
        } catch {
            return .failed(describe(error))
        }
    }

    func rotate(name: String, value: String) async -> Bool {
        do {
            try await mgmt.rotateSecret(name: name, value: value)
            toast = .ok("Rotated \(name)")
            await load()
            return true
        } catch {
            toast = .bad(describe(error))
            return false
        }
    }

    func delete(_ name: String) async {
        do {
            try await mgmt.deleteSecret(name: name)
            toast = .ok("Deleted \(name)")
            await load()
        } catch {
            toast = .bad(describe(error))
        }
    }
}

/// Displays secret metadata and controls for adding, editing, rotating, and deleting keys.
struct KeysAPIsView: View {
    let model: AppModel
    @State private var vm: KeysViewModel
    @State private var selection = Set<SecretMetadata.ID>()
    @State private var editing: SecretMetadata?
    @State private var isAdding = false
    @State private var rotating: SecretMetadata?
    @State private var pendingDelete: SecretMetadata?

    init(model: AppModel) {
        self.model = model
        _vm = State(initialValue: KeysViewModel(mgmt: model.mgmt))
    }

    var body: some View {
        ManagementScaffold(
            title: "Keys and APIs",
            subtitle: "API and SSH keys. Stored values are write-only in this interface.",
            symbol: "key.fill",
            isLoading: vm.isLoading,
            error: vm.error,
            locked: model.vault.locked,
            onUnlock: model.unlockForEditing,
            onRefresh: { Task { await vm.load() } },
            toolbar: {
                Button {
                    isAdding = true
                } label: {
                    Label("Add key", systemImage: "plus")
                }
                .buttonStyle(.borderedProminent)
            },
            content: { content }
        )
        .toast($vm.toast)
        .task { if !model.vault.locked { await vm.load() } }
        // Reload after another view changes secrets or the vault unlocks.
        .task(id: model.secretsRevision) { if !model.vault.locked { await vm.load() } }
        .sheet(isPresented: $isAdding) {
            SecretEditor(existing: nil, knownSecrets: vm.secrets,
                         vaultLocked: model.vault.locked, unlockVault: model.unlockForEditing) { input in
                await vm.save(input, isNew: true)
            }
        }
        .sheet(item: $editing) { secret in
            SecretEditor(existing: secret, knownSecrets: vm.secrets,
                         vaultLocked: false, unlockVault: model.unlockForEditing) { input in
                await vm.save(input, isNew: false)
            }
        }
        .sheet(item: $rotating) { secret in
            RotateSheet(secret: secret) { value in
                await vm.rotate(name: secret.name, value: value)
            }
        }
        .confirmationDialog(
            "Delete \(pendingDelete?.name ?? "")?",
            isPresented: Binding(get: { pendingDelete != nil }, set: { if !$0 { pendingDelete = nil } }),
            titleVisibility: .visible
        ) {
            Button("Delete", role: .destructive) {
                if let secret = pendingDelete { Task { await vm.delete(secret.name) } }
                pendingDelete = nil
            }
            Button("Cancel", role: .cancel) { pendingDelete = nil }
        } message: {
            Text("Any host binding that references this key will stop working.")
        }
    }

    @ViewBuilder private var content: some View {
        if vm.secrets.isEmpty && !vm.isLoading {
            EmptyStateView(
                title: "No keys yet",
                message: "Add an API key or SSH key. Stored values are encrypted and are not shown again.",
                symbol: "key"
            ) {
                Button("Add key", systemImage: "plus") { isAdding = true }.buttonStyle(.borderedProminent)
            }
        } else {
            Table(vm.secrets, selection: $selection) {
                TableColumn("Name") { secret in
                    HStack(spacing: 8) {
                        Image(systemName: secret.kind == "ssh-ed25519" ? "terminal.fill" : "network")
                            .foregroundStyle(.secondary)
                        Text(secret.name).fontWeight(.medium).textSelection(.enabled)
                    }
                }
                TableColumn("Kind") { secret in Text(secret.kindLabel).foregroundStyle(.secondary) }
                TableColumn("Per call") { secret in
                    switch secret.confirm {
                    case "click":
                        Label("Click", systemImage: "cursorarrow.click.badge.clock")
                            .font(.caption).foregroundStyle(Theme.warning)
                            .help("Every call with this key needs a one-click confirmation")
                    case "touchid":
                        Label("Touch ID", systemImage: "touchid")
                            .font(.caption).foregroundStyle(Theme.warning)
                            .help("Every call with this key needs a Touch ID confirmation")
                    default:
                        Text("Off").foregroundStyle(.tertiary)
                    }
                }
                .width(90)
                TableColumn("Bound to") { secret in
                    if secret.bind.isEmpty {
                        Text("Not set").foregroundStyle(.tertiary)
                    } else {
                        Text(secret.bind.joined(separator: ", ")).foregroundStyle(.secondary).lineLimit(1)
                    }
                }
                TableColumn("Rotated") { secret in
                    Text(secret.rotatedAt.map(TimeFormat.day) ?? "Not available").foregroundStyle(.secondary)
                }
                TableColumn("") { secret in
                    Menu {
                        Button("Edit…", systemImage: "pencil") { editing = secret }
                        Button("Rotate value…", systemImage: "arrow.triangle.2.circlepath") { rotating = secret }
                        Divider()
                        Button("Delete", systemImage: "trash", role: .destructive) { pendingDelete = secret }
                    } label: {
                        Image(systemName: "ellipsis.circle")
                    }
                    .menuStyle(.borderlessButton)
                    .fixedSize()
                }
                .width(36)
            }
            // Double-click opens the editor. The context menu mirrors the row menu.
            .contextMenu(forSelectionType: SecretMetadata.ID.self) { ids in
                if let secret = secret(for: ids) {
                    Button("Edit…", systemImage: "pencil") { editing = secret }
                    Button("Rotate value…", systemImage: "arrow.triangle.2.circlepath") { rotating = secret }
                    Divider()
                    Button("Delete", systemImage: "trash", role: .destructive) { pendingDelete = secret }
                }
            } primaryAction: { ids in
                editing = secret(for: ids)
            }
        }
    }

    /// Returns the row selected by a table gesture.
    private func secret(for ids: Set<SecretMetadata.ID>) -> SecretMetadata? {
        ids.first.flatMap { id in vm.secrets.first { $0.id == id } }
    }
}

// MARK: - Add / edit sheet (value is write-only)

struct SecretEditor: View {
    static let maxImportedKeyBytes = 1 * 1024 * 1024

    enum ImportedKeyFileError: LocalizedError, Equatable {
        case tooLarge
        case unsafeFile
        case unreadable
        case invalidUTF8

        var errorDescription: String? {
            switch self {
            case .tooLarge:
                return "The key file exceeds the 1 MiB import limit."
            case .unsafeFile:
                return "The key must be a direct, single-link regular file."
            case .unreadable:
                return "The key file changed while it was being read or failed validation."
            case .invalidUTF8:
                return "The key file is not valid UTF-8 text."
            }
        }
    }

    let existing: SecretMetadata?
    let knownSecrets: [SecretMetadata]
    /// Initial values for a key requested by an agent.
    var prefill: SecretPrefill?
    /// Optional context shown above the form.
    var headerAccessory: AnyView?
    /// Indicates that saving requires an unlock first.
    var vaultLocked: Bool = false
    /// Unlocks the vault and reports whether it opened.
    var unlockVault: (() async -> Bool)?
    let onSave: (SecretInput) async -> SecretSaveOutcome

    @Environment(\.dismiss) private var dismiss
    @State private var name: String
    @State private var kind: SecretKind
    @State private var value = ""
    @State private var bind: [String]
    @State private var header: String
    @State private var format: String
    @State private var params: [String: String]
    @State private var confirm: String
    @State private var insecureTLS: Bool
    @State private var passphrase = ""
    @State private var pickedPreset: ServicePreset?
    @State private var isBusy = false
    /// Error shown beside the form fields.
    @State private var formError: String?
    /// Hint shown after an encrypted SSH key requires a passphrase.
    @State private var passphraseHint: String?
    @FocusState private var passphraseFocused: Bool
    /// Tracks fields eligible to show validation errors.
    @State private var touched: Set<String> = []
    @State private var didAttemptSave = false
    /// Controls the unlock confirmation.
    @State private var askUnlock = false
    @State private var isUnlocking = false

    init(existing: SecretMetadata?, knownSecrets: [SecretMetadata],
         prefill: SecretPrefill? = nil, headerAccessory: AnyView? = nil,
         vaultLocked: Bool = false, unlockVault: (() async -> Bool)? = nil,
         onSave: @escaping (SecretInput) async -> SecretSaveOutcome) {
        self.existing = existing
        self.knownSecrets = knownSecrets
        self.prefill = prefill
        self.headerAccessory = headerAccessory
        self.vaultLocked = vaultLocked
        self.unlockVault = unlockVault
        self.onSave = onSave
        _name = State(initialValue: existing?.name ?? prefill?.name ?? "")
        _kind = State(initialValue: existing.flatMap { SecretKind(rawValue: $0.kind) } ?? prefill?.kind ?? .bearer)
        _bind = State(initialValue: existing?.bind ?? prefill?.bind ?? [])
        _header = State(initialValue: existing?.header ?? prefill?.header ?? "")
        _format = State(initialValue: existing?.format
                        ?? prefill?.format.nilIfEmpty
                        ?? "Bearer {secret}")
        _params = State(initialValue: existing?.params ?? [:])
        _confirm = State(initialValue: existing?.confirm ?? "")
        _insecureTLS = State(initialValue: existing?.insecureTLS ?? false)
    }

    private var isEditing: Bool { existing != nil }
    private var isSSH: Bool { kind == .sshEd25519 }

    /// Derives service-neutral placeholders from the first host binding.
    private var bindPlaceholder: String { bind.first ?? "api.example.com" }
    private var namePlaceholder: String {
        if let host = bind.first, !host.isEmpty {
            return host.replacingOccurrences(of: ".", with: "_") + "_key"
        }
        return "my_api_key"
    }
    private var trimmedName: String { name.trimmingCharacters(in: .whitespaces) }
    private var nameCollision: Bool {
        !isEditing && knownSecrets.contains { $0.name == trimmedName }
    }

    // MARK: Validation

    /// Show a field's error only once it's been touched or a save was attempted.
    private func shows(_ field: String) -> Bool { didAttemptSave || touched.contains(field) }

    private var nameError: String? {
        guard shows("name") else { return nil }
        if trimmedName.isEmpty { return "Give the key a name." }
        if nameCollision { return "A key named \(trimmedName) already exists." }
        if trimmedName.contains(" ") { return "Use letters, digits, _ or - (no spaces)." }
        return nil
    }
    private var valueError: String? {
        guard shows("value"), !isEditing, value.isEmpty else { return nil }
        return isSSH ? "Paste the private key, or import it from a file."
                     : "Paste the secret value."
    }
    private var headerError: String? {
        guard shows("header"), kind.needsHeaderName,
              header.trimmingCharacters(in: .whitespaces).isEmpty else { return nil }
        return "Name the header this key is sent in (e.g. X-Api-Key)."
    }
    private func paramError(_ field: ParamField) -> String? {
        // Labels containing "optional" are not required.
        guard shows("param." + field.key), !field.label.lowercased().contains("optional"),
              (params[field.key] ?? "").trimmingCharacters(in: .whitespaces).isEmpty else { return nil }
        return "\(field.label) is required for \(kind.label)."
    }
    private func paramRequired(_ field: ParamField) -> Bool {
        !field.label.lowercased().contains("optional")
    }
    /// Warns when an HTTP key has no permitted destination.
    private var bindWarning: String? {
        guard kind.isHTTPCredential, bind.isEmpty else { return nil }
        return "This key has no host binding and will not be sent. Add the API host."
    }

    /// Required fields that still block saving.
    private var missingFields: [String] {
        var out: [String] = []
        if trimmedName.isEmpty || nameCollision || trimmedName.contains(" ") { out.append("Name") }
        if !isEditing && value.isEmpty { out.append("Value") }
        if kind.needsHeaderName && header.trimmingCharacters(in: .whitespaces).isEmpty { out.append("Header") }
        for f in kind.paramFields where paramRequired(f)
            && (params[f.key] ?? "").trimmingCharacters(in: .whitespaces).isEmpty {
            out.append(f.label)
        }
        return out
    }
    private var canSave: Bool { missingFields.isEmpty }

    var body: some View {
        SheetScaffold(existing.map { "Edit key \($0.name)" } ?? "Add key",
                      systemImage: "key.fill", width: 480) {
            VStack(alignment: .leading, spacing: 12) {
                if let headerAccessory { headerAccessory }
                if vaultLocked { lockedBanner }
                // A service preset fills the host binding and adapter fields.
                if !isEditing {
                    FormRow(label: "Service",
                            hint: "Optional. Fills the binding and adapter for a known service.") {
                        Menu {
                            ForEach(ServicePresets.all) { preset in
                                Button(preset.label) { applyPreset(preset) }
                            }
                        } label: {
                            Label(pickedPreset?.label ?? "Choose a service…", systemImage: "sparkles")
                        }
                        .menuStyle(.borderlessButton)
                        .fixedSize()
                    }
                    if let preset = pickedPreset, let url = URL(string: preset.docsURL) {
                        Link("Create the token on \(preset.label) ↗", destination: url)
                            .font(.caption)
                    }
                }
                FormRow(label: "Name",
                        hint: "Referenced by hosts and MCP env mappings.",
                        isRequired: !isEditing, error: nameError) {
                    TextField(namePlaceholder, text: $name)
                        .textFieldStyle(.roundedBorder)
                        .disabled(isEditing)
                        .invalidField(nameError != nil)
                        .onChange(of: name) { touched.insert("name") }
                }
                FormRow(label: "Kind") {
                    Picker("Kind", selection: $kind) {
                        ForEach(SecretKind.allCases) { Text($0.label).tag($0) }
                    }
                    .labelsHidden()
                    .fixedSize()
                    // Update only an untouched default injection format.
                    .onChange(of: kind) { old, new in
                        let defaults = ["Bearer {secret}", "{secret}"]
                        guard !isEditing, defaults.contains(format) else { return }
                        format = new == .bearer ? "Bearer {secret}" : "{secret}"
                        _ = old
                    }
                }
                FormRow(label: isEditing ? "New value" : "Value",
                        hint: isEditing ? "Leave blank to keep the current value; type to replace it." : "\(kind.valueLabel). Stored encrypted and not shown again.",
                        isRequired: !isEditing, error: valueError) {
                    // The stored value is never loaded back into the field.
                    HStack(spacing: Theme.Spacing.sm) {
                        SecureField(isSSH ? "paste private key (PEM/OpenSSH)" : kind.valueLabel, text: $value)
                            .textFieldStyle(.roundedBorder)
                            .invalidField(valueError != nil)
                            .onChange(of: value) { touched.insert("value") }
                        if isSSH {
                            Button("Import from file…", systemImage: "doc.badge.plus", action: importFromFile)
                                .controlSize(.small)
                                .help("Read a private key file (e.g. ~/.ssh/id_ed25519) into the value.")
                        }
                    }
                }

                // The passphrase decrypts an imported SSH key and is not stored.
                if isSSH {
                    FormRow(label: "Passphrase",
                            hint: passphraseHint ?? "Optional. Used once to decrypt a password-protected key and not stored.") {
                        SecureField("key passphrase (optional)", text: $passphrase)
                            .textFieldStyle(.roundedBorder)
                            .focused($passphraseFocused)
                            .onSubmit(submit)
                    }
                }

                if kind.isHTTPCredential {
                    FormRow(label: "Bind hosts",
                            hint: "The key may be sent only to these domains.",
                            warning: bindWarning) {
                        TokenEditor(tokens: $bind, placeholder: bindPlaceholder)
                    }
                    if kind.needsHeaderName {
                        FormRow(label: "Header", isRequired: true, error: headerError) {
                            TextField("X-Api-Key", text: $header)
                                .textFieldStyle(.roundedBorder)
                                .invalidField(headerError != nil)
                                .onChange(of: header) { touched.insert("header") }
                        }
                    }
                    if kind.usesInjectFormat {
                        FormRow(label: "Inject format",
                                hint: "`{secret}` is replaced with the value at request time.") {
                            TextField("Bearer {secret}", text: $format).textFieldStyle(.roundedBorder)
                        }
                    }
                    // Adapter parameters are stored as metadata.
                    ForEach(kind.paramFields) { field in
                        FormRow(label: field.label,
                                isRequired: paramRequired(field), error: paramError(field)) {
                            TextField(field.placeholder, text: Binding(
                                get: { params[field.key] ?? "" },
                                set: { params[field.key] = $0; touched.insert("param." + field.key) }))
                                .textFieldStyle(.roundedBorder)
                                .invalidField(paramError(field) != nil)
                        }
                    }
                } else {
                    FormRow(label: "Bind hosts", hint: "SSH keys are referenced by name from SSH Hosts.") {
                        Text("Set the host on the SSH Hosts tab.").font(.caption).foregroundStyle(.tertiary)
                    }
                }

                Divider()
                FormRow(label: "Approval per call",
                        hint: "Require approval for each use of this key, including approved agent sessions.") {
                    Picker("Approval per call", selection: $confirm) {
                        Text("Off").tag("")
                        Text("One click").tag("click")
                        Text("Touch ID").tag("touchid")
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                }

                if kind.isHTTPCredential {
                    FormRow(label: "TLS verification",
                            hint: "When disabled, accepts any certificate from bound hosts. Use only for controlled internal endpoints.") {
                        Toggle("Disable certificate verification", isOn: $insecureTLS)
                            .toggleStyle(.checkbox)
                    }
                }

                if let formError {
                    Label(formError, systemImage: "exclamationmark.triangle.fill")
                        .font(.caption).foregroundStyle(Theme.danger)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        } footer: {
            VStack(alignment: .leading, spacing: Theme.Spacing.sm) {
                if didAttemptSave, !missingFields.isEmpty {
                    Label("Still needed: \(missingFields.joined(separator: ", "))",
                          systemImage: "exclamationmark.circle.fill")
                        .font(.caption).foregroundStyle(Theme.danger)
                }
                SheetButtons(saveTitle: saveTitle, isBusy: isBusy || isUnlocking, isDisabled: false,
                             onCancel: { dismiss() }, onSave: submit)
            }
        }
        .confirmationDialog("The vault is locked", isPresented: $askUnlock, titleVisibility: .visible) {
            Button("Unlock with Touch ID") { unlockThenSave() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Unlock the vault to add \(trimmedName). Sallyport will continue after the unlock.")
        }
    }

    /// Includes the unlock step in the add-button label when required.
    private var saveTitle: String {
        if isEditing { return "Save" }
        return vaultLocked ? "Unlock & Add" : "Add"
    }

    private var lockedBanner: some View {
        HStack(alignment: .top, spacing: Theme.Spacing.sm) {
            Image(systemName: "lock.fill").foregroundStyle(Theme.warning)
            VStack(alignment: .leading, spacing: 2) {
                Text("The vault is locked").font(.callout.weight(.medium))
                Text("Adding a key needs the vault open. You'll be asked for Touch ID.")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
            Button("Unlock", systemImage: "touchid") { unlockThenSave(saveAfter: false) }
                .buttonStyle(.borderedProminent)
                .controlSize(.small)
                .disabled(isUnlocking)
        }
        .padding(Theme.Spacing.md)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Theme.warning.opacity(0.10),
                    in: RoundedRectangle(cornerRadius: Theme.Radius.md, style: .continuous))
    }

    /// Unlocks the vault and optionally continues the save.
    private func unlockThenSave(saveAfter: Bool = true) {
        guard let unlockVault, !isUnlocking else { return }
        isUnlocking = true
        formError = nil
        Task {
            let opened = await unlockVault()
            isUnlocking = false
            guard opened else {
                formError = "The vault is still locked. The key was not added."
                return
            }
            if saveAfter { performSave() }
        }
    }

    /// Open a private key file and read it straight into the (masked) value field.
    /// Any key type / no extension is allowed, since SSH keys are often extensionless.
    /// Seed the form from a known-service preset (name/kind/bind/header/format/params).
    private func applyPreset(_ preset: ServicePreset) {
        pickedPreset = preset
        if name.isEmpty { name = preset.suggestedName }
        kind = preset.kind
        if bind.isEmpty { bind = preset.bind }
        if let h = preset.header { header = h }
        if let f = preset.format { format = f }
        for (k, v) in preset.params where params[k]?.isEmpty ?? true { params[k] = v }
    }

    private func importFromFile() {
        let panel = NSOpenPanel()
        panel.title = "Import SSH private key"
        panel.prompt = "Import"
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        panel.showsHiddenFiles = true       // ~/.ssh is hidden
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            value = try Self.readImportedKey(at: url)
            formError = nil
        } catch {
            formError = "Couldn't read \(url.lastPathComponent): \(error.localizedDescription)"
        }
    }

    /// Reads an imported key through the bounded regular-file reader.
    static func readImportedKey(at url: URL) throws -> String {
        let data: Data
        do {
            data = try BoundedFileReader.read(url, maxBytes: maxImportedKeyBytes)
        } catch BoundedFileReader.ReadError.tooLarge {
            throw ImportedKeyFileError.tooLarge
        } catch BoundedFileReader.ReadError.notRegularFile,
                BoundedFileReader.ReadError.multipleLinks {
            throw ImportedKeyFileError.unsafeFile
        } catch BoundedFileReader.ReadError.open(let code) where code == ELOOP {
            throw ImportedKeyFileError.unsafeFile
        } catch {
            throw ImportedKeyFileError.unreadable
        }
        guard let text = String(data: data, encoding: .utf8) else {
            throw ImportedKeyFileError.invalidUTF8
        }
        return text
    }

    /// Validates the form and requests an unlock before saving when needed.
    private func submit() {
        didAttemptSave = true
        guard canSave else { return }        // errors are now visible on the fields
        if vaultLocked {
            askUnlock = true                 // → "Unlock with Touch ID" → performSave()
            return
        }
        performSave()
    }

    private func performSave() {
        guard canSave else { return }
        isBusy = true
        formError = nil
        Task {
            let input = SecretInput(
                name: name.trimmingCharacters(in: .whitespaces),
                kind: kind.rawValue,
                value: value,
                bind: kind.isHTTPCredential ? bind : [],
                header: kind.needsHeaderName ? header : nil,
                format: kind.usesInjectFormat ? format : nil,
                params: kind.paramFields.isEmpty ? [:] : params,
                passphrase: isSSH ? passphrase : nil,
                confirm: confirm,
                insecureTLS: kind.isHTTPCredential && insecureTLS)
            let outcome = await onSave(input)
            isBusy = false
            switch outcome {
            case .saved:
                dismiss()
            case .needsPassphrase:
                passphraseHint = "This key is password-protected. Enter its passphrase to import it."
                formError = nil
                passphraseFocused = true
            case .failed(let message):
                formError = message
            }
        }
    }
}

// MARK: - Rotate sheet

private struct RotateSheet: View {
    let secret: SecretMetadata
    let onRotate: (String) async -> Bool

    @Environment(\.dismiss) private var dismiss
    @State private var value = ""
    @State private var isBusy = false

    var body: some View {
        SheetScaffold("Rotate \(secret.name)", systemImage: "arrow.triangle.2.circlepath",
                      width: 440, scrolls: false) {
            Text("Replace the stored value. Host bindings and approval settings do not change.")
                .font(.callout).foregroundStyle(.secondary)
            FormRow(label: "New value") {
                SecureField("paste new secret", text: $value).textFieldStyle(.roundedBorder)
            }
        } footer: {
            SheetButtons(saveTitle: "Rotate", isBusy: isBusy, isDisabled: value.isEmpty,
                         onCancel: { dismiss() }, onSave: {
                isBusy = true
                Task {
                    let ok = await onRotate(value)
                    isBusy = false
                    if ok { dismiss() }
                }
            })
        }
    }
}

#if DEBUG && !SP_NO_PREVIEWS
#Preview("Keys & APIs (light)") {
    KeysAPIsView(model: AppModel.previewModel())
        .frame(width: 820, height: 560).preferredColorScheme(.light)
}

#if !SP_NO_PREVIEWS
#Preview("Keys & APIs (dark)") {
    KeysAPIsView(model: AppModel.previewModel())
        .frame(width: 820, height: 560).preferredColorScheme(.dark)
}
#endif
#endif

/// Initial values for a key requested by an agent.
struct SecretPrefill {
    let name: String
    let kind: SecretKind
    let bind: [String]
    /// Metadata supplied with the request.
    var header: String = ""
    var format: String = ""
}

/// A prefilled key editor for an agent credential request.
struct CredentialRequestSheet: View {
    let request: CredentialRequest
    @Bindable var model: AppModel
    @State private var responded = false

    private var originName: String {
        request.provenance.origin.appName ?? request.provenance.origin.name
    }
    private var seedKind: SecretKind { SecretKind(rawValue: request.kind) ?? .bearer }
    private var seedName: String {
        request.suggestedName.isEmpty
            ? request.host.replacingOccurrences(of: ".", with: "_") + "_key"
            : request.suggestedName
    }

    /// Accepts only public HTTPS documentation links without userinfo or custom ports.
    static func safeDocsURL(_ raw: String) -> URL? {
        guard !raw.isEmpty,
              raw.unicodeScalars.allSatisfy({ $0.value >= 0x20 && !$0.properties.isWhitespace }),
              var components = URLComponents(string: raw),
              components.scheme?.lowercased() == "https",
              components.user == nil, components.password == nil,
              components.port == nil || components.port == 443,
              let host = components.host?.lowercased(), host.contains("."),
              host.unicodeScalars.allSatisfy({ $0.isASCII }),
              isDNSHostname(host),
              host != "localhost", !host.hasSuffix(".localhost"), !host.hasSuffix(".local"),
              !isIPAddress(host) else { return nil }
        components.scheme = "https"
        return components.url
    }

    private static func isIPAddress(_ host: String) -> Bool {
        var v4 = in_addr()
        var v6 = in6_addr()
        return host.withCString {
            inet_pton(AF_INET, $0, &v4) == 1 || inet_pton(AF_INET6, $0, &v6) == 1
        }
    }

    private static func isDNSHostname(_ host: String) -> Bool {
        guard host.utf8.count <= 253 else { return false }
        let labels = host.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count >= 2 else { return false }
        return labels.allSatisfy { label in
            let bytes = Array(label.utf8)
            guard (1...63).contains(bytes.count),
                  let first = bytes.first, let last = bytes.last,
                  isASCIIAlphaNumeric(first), isASCIIAlphaNumeric(last) else { return false }
            return bytes.allSatisfy { isASCIIAlphaNumeric($0) || $0 == 0x2d }
        }
    }

    private static func isASCIIAlphaNumeric(_ byte: UInt8) -> Bool {
        (0x30...0x39).contains(byte) || (0x61...0x7a).contains(byte)
    }

    var body: some View {
        SecretEditor(existing: nil, knownSecrets: [],
                     prefill: SecretPrefill(name: seedName, kind: seedKind, bind: request.hosts,
                                            header: request.header, format: request.format),
                     headerAccessory: AnyView(banner),
                     vaultLocked: model.vault.locked,
                     unlockVault: model.unlockForEditing) { input in
            do {
                try await model.mgmt.setSecret(input)
                responded = true
                model.respondCredential(request, provisioned: true, name: input.name)
                return .saved
            } catch let error as MgmtError where error.isPassphraseRequired {
                return .needsPassphrase(error.message)
            } catch {
                return .failed(describe(error))
            }
        }
        // Closing without saving declines the request.
        .onDisappear {
            if !responded { model.respondCredential(request, provisioned: false, name: nil) }
        }
    }

    private var banner: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label("\(originName) requested a key", systemImage: "key.fill")
                .font(.headline)
            if !request.purpose.isEmpty {
                Text(request.purpose).font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            // The requested hosts seed the editable binding field.
            VStack(alignment: .leading, spacing: 3) {
                Label("Will be used only for", systemImage: "shield.lefthalf.filled")
                    .font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                Text(request.hosts.joined(separator: "  ·  "))
                    .font(.callout.monospaced()).textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let url = Self.safeDocsURL(request.docsURL),
               let destination = url.host(percentEncoded: true) {
                Link("Create token on \(destination) ↗", destination: url).font(.callout)
            } else if !request.docsURL.isEmpty {
                Text("Agent supplied an unsafe documentation link; it was not opened.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            if !request.scopes.isEmpty {
                Text("Suggested: \(request.scopes.joined(separator: ", "))")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Theme.accent.opacity(0.08), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
    }
}


private extension String {
    var nilIfEmpty: String? { isEmpty ? nil : self }
}
