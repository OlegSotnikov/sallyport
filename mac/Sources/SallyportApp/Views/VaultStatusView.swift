import SwiftUI
import SallyportKit

/// Displays vault lock state, hardware protection, and root keys.
struct VaultStatusView: View {
    let model: AppModel
    @State private var confirmGate = false
    @State private var gateBusy = false
    @State private var gateError: String?
    @State private var showingReset = false

    var body: some View {
        VStack(spacing: 0) {
            ScreenHeader(
                title: LocalizedStringResource("Vault and keys"),
                subtitle: LocalizedStringResource("Lock state, hardware protection, and cryptographic keys."),
                symbol: "lock.rectangle.stack"
            ) {
                if model.vault.locked {
                    Button("Unlock", systemImage: "touchid") { Task { await model.unlock() } }
                        .buttonStyle(.borderedProminent)
                } else {
                    Button("Lock now", systemImage: "lock.fill") { model.lockNow() }
                }
            }
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: Theme.Spacing.lg) {
                    if let err = model.vaultUnlockError {
                        Label {
                            Text(verbatim: err)
                        } icon: {
                            Image(systemName: "exclamationmark.triangle.fill")
                        }
                            .font(.callout)
                            .foregroundStyle(Theme.danger)
                            .fixedSize(horizontal: false, vertical: true)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(Theme.Spacing.md)
                            .background(Theme.danger.opacity(0.10),
                                        in: RoundedRectangle(cornerRadius: Theme.Radius.md, style: .continuous))
                    }
                    vaultCard
                    hardwareGateCard
                    trustCard
                    rootKeysCard
                    dangerZoneCard
                    Text("Stored secret values are not shown in this interface.")
                        .font(.caption).foregroundStyle(.tertiary)
                }
                .padding(Theme.screenPadding)
            }
        }
        .sheet(isPresented: $showingReset) {
            ResetVaultSheet(model: model)
        }
    }

    /// Opens the confirmation flow for permanently erasing the vault.
    private var dangerZoneCard: some View {
        Card {
            SectionHeader(LocalizedStringResource("Danger zone"),
                          systemImage: "exclamationmark.octagon")
            HStack(alignment: .top, spacing: Theme.Spacing.md) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Erase the vault and start over").font(.callout.weight(.medium))
                    Text("Permanently erases stored keys and configuration. There is no backup or recovery. You must reissue keys from their providers.")
                        .font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .layoutPriority(1)
                Spacer(minLength: Theme.Spacing.sm)
                Button("Erase…", systemImage: "trash") { showingReset = true }
                    .buttonStyle(.bordered)
                    .tint(Theme.danger)
                    .fixedSize(horizontal: true, vertical: false)
            }
        }
    }

    private var vaultCard: some View {
        Card {
            HStack(spacing: Theme.Spacing.md) {
                Image(systemName: model.vault.symbol)
                    .font(.title)
                    .foregroundStyle(model.vault.tint)
                    .frame(width: 36)
                VStack(alignment: .leading, spacing: 2) {
                    Text(vaultStateTitle)
                        .font(.headline)
                    Text(vaultStateSubtitle)
                        .font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer()
                if !model.vault.locked {
                    // Limit the one-second refresh to the countdown pill.
                    TimelineView(.periodic(from: .now, by: 1)) { context in
                        StatusPill(verbatim: model.vault.ttlClock(anchoredAt: model.vaultUpdatedAt, now: context.date),
                                   systemImage: "timer", tint: Theme.verified, style: .mono)
                    }
                }
            }
        }
    }

    private var hardwareGateCard: some View {
        Card {
            SectionHeader(LocalizedStringResource("Hardware gate"), systemImage: "lock.shield")
            if model.isHardwareGated {
                HStack(spacing: Theme.Spacing.sm) {
                    Image(systemName: "checkmark.shield.fill").foregroundStyle(Theme.verified)
                    VStack(alignment: .leading, spacing: 1) {
                        Text("Enabled").fontWeight(.medium)
                        Text("Secure Enclave and Touch ID gate vault unlock. The decrypted vault key remains in memory only while the vault is unlocked.")
                            .font(.caption).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .layoutPriority(1)
                    Spacer()
                    StatusPill(LocalizedStringResource("Secure Enclave"), tint: Theme.verified)
                }
            } else {
                VStack(alignment: .leading, spacing: Theme.Spacing.sm) {
                    Text("The vault wrap key is stored in a user-readable software file. The hardware gate replaces it with a vault identity protected by Secure Enclave and Touch ID.")
                        .font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    Text("Enabling the hardware gate is irreversible. If this Mac is erased or the Secure Enclave key is lost, the vault cannot be recovered. Reissue stored keys from their providers.")
                        .font(.caption).foregroundStyle(Theme.warning)
                        .fixedSize(horizontal: false, vertical: true)
                    HStack(spacing: Theme.Spacing.sm) {
                        Button("Enable hardware gate…", systemImage: "lock.shield") { confirmGate = true }
                            .buttonStyle(.borderedProminent)
                            .disabled(model.backend != .secureEnclave || gateBusy)
                        if gateBusy { ProgressView().controlSize(.small) }
                    }
                    if model.backend != .secureEnclave {
                        Text("Sallyport hardware protection requires Apple Silicon.")
                            .font(.caption2).foregroundStyle(.tertiary)
                    }
                    if let gateError {
                        Text(verbatim: gateError).font(.caption).foregroundStyle(Theme.danger)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
        }
        .confirmationDialog("Enable the hardware gate?", isPresented: $confirmGate, titleVisibility: .visible) {
            Button("Enable hardware gate") { runEnableGate() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Secure Enclave and Touch ID will gate vault unlock. The change is irreversible. Every unlock will require Touch ID. If the Secure Enclave key is lost, the vault cannot be recovered.")
        }
    }

    private func runEnableGate() {
        gateError = nil
        gateBusy = true
        Task {
            do { try await model.enableHardwareGate() }
            catch { gateError = error.localizedDescription }
            gateBusy = false
        }
    }

    private var trustCard: some View {
        Card {
            SectionHeader(LocalizedStringResource("Key storage"), systemImage: "checkmark.seal")
            HStack(spacing: Theme.Spacing.sm) {
                Image(systemName: model.backend == .secureEnclave ? "cpu.fill" : "desktopcomputer")
                    .foregroundStyle(model.backend == .secureEnclave ? Theme.verified : Theme.warning)
                Text(model.backendDisplayName).fontWeight(.medium)
                Spacer()
                StatusPill(backendProtectionStatus,
                           tint: model.backend == .secureEnclave ? Theme.verified : Theme.warning)
            }
            if model.backend == .software {
                Text("Development software keys are in use. Vault and audit keys are not Secure Enclave backed.")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    /// Lists the keys used by the current vault and audit implementation.
    private var rootKeysCard: some View {
        Card {
            SectionHeader(LocalizedStringResource("Root keys"), systemImage: "key.fill")
            keyRow(Text(verbatim: "K-wrap"), LocalizedStringResource(
                "P-256 ECDH · Secure Enclave · opens the vault identity after Touch ID; the identity unwraps the DEK"))
            keyRow(Text(verbatim: "DEK"), LocalizedStringResource(
                "256-bit ChaCha20-Poly1305 · memory only while unlocked · encrypts stored secrets and metadata"))
            keyRow(Text("Audit recipient"), LocalizedStringResource(
                "P-256 ECIES · encrypts audit rows for this vault"))
            keyRow(Text("Audit signer"), LocalizedStringResource(
                "Separate P-256 ECDSA key · signs audit rows, not approval decisions"))
        }
    }

    private func keyRow(_ name: Text, _ desc: LocalizedStringResource) -> some View {
        HStack(alignment: .top, spacing: Theme.Spacing.sm) {
            Image(systemName: "key.fill").foregroundStyle(Theme.accent).font(.caption).frame(width: 16)
            VStack(alignment: .leading, spacing: 1) {
                name.font(.callout.monospaced()).fontWeight(.medium)
                Text(desc).font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
        }
    }

    private var vaultStateTitle: LocalizedStringResource {
        model.vault.locked
            ? LocalizedStringResource("Vault locked")
            : LocalizedStringResource("Vault unlocked")
    }

    private var vaultStateSubtitle: LocalizedStringResource {
        model.vault.locked
            ? LocalizedStringResource("Unlock to let bound credentials be used.")
            : LocalizedStringResource("Your stored keys work while unlocked.")
    }

    private var backendProtectionStatus: LocalizedStringResource {
        model.backend == .secureEnclave
            ? LocalizedStringResource("Hardware")
            : LocalizedStringResource("Software")
    }
}

#if DEBUG && !SP_NO_PREVIEWS
#Preview("Vault unlocked (light)") {
    VaultStatusView(model: AppModel.previewModel())
        .frame(width: 820, height: 560)
        .preferredColorScheme(.light)
}

#if !SP_NO_PREVIEWS
#Preview("Vault locked (dark)") {
    let model = AppModel.previewModel()
    model.vault = VaultState(locked: true, ttlSec: 0)
    return VaultStatusView(model: model)
        .frame(width: 820, height: 560)
        .preferredColorScheme(.dark)
}
#endif
#endif


// MARK: - Reset (erase the vault)

/// Requires the reset phrase before permanently erasing the vault.
private struct ResetVaultSheet: View {
    let model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var typed = ""
    @State private var isBusy = false
    @State private var error: String?

    private let erasedItems: [LocalizedStringResource] = [
        LocalizedStringResource("API keys, SSH private keys, and OAuth tokens"),
        LocalizedStringResource("SSH hosts, MCP servers, and allowlist entries"),
        LocalizedStringResource("Security settings"),
        LocalizedStringResource("Audit history and session recordings")
    ]

    private var phrase: String { AppModel.resetConfirmationPhrase }
    private var matches: Bool {
        AppModel.resetConfirmationMatches(typed, phrase: phrase)
    }

    var body: some View {
        SheetScaffold(LocalizedStringResource("Erase the vault"),
                      systemImage: "exclamationmark.octagon.fill", width: 520) {
            VStack(alignment: .leading, spacing: Theme.Spacing.md) {
                HStack(alignment: .top, spacing: Theme.Spacing.sm) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(Theme.danger).font(.title3)
                    VStack(alignment: .leading, spacing: 4) {
                        Text("This permanently destroys every stored key.")
                            .font(.callout.weight(.semibold))
                        Text("There is no backup, export, or recovery. After erasing, create a new vault and reissue keys from their providers.")
                            .font(.caption).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                .padding(Theme.Spacing.md)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Theme.danger.opacity(0.10),
                            in: RoundedRectangle(cornerRadius: Theme.Radius.md, style: .continuous))

                VStack(alignment: .leading, spacing: 4) {
                    Text("The reset erases:").font(.callout.weight(.medium))
                    ForEach(erasedItems.indices, id: \.self) { index in
                        Label {
                            Text(erasedItems[index])
                        } icon: {
                            Image(systemName: "minus")
                        }
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)

                FormRow(label: LocalizedStringResource("Type to confirm"),
                        hint: LocalizedStringResource("Type the phrase exactly as shown."),
                        isRequired: true,
                        error: (!typed.isEmpty && !matches)
                            ? String(localized: "That is not the phrase.") : nil) {
                    TextField(text: $typed, prompt: Text(verbatim: phrase)) {
                        Text("Confirmation phrase")
                    }
                        .textFieldStyle(.roundedBorder)
                        .autocorrectionDisabled()
                        .invalidField(!typed.isEmpty && !matches)
                }

                if let error {
                    Label {
                        Text(verbatim: error)
                    } icon: {
                        Image(systemName: "exclamationmark.triangle.fill")
                    }
                        .font(.caption).foregroundStyle(Theme.danger)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        } footer: {
            HStack {
                Button("Cancel", role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Button(role: .destructive) { erase() } label: {
                    HStack(spacing: Theme.Spacing.xs + 2) {
                        if isBusy { ProgressView().controlSize(.small) }
                        Text("Erase the vault")
                    }
                }
                .buttonStyle(.borderedProminent)
                .tint(Theme.danger)
                .disabled(!matches || isBusy)
            }
        }
    }

    private func erase() {
        guard matches, !isBusy else { return }
        isBusy = true
        error = nil
        Task {
            do {
                try await model.resetVault(confirmation: typed)
                dismiss()
            } catch {
                self.error = describe(error)
            }
            isBusy = false
        }
    }
}


#if DEBUG
/// Exposes the private reset sheet to the UI renderer.
struct ResetVaultSheetPreview: View {
    let model: AppModel
    var body: some View { ResetVaultSheet(model: model) }
}
#endif
