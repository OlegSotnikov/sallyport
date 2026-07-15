import SwiftUI
import SallyportVault

/// Shows vault or journal integrity failures and requires Touch ID to accept the current state.
struct IntegrityBanner: View {
    @Bindable var model: AppModel
    @State private var isBusy = false

    var body: some View {
        VStack(alignment: .leading, spacing: Theme.Spacing.sm) {
            Label("Integrity check failed", systemImage: "exclamationmark.shield.fill")
                .font(.headline)
                .foregroundStyle(Theme.danger)
            ForEach(model.integrityIssues, id: \.code) { issue in
                if let message = localizedMessage(for: issue) {
                    Text(message)
                        .font(.callout)
                        .fixedSize(horizontal: false, vertical: true)
                } else {
                    Text(verbatim: issue.message)
                        .font(.callout)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            VStack(alignment: .leading, spacing: Theme.Spacing.sm) {
                Text("Accept only if you restored a backup or reset this Mac. Otherwise, treat every stored key as exposed and rotate it.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Button("Accept current state with Touch ID",
                       systemImage: "touchid",
                       action: acceptCurrentState)
                    .disabled(isBusy)
            }
        }
        .padding(Theme.Spacing.lg)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Theme.danger.opacity(0.10))
    }

    private func acceptCurrentState() {
        isBusy = true
        Task {
            await model.readoptIntegrity()
            isBusy = false
        }
    }

    /// Integrity codes are stable; engine messages can contain technical details
    /// that are intentionally not used as localization keys.
    private func localizedMessage(for issue: IntegrityIssue) -> LocalizedStringResource? {
        switch issue.code {
        case "hydration-unreadable":
            LocalizedStringResource("The sealed vault configuration could not be decoded.")
        case "integrity-gate-unavailable":
            LocalizedStringResource("The integrity check can run only while the vault is being unlocked.")
        case "lifecycle-superseded":
            LocalizedStringResource("A newer vault operation replaced this integrity check.")
        case "trust-state-unreadable":
            LocalizedStringResource("The vault integrity state is unreadable.")
        case "signer-root-missing":
            LocalizedStringResource(
                "The audit trust root is missing. The vault may have been changed or restored.")
        case "signer-root-unsealed":
            LocalizedStringResource(
                "The audit trust root could not be sealed. The vault remains quarantined.")
        case "anchor-floor-missing":
            LocalizedStringResource(
                "The replay counter is missing. The vault may have been changed or restored.")
        case "audit-recipient-swapped":
            LocalizedStringResource(
                "The audit recipient does not match the sealed identity. Audit encryption may have been redirected.")
        case "anchor-checkpoint-failed":
            LocalizedStringResource("The verified state could not be saved durably.")
        case "mutation-preflight-failed":
            LocalizedStringResource(
                "The integrity state could not advance. The configuration change was not applied.")
        case "mutation-partial":
            LocalizedStringResource("A failed configuration change modified integrity state.")
        case "mutation-checkpoint-failed":
            LocalizedStringResource("A configuration change could not be saved durably.")
        case "integrity-counter-invalid":
            LocalizedStringResource("The vault contains an invalid integrity counter.")
        case "signer-changed":
            LocalizedStringResource(
                "The audit signing key changed. Accept the current state to start a new audit chain.")
        case "anchor-missing":
            LocalizedStringResource(
                "The integrity anchor is missing, so the audit log and settings cannot be checked for rollback.")
        case "anchor-invalid":
            LocalizedStringResource("The integrity anchor contains invalid version or counter fields.")
        case "anchor-forged":
            LocalizedStringResource(
                "This vault's audit key did not sign the integrity anchor. It may have been replaced or corrupted.")
        case "anchor-rolled-back":
            LocalizedStringResource(
                "The integrity anchor is older than the vault's recorded counter. It may have been restored from a backup.")
        case "audit-rolled-back":
            LocalizedStringResource(
                "The audit log is older than its last known state. Later entries are missing or changed.")
        case "audit-unreadable":
            LocalizedStringResource("The audit journal cannot be read for the integrity check.")
        case "audit-untrusted":
            LocalizedStringResource("The audit log failed verification.")
        case "vault-rolled-back":
            LocalizedStringResource(
                "The vault database is older than its last known state. Deleted keys or old settings may have returned.")
        case "state-rolled-back":
            LocalizedStringResource(
                "The stored configuration does not match the signed integrity anchor. Sealed content may have been rolled back.")
        default:
            nil
        }
    }
}
