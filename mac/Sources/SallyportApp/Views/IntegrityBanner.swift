import SwiftUI

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
                Text(issue.message)
                    .font(.callout)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack(spacing: Theme.Spacing.md) {
                Button {
                    isBusy = true
                    Task { await model.readoptIntegrity(); isBusy = false }
                } label: {
                    Label("Accept current state (Touch ID)", systemImage: "touchid")
                }
                .disabled(isBusy)
                Text("Accept only if you restored a backup or reset this Mac. Otherwise, treat every stored key as exposed and rotate it.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(Theme.Spacing.lg)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Theme.danger.opacity(0.10))
    }
}
