import SwiftUI
import AppKit
import SallyportKit

/// Creates a vault, starts the local agent connection, and verifies the first call.
struct SetupView: View {
    @Bindable var model: AppModel

    /// The step whose action is currently running.
    @State private var runningStep: Int?
    @State private var toast: Toast?

    private var steps: [Bool] {
        [model.onboarding.vaultCreated,
         model.onboarding.agentInstalled,
         model.onboarding.agentConnected]
    }
    private var doneCount: Int { steps.filter { $0 }.count }
    /// The first incomplete step.
    private var activeIndex: Int? { steps.firstIndex(of: false) }

    var body: some View {
        VStack(spacing: 0) {
            ScreenHeader(
                title: LocalizedStringResource("Setup"),
                subtitle: LocalizedStringResource("Create a vault and connect an agent."),
                symbol: Theme.gateCalm
            ) {
                StatusPill(verbatim: "\(doneCount) / 3",
                           systemImage: model.onboarding.allDone ? "checkmark.seal.fill" : "circle.dashed",
                           tint: model.onboarding.allDone ? Theme.verified : Theme.accent)
            }
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: Theme.Spacing.lg) {
                    progressCard
                    stepsCard
                    finishCard
                }
                .frame(maxWidth: 720)
                .frame(maxWidth: .infinity)
                .padding(Theme.screenPadding)
            }
        }
        .toast($toast)
        .task { model.refreshOnboardingState() }
    }

    /// Creates a vault and archives incompatible existing files.
    private func createVault() {
        guard runningStep == nil else { return }
        runningStep = 0
        Task {
            do {
                try await model.ensureVaultCreated()
                toast = .ok(model.backend == .secureEnclave
                            ? String(localized: "Vault created with Secure Enclave and Touch ID protection.")
                            : String(localized: "Vault ready."))
            } catch { toast = .bad(describe(error)) }
            runningStep = nil
        }
    }

    private var progressCard: some View {
        Card {
            HStack(alignment: .center, spacing: Theme.Spacing.md) {
                Image(systemName: Theme.gateCalm)
                    .font(.system(size: 26))
                    .foregroundStyle(Theme.accent)
                    .frame(width: 34)
                VStack(alignment: .leading, spacing: 2) {
                    Text(progressTitle)
                        .font(.headline)
                    Text(progressDetail)
                        .font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer()
            }
            ProgressPips(total: 3, done: doneCount)
        }
    }

    private var stepsCard: some View {
        Card(spacing: 0) {
            SetupStep(
                number: 1, title: LocalizedStringResource("Create vault"),
                subtitle: createSubtitle,
                done: model.onboarding.vaultCreated,
                isActive: activeIndex == 0,
                inProgress: runningStep == 0,
                actionTitle: LocalizedStringResource("Create")
            ) {
                createVault()
            }

            Divider().padding(.vertical, Theme.Spacing.xs)

            SetupStep(
                number: 2, title: LocalizedStringResource("Start Sallyport"),
                subtitle: LocalizedStringResource("Starts the local agent socket and vault service in this app."),
                done: model.onboarding.agentInstalled,
                isActive: activeIndex == 1,
                actionTitle: LocalizedStringResource("Start")
            ) { model.connect() }

            Divider().padding(.vertical, Theme.Spacing.xs)

            SetupStep(
                number: 3, title: LocalizedStringResource("Connect your agent"),
                subtitle: connectSubtitle,
                done: model.onboarding.agentConnected,
                isActive: activeIndex == 2,
                actionTitle: LocalizedStringResource("Integrations")
            ) { model.selectedTab = .integrations }
        }
    }

    private var createSubtitle: LocalizedStringResource {
        if model.runtime.incompatibleVault {
            return LocalizedStringResource(
                "An incompatible vault was found. Creating a new vault archives the old files.")
        }
        if model.backend == .secureEnclave {
            return LocalizedStringResource(
                "Secure Enclave and Touch ID gate vault unlock. There is no recovery if the Secure Enclave key is lost.")
        }
        return LocalizedStringResource("This development build stores the vault key in software.")
    }

    private var finishCard: some View {
        HStack(spacing: Theme.Spacing.md) {
            if model.onboarding.allDone {
                Label("Setup complete.", systemImage: "checkmark.seal.fill")
                    .font(.callout).foregroundStyle(Theme.verified)
            } else {
                Text(finishProgress)
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
            Button("Done") { model.selectedTab = .approvals }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .disabled(!model.onboarding.allDone)
        }
    }

    private var connectSubtitle: LocalizedStringResource {
        if model.onboarding.agentConnected {
            return LocalizedStringResource("An agent has completed its first call.")
        }
        switch model.connection {
        case .connected:
            return LocalizedStringResource(
                "Copy the integration snippet for your client. This step completes after the first agent call.")
        case .connecting:
            return LocalizedStringResource("Starting Sallyport…")
        case .waiting, .disconnected:
            return LocalizedStringResource("Create the vault first. The agent socket starts after that.")
        }
    }

    private var progressTitle: LocalizedStringResource {
        model.onboarding.allDone
            ? LocalizedStringResource("Setup complete")
            : LocalizedStringResource("Set up Sallyport")
    }

    private var progressDetail: LocalizedStringResource {
        guard !model.onboarding.allDone else {
            return LocalizedStringResource("All three steps are done.")
        }
        let count = doneCount
        return LocalizedStringResource(
            "\(count) of 3 complete. Continue with the highlighted step.",
            comment: "Setup progress. The first number is the completed step count.")
    }

    private var finishProgress: LocalizedStringResource {
        let count = doneCount
        return LocalizedStringResource(
            "\(count) of 3 complete",
            comment: "Compact setup progress. The first number is the completed step count.")
    }
}

/// Segmented progress for setup steps.
private struct ProgressPips: View {
    let total: Int
    let done: Int
    var body: some View {
        HStack(spacing: Theme.Spacing.sm) {
            ForEach(0..<total, id: \.self) { i in
                RoundedRectangle(cornerRadius: 3, style: .continuous)
                    .fill(i < done ? Theme.verified : Color.primary.opacity(0.12))
                    .frame(maxWidth: .infinity)
                    .frame(height: 5)
                    .animation(.easeOut(duration: 0.25), value: done)
            }
        }
    }
}

/// One setup step and its current state.
private struct SetupStep: View {
    let number: Int
    let title: LocalizedStringResource
    let subtitle: LocalizedStringResource
    let done: Bool
    let isActive: Bool
    var inProgress: Bool = false
    let actionTitle: LocalizedStringResource
    /// Optional secondary action available after completion.
    var doneActionTitle: LocalizedStringResource? = nil
    let action: () -> Void

    var body: some View {
        HStack(alignment: .center, spacing: Theme.Spacing.md) {
            ZStack {
                Circle()
                    .fill(done ? Theme.verified.opacity(0.15)
                          : (isActive ? Theme.accent.opacity(0.14) : Color.primary.opacity(0.08)))
                    .frame(width: 30, height: 30)
                if isActive && !done {
                    Circle().strokeBorder(Theme.accent.opacity(0.5), lineWidth: 1.5).frame(width: 30, height: 30)
                }
                if done {
                    Image(systemName: "checkmark").foregroundStyle(Theme.verified).fontWeight(.bold)
                } else {
                    Text(verbatim: "\(number)").fontWeight(.semibold)
                        .foregroundStyle(isActive ? Theme.accent : .secondary)
                }
            }
            .frame(width: 30, height: 30)

            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.headline)
                Text(subtitle).font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .layoutPriority(1)

            Spacer(minLength: Theme.Spacing.sm)

            trailing.fixedSize(horizontal: true, vertical: false)
        }
        .padding(.horizontal, Theme.Spacing.md)
        .padding(.vertical, Theme.Spacing.md)
    }

    @ViewBuilder private var trailing: some View {
        if done {
            HStack(spacing: Theme.Spacing.sm) {
                Label("Done", systemImage: "checkmark.circle.fill")
                    .foregroundStyle(Theme.verified).labelStyle(.titleAndIcon).font(.caption)
                if let doneActionTitle {
                    Button(doneActionTitle, action: action)
                        .buttonStyle(.bordered).controlSize(.small)
                }
            }
        } else if isActive {
            Button(action: action) { actionLabel }
                .buttonStyle(.borderedProminent).controlSize(.regular).disabled(inProgress)
        } else {
            Button(action: action) { actionLabel }
                .buttonStyle(.bordered).controlSize(.regular).disabled(inProgress)
        }
    }

    @ViewBuilder private var actionLabel: some View {
        if inProgress {
            HStack(spacing: Theme.Spacing.xs + 2) {
                ProgressView().controlSize(.small)
                Text(actionTitle)
            }
        } else {
            Text(actionTitle)
        }
    }
}



#if DEBUG && !SP_NO_PREVIEWS
#Preview("Onboarding fresh (light)") {
    let model = AppModel.previewModel()
    model.onboarding = OnboardingState()   // nothing done yet
    return SetupView(model: model)
        .frame(width: 820, height: 560)
        .preferredColorScheme(.light)
}

#if !SP_NO_PREVIEWS
#Preview("Onboarding in progress (dark)") {
    let model = AppModel.previewModel()
    model.onboarding = OnboardingState(agentInstalled: true, vaultCreated: false, agentConnected: false)
    return SetupView(model: model)
        .frame(width: 820, height: 560)
        .preferredColorScheme(.dark)
}

#Preview("Onboarding complete (dark)") {
    let model = AppModel.previewModel()
    model.onboarding = OnboardingState(agentInstalled: true, vaultCreated: true, agentConnected: true)
    return SetupView(model: model)
        .frame(width: 820, height: 560)
        .preferredColorScheme(.dark)
}

#Preview("Onboarding minimum size") {
    let model = AppModel.previewModel()
    model.onboarding = OnboardingState()
    return SetupView(model: model)
        .frame(width: 520, height: 420)
}
#endif

#endif
