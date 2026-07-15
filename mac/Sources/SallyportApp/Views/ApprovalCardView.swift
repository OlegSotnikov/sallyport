import SwiftUI
import SallyportKit

/// Displays an approval request, its provenance, scope, and decision controls.
/// Provenance failures use the warning style.
struct ApprovalCardView: View {
    let request: ApprovalRequest
    let model: AppModel

    @State private var isProcessing = false
    @State private var showDetails = false

    private var badge: TrustBadge {
        // Origin-aware: the badge must go red if the requesting process itself
        // is unsigned, not only when an intermediate chain hop is.
        ProvenanceEvaluator.badge(for: request.provenance)
    }
    private var isIntact: Bool { badge.isVerified }
    private var isSession: Bool { request.mode.hasPrefix("session") }
    private var isPerCall: Bool { request.mode.hasPrefix("per-call") }
    private var needsTouchID: Bool { ApprovalRequest.biometricModes.contains(request.mode) }

    var body: some View {
        // Keep the request and controls visible. Put the rule and process chain
        // under Details.
        VStack(alignment: .leading, spacing: Theme.Spacing.md) {
            if !isIntact { warningStrip }
            if isIntact { modeStrip }
            OriginHeader(request: request)
            if isSession || isPerCall { signatureBanner }
            // A credential request collects the specific key in the next sheet.
            if request.action.tool != "sallyport.request_credential" { actionBlock }
            if isSession { sessionScopeNote }
            if isPerCall { perCallNote }
            buttonRow
            detailsDisclosure
        }
        .padding(Theme.Spacing.lg + 2)
        .frame(maxWidth: 460, alignment: .leading)
        .background(.background, in: RoundedRectangle(cornerRadius: Theme.Radius.xl, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: Theme.Radius.xl, style: .continuous)
                .strokeBorder(isIntact ? Theme.Surface.stroke : Theme.danger.opacity(0.7),
                              lineWidth: isIntact ? 1 : 2)
        )
        .shadow(color: .black.opacity(0.16), radius: 16, y: 6)
    }

    /// Describes the approval scope for requests with verified provenance.
    @ViewBuilder private var modeStrip: some View {
        switch request.mode {
        case "session":
            contextStrip(icon: "person.badge.shield.checkmark", tint: Theme.accent, title: "Approve this agent",
                         detail: "Session approval lasts until this process exits, you revoke it, or the vault locks. Per-call settings still apply.")
        case "session-touchid":
            contextStrip(icon: "touchid", tint: Theme.accent, title: "Approve this agent with Touch ID",
                         detail: "Requires Touch ID. Session approval lasts until this process exits, you revoke it, or the vault locks. Per-call settings still apply.")
        case "per-call":
            contextStrip(icon: "exclamationmark.lock.fill", tint: Theme.warning, title: "Per-call approval",
                         detail: "Approval covers this call only.")
        case "per-call-touchid", "strict":
            contextStrip(icon: "touchid", tint: Theme.warning, title: "Per-call approval with Touch ID",
                         detail: "This call requires Touch ID.")
        default:
            EmptyView()
        }
    }

    private func contextStrip(icon: String, tint: Color,
                              title: LocalizedStringResource,
                              detail: LocalizedStringResource) -> some View {
        HStack(alignment: .top, spacing: Theme.Spacing.sm) {
            Image(systemName: icon).foregroundStyle(tint)
            VStack(alignment: .leading, spacing: 1) {
                Text(title).font(.callout.weight(.semibold))
                Text(detail).font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, Theme.Spacing.md).padding(.vertical, Theme.Spacing.sm)
        .background(tint.opacity(0.08), in: RoundedRectangle(cornerRadius: Theme.Radius.md, style: .continuous))
    }

    /// Shows the executable's code-signing status and authority.
    private var signatureBanner: some View {
        let signed = request.provenance.origin.validSignature ?? false
        let authority = request.provenance.origin.signedBy ?? ""
        let tint = signed ? Theme.verified : Theme.danger
        return HStack(alignment: .top, spacing: Theme.Spacing.sm) {
            Image(systemName: signed ? "checkmark.seal.fill" : "exclamationmark.shield.fill")
                .foregroundStyle(tint).font(.title3)
            VStack(alignment: .leading, spacing: 2) {
                if signed {
                    Text("Valid code signature")
                        .font(.callout.weight(.semibold)).foregroundStyle(tint)
                } else {
                    Text("No valid code signature")
                        .font(.callout.weight(.semibold)).foregroundStyle(tint)
                }
                if !authority.isEmpty {
                    Text(verbatim: authority)
                        .font(.caption).foregroundStyle(.secondary)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                } else if signed {
                    Text("Signed")
                        .font(.caption).foregroundStyle(.secondary)
                } else {
                    Text("Approve only if you recognize this executable.")
                        .font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if let path = request.provenance.origin.path, !path.isEmpty {
                    Text(verbatim: path).font(Theme.Typography.monoSmall).foregroundStyle(.tertiary)
                        .lineLimit(1).truncationMode(.middle).textSelection(.enabled)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(Theme.Spacing.md - 2)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(tint.opacity(0.08), in: RoundedRectangle(cornerRadius: Theme.Radius.md, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: Theme.Radius.md, style: .continuous).strokeBorder(tint.opacity(0.22)))
    }

    /// Per-call approval applies to one action.
    private var perCallNote: some View {
        HStack(alignment: .top, spacing: Theme.Spacing.sm) {
            Image(systemName: "1.circle").foregroundStyle(.secondary)
            Text("Applies to this call. The next use asks again.")
                .font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
        .padding(.horizontal, Theme.Spacing.md).padding(.vertical, Theme.Spacing.sm)
        .background(Theme.Surface.inset, in: RoundedRectangle(cornerRadius: Theme.Radius.md, style: .continuous))
    }

    /// Session approval ends on process exit, revoke, or vault lock.
    private var sessionScopeNote: some View {
        HStack(alignment: .top, spacing: Theme.Spacing.sm) {
            Image(systemName: "clock.arrow.circlepath").foregroundStyle(.secondary)
            Text("Applies until this process exits, you revoke it, or the vault locks.")
                .font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
        .padding(.horizontal, Theme.Spacing.md).padding(.vertical, Theme.Spacing.sm)
        .background(Theme.Surface.inset, in: RoundedRectangle(cornerRadius: Theme.Radius.md, style: .continuous))
    }

    // Keep provenance failures visible without opening Details.
    private var warningStrip: some View {
        HStack(spacing: Theme.Spacing.sm) {
            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(Theme.danger)
            Text("Provenance not verified").font(.callout.weight(.semibold)).foregroundStyle(Theme.danger)
            Spacer()
            TrustBadgePill(badge: badge)
        }
        .padding(.horizontal, Theme.Spacing.md).padding(.vertical, Theme.Spacing.sm)
        .background(Theme.danger.opacity(0.08), in: RoundedRectangle(cornerRadius: Theme.Radius.md, style: .continuous))
    }

    // The rule and process chain are available on demand.
    private var detailsDisclosure: some View {
        DisclosureGroup(isExpanded: $showDetails) {
            VStack(alignment: .leading, spacing: Theme.Spacing.md - 2) {
                whyLine
                ProcessChainView(chain: request.provenance.chain)
            }
            .padding(.top, Theme.Spacing.sm)
            .frame(maxWidth: .infinity, alignment: .leading)
        } label: {
            Text("Details").font(.caption.weight(.medium)).foregroundStyle(.secondary)
        }
        .tint(.secondary)
    }

    private var actionBlock: some View {
        VStack(alignment: .leading, spacing: Theme.Spacing.sm) {
            toolLabel
                .font(.caption).fontWeight(.semibold)
                .foregroundStyle(.secondary)
            HStack(alignment: .top, spacing: Theme.Spacing.sm) {
                Text(verbatim: request.action.channel == "ssh" ? "$" : "▸")
                    .font(Theme.mono).foregroundStyle(.tertiary)
                Text(highlightedCommand)
                    .font(Theme.mono)
                    .textSelection(.enabled)
            }
            .padding(Theme.Spacing.md - 2)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Theme.Surface.inset, in: RoundedRectangle(cornerRadius: Theme.Radius.md, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: Theme.Radius.md, style: .continuous).strokeBorder(Theme.Surface.stroke))

            if let body = request.action.bodyPreview,
               request.action.channel != "ssh", !body.isEmpty {
                Text(verbatim: body)
                    .font(Theme.Typography.monoSmall)
                    .foregroundStyle(.secondary)
                    .lineLimit(3)
                    .padding(.leading, 2)
            }
        }
    }

    private var whyLine: some View {
        let reason = ApprovalCopy.reason(request.why.reason)
        return HStack(alignment: .firstTextBaseline, spacing: Theme.Spacing.xs + 2) {
            Image(systemName: "info.circle").foregroundStyle(.secondary).font(.callout)
            (Text("Why: ").fontWeight(.medium)
             + Text("Rule ").foregroundStyle(.secondary)
             + Text(verbatim: "`\(request.why.rule)`").font(.callout.monospaced())
             + Text(verbatim: " · \(reason)").foregroundStyle(.secondary))
                .font(.callout)
                .lineLimit(2)
        }
    }


    private var buttonRow: some View {
        HStack(spacing: Theme.Spacing.md) {
            Button(role: .destructive) {
                Task { await model.deny(request) }
            } label: {
                Text("Deny").frame(maxWidth: .infinity)
            }
            .keyboardShortcut(.cancelAction)
            .controlSize(.large)

            Button {
                approve()
            } label: {
                HStack(spacing: Theme.Spacing.xs + 2) {
                    if isProcessing {
                        ProgressView().controlSize(.small)
                    } else if needsTouchID {
                        // Only biometric approval modes require Touch ID here.
                        Image(systemName: "touchid")
                    } else if isSession {
                        Image(systemName: "person.badge.shield.checkmark")
                    }
                    Text(approveLabel)
                }
                .frame(maxWidth: .infinity)
            }
            .keyboardShortcut(.defaultAction)
            .controlSize(.large)
            .buttonStyle(.borderedProminent)
            .disabled(isProcessing)
        }
        .padding(.top, Theme.Spacing.xxs)
    }

    private var approveLabel: LocalizedStringResource {
        if isProcessing { return "Authorizing…" }
        if isSession { return "Approve agent" }
        if isPerCall { return "Approve call" }
        return "Approve"
    }

    private var toolLabel: Text {
        switch request.action.tool {
        case "http.request": Text("HTTP request")
        case "ssh.exec": Text("SSH command")
        case "sallyport.request_credential": Text("Credential request")
        default: Text(verbatim: request.action.tool)
        }
    }

    private func approve() {
        isProcessing = true
        Task {
            await model.approve(request)
            isProcessing = false
        }
    }

    /// The command with danger tokens highlighted red.
    private var highlightedCommand: AttributedString {
        let text = ApprovalCopy.actionText(request.action)
        var attributed = AttributedString(text)
        for range in ApprovalPresentation.dangerRanges(in: text, tokens: request.action.dangerTokens) {
            let lower = text.distance(from: text.startIndex, to: range.lowerBound)
            let upper = text.distance(from: text.startIndex, to: range.upperBound)
            let attrLower = attributed.index(attributed.startIndex, offsetByCharacters: lower)
            let attrUpper = attributed.index(attributed.startIndex, offsetByCharacters: upper)
            attributed[attrLower..<attrUpper].foregroundColor = Theme.danger
            attributed[attrLower..<attrUpper].inlinePresentationIntent = .stronglyEmphasized
        }
        return attributed
    }
}

#if DEBUG
private struct ApprovalCardGallery: View {
    var body: some View {
        ScrollView {
            VStack(spacing: Theme.Spacing.lg) {
                ApprovalCardView(request: Fixtures.sessionClaude, model: AppModel.previewModel())
                ApprovalCardView(request: Fixtures.sessionUnsigned, model: AppModel.previewModel())
                ApprovalCardView(request: Fixtures.sshRestartNginx, model: AppModel.previewModel())
                ApprovalCardView(request: Fixtures.sshTampered, model: AppModel.previewModel())
                ApprovalCardView(request: Fixtures.httpCloudflareDNS, model: AppModel.previewModel())
            }
            .padding(Theme.Spacing.xl)
        }
    }
}

#if !SP_NO_PREVIEWS
#Preview("Approval cards (light)") {
    ApprovalCardGallery().frame(width: 520, height: 720).preferredColorScheme(.light)
}

#Preview("Approval cards (dark)") {
    ApprovalCardGallery().frame(width: 520, height: 720).preferredColorScheme(.dark)
}
#endif
#endif
