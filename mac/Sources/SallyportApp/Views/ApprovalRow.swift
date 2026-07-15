import SwiftUI
import SallyportKit

/// A pending approval row with compact actions and expandable request details.
/// Provenance failures remain visible while the row is collapsed.
struct ApprovalRow: View {
    let request: ApprovalRequest
    let model: AppModel

    @State private var expanded: Bool
    @State private var isProcessing = false

    /// The caller may expand a single pending request by default.
    init(request: ApprovalRequest, model: AppModel, startsExpanded: Bool = false) {
        self.request = request
        self.model = model
        _expanded = State(initialValue: startsExpanded)
    }

    private var badge: TrustBadge { ProvenanceEvaluator.badge(for: request.provenance) }
    private var isIntact: Bool { badge.isVerified }
    private var isSession: Bool { request.mode.hasPrefix("session") }
    private var isPerCall: Bool { request.mode.hasPrefix("per-call") }
    private var needsTouchID: Bool { ApprovalRequest.biometricModes.contains(request.mode) }
    private var origin: String { request.provenance.origin.appName ?? request.provenance.origin.name }
    private var summary: String { ApprovalCopy.actionText(request.action) }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            if expanded {
                detail
                    .padding(.top, Theme.Spacing.md)
                    .transition(.opacity.combined(with: .move(edge: .top)))
            }
        }
        .padding(Theme.Spacing.md)
        .background(Theme.Surface.card, in: RoundedRectangle(cornerRadius: Theme.Radius.lg, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: Theme.Radius.lg, style: .continuous)
                .strokeBorder(isIntact ? Theme.Surface.stroke : Theme.danger.opacity(0.65),
                              lineWidth: isIntact ? 1 : 1.5)
        )
    }

    // MARK: - Header

    private var header: some View {
        HStack(spacing: Theme.Spacing.sm) {
            icon.frame(width: 30, height: 30)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 5) {
                    Text(verbatim: origin).font(.callout.weight(.semibold)).lineLimit(1)
                    if !isIntact {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .font(.caption2).foregroundStyle(Theme.danger)
                    }
                }
                Text(verbatim: summary)
                    .font(Theme.Typography.monoSmall)
                    .foregroundStyle(.secondary)
                    .lineLimit(1).truncationMode(.middle)
            }
            Spacer(minLength: Theme.Spacing.sm)
            if !expanded { compactButtons }
            Button {
                withAnimation(.snappy(duration: 0.18)) { expanded.toggle() }
            } label: {
                Image(systemName: expanded ? "chevron.up" : "chevron.down")
                    .font(.caption).foregroundStyle(.secondary)
                    .frame(width: 22, height: 22).contentShape(Rectangle())
            }
            .buttonStyle(.plain)
        }
        .contentShape(Rectangle())
        .onTapGesture { withAnimation(.snappy(duration: 0.18)) { expanded.toggle() } }
        .accessibilityAddTraits(.isButton)
        .accessibilityHint(expanded
                           ? String(localized: "Collapse details")
                           : String(localized: "Expand details"))
    }

    @ViewBuilder private var icon: some View {
        if let ns = AppIconResolver.icon(forPID: request.provenance.origin.pid) {
            Image(nsImage: ns).resizable().scaledToFit()
        } else {
            Image(systemName: request.action.channel == "ssh" ? "terminal.fill" : "globe")
                .resizable().scaledToFit().padding(6)
                .foregroundStyle(Theme.accent)
                .background(Theme.accent.opacity(0.12),
                            in: RoundedRectangle(cornerRadius: Theme.Radius.sm, style: .continuous))
        }
    }

    /// Actions shown while the row is collapsed.
    private var compactButtons: some View {
        HStack(spacing: Theme.Spacing.xs + 2) {
            Button("Deny", role: .destructive) { Task { await model.deny(request) } }
                .controlSize(.small).disabled(isProcessing)
            Button { approve() } label: {
                if isProcessing {
                    ProgressView().controlSize(.small)
                } else if needsTouchID {
                    if isSession {
                        Label("Approve agent", systemImage: "touchid").labelStyle(.titleAndIcon)
                    } else {
                        Label("Approve call", systemImage: "touchid").labelStyle(.titleAndIcon)
                    }
                } else if isPerCall {
                    Label("Approve call", systemImage: "1.circle").labelStyle(.titleAndIcon)
                } else if isSession {
                    Label("Approve agent", systemImage: "person.badge.shield.checkmark").labelStyle(.titleAndIcon)
                } else {
                    Text("Approve")
                }
            }
            .controlSize(.small).buttonStyle(.borderedProminent).disabled(isProcessing)
        }
    }

    // MARK: - Expanded detail

    private var detail: some View {
        VStack(alignment: .leading, spacing: Theme.Spacing.md) {
            if let host = request.action.host, !host.isEmpty {
                Text("Target: \(host)").font(.caption).foregroundStyle(.secondary)
            }
            if isSession || isPerCall { sessionSignatureLine }
            commandBlock
            if let body = request.action.bodyPreview,
               request.action.channel != "ssh", !body.isEmpty {
                Text(verbatim: body).font(Theme.Typography.monoSmall)
                    .foregroundStyle(.secondary).lineLimit(4)
            }
            if isSession { sessionNote }
            if isPerCall { perCallNote }
            whyLine
            ProcessChainView(chain: request.provenance.chain)
            expandedButtons
        }
    }

    private var commandBlock: some View {
        HStack(alignment: .top, spacing: Theme.Spacing.sm) {
            Text(verbatim: request.action.channel == "ssh" ? "$" : "▸")
                .font(Theme.mono).foregroundStyle(.tertiary)
            Text(highlightedCommand).font(Theme.mono).textSelection(.enabled)
        }
        .padding(Theme.Spacing.sm)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Theme.Surface.inset, in: RoundedRectangle(cornerRadius: Theme.Radius.md, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: Theme.Radius.md, style: .continuous).strokeBorder(Theme.Surface.stroke))
    }


    /// Shows the executable's code-signing authority for scoped approvals.
    private var sessionSignatureLine: some View {
        let signed = request.provenance.origin.validSignature ?? false
        let authority = request.provenance.origin.signedBy ?? ""
        let tint = signed ? Theme.verified : Theme.danger
        return HStack(spacing: Theme.Spacing.xs + 2) {
            Image(systemName: signed ? "checkmark.seal.fill" : "exclamationmark.shield.fill")
                .foregroundStyle(tint)
            if !authority.isEmpty {
                Text(verbatim: authority)
                    .font(.caption.weight(.medium)).foregroundStyle(signed ? .primary : tint)
                    .lineLimit(2).truncationMode(.middle).textSelection(.enabled)
            } else if signed {
                Text("Signed").font(.caption.weight(.medium))
            } else {
                Text("Unsigned executable")
                    .font(.caption.weight(.medium)).foregroundStyle(tint)
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, Theme.Spacing.sm).padding(.vertical, Theme.Spacing.xs)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(tint.opacity(0.08), in: RoundedRectangle(cornerRadius: Theme.Radius.sm, style: .continuous))
    }

    private var sessionNote: some View {
        Text("Session approval lasts until this process exits, you revoke it, or the vault locks. Per-call settings still apply.")
            .font(.caption2).foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
    }

    private var perCallNote: some View {
        Text("Applies to this call. The next use asks again.")
            .font(.caption2).foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
    }

    private var whyLine: some View {
        let reason = ApprovalCopy.reason(request.why.reason)
        return (Text("Why: ").fontWeight(.medium)
                + Text("Rule ").foregroundStyle(.secondary)
                + Text(verbatim: request.why.rule).font(.caption.monospaced())
                + Text(verbatim: " · \(reason)").foregroundStyle(.secondary))
            .font(.caption).lineLimit(3)
    }

    private var expandedButtons: some View {
        HStack(spacing: Theme.Spacing.md) {
            Button(role: .destructive) { Task { await model.deny(request) } } label: {
                Text("Deny").frame(maxWidth: .infinity)
            }
            .keyboardShortcut(.cancelAction).controlSize(.large)
            Button { approve() } label: {
                HStack(spacing: Theme.Spacing.xs + 2) {
                    if isProcessing { ProgressView().controlSize(.small) }
                    else if needsTouchID { Image(systemName: "touchid") }
                    else if isSession { Image(systemName: "person.badge.shield.checkmark") }
                    Text(approveLabel)
                }
                .frame(maxWidth: .infinity)
            }
            .keyboardShortcut(.defaultAction)
            .controlSize(.large).buttonStyle(.borderedProminent).disabled(isProcessing)
        }
    }

    private func approve() {
        isProcessing = true
        Task {
            await model.approve(request)
            isProcessing = false
        }
    }

    private var approveLabel: LocalizedStringResource {
        if isProcessing { return "Authorizing…" }
        if isSession { return "Approve agent" }
        if isPerCall { return "Approve call" }
        return "Approve"
    }

    /// The command with danger tokens highlighted red.
    private var highlightedCommand: AttributedString {
        let text = ApprovalCopy.actionText(request.action)
        var attributed = AttributedString(text)
        for range in ApprovalPresentation.dangerRanges(in: text, tokens: request.action.dangerTokens) {
            let lower = text.distance(from: text.startIndex, to: range.lowerBound)
            let upper = text.distance(from: text.startIndex, to: range.upperBound)
            let l = attributed.index(attributed.startIndex, offsetByCharacters: lower)
            let u = attributed.index(attributed.startIndex, offsetByCharacters: upper)
            attributed[l..<u].foregroundColor = Theme.danger
            attributed[l..<u].inlinePresentationIntent = .stronglyEmphasized
        }
        return attributed
    }
}
