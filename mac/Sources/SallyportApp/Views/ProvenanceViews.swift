import SwiftUI
import SallyportKit

/// Displays the process-chain verification result.
struct TrustBadgePill: View {
    let badge: TrustBadge

    var body: some View {
        Label {
            Text(localizedLabel).font(.caption).fontWeight(.semibold)
        } icon: {
            Image(systemName: badge.symbol).font(.caption)
        }
        .labelStyle(.titleAndIcon)
        .padding(.horizontal, Theme.Spacing.sm + 1)
        .padding(.vertical, 4)
        .background(badge.tint.opacity(0.14), in: Capsule())
        .overlay(Capsule().strokeBorder(badge.tint.opacity(0.22)))
        .foregroundStyle(badge.tint)
        .accessibilityLabel(Text(localizedLabel))
    }

    private var localizedLabel: LocalizedStringResource {
        switch badge {
        case .verified:
            LocalizedStringResource("Verified")
        case .unsignedInChain(let hopName, _):
            LocalizedStringResource(
                "Unsigned: \(hopName)",
                comment: "Code-signature warning followed by a process name.")
        case .unknown:
            LocalizedStringResource("Verifying…")
        }
    }
}

/// Expandable process chain with code-signature status for each process.
struct ProcessChainView: View {
    let chain: [ProcessHop]
    @State private var expanded = false
    @State private var hovering = false

    var body: some View {
        VStack(alignment: .leading, spacing: Theme.Spacing.sm) {
            Button {
                withAnimation(.snappy) { expanded.toggle() }
            } label: {
                HStack(spacing: Theme.Spacing.xs + 2) {
                    Image(systemName: "point.3.filled.connected.trianglepath.dotted")
                        .foregroundStyle(.secondary)
                    Text(verbatim: ProvenanceEvaluator.chainSummary(chain))
                        .font(.callout)
                        .foregroundStyle(.primary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Spacer(minLength: Theme.Spacing.xs)
                    Image(systemName: expanded ? "chevron.up" : "chevron.down")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                .padding(.horizontal, Theme.Spacing.sm)
                .padding(.vertical, Theme.Spacing.xs + 2)
                .background(
                    RoundedRectangle(cornerRadius: Theme.Radius.md, style: .continuous)
                        .fill(hovering ? Theme.Surface.hover : .clear)
                )
                .contentShape(RoundedRectangle(cornerRadius: Theme.Radius.md, style: .continuous))
            }
            .buttonStyle(.plain)
            .accessibilityLabel(Text(chainToggleLabel))
            .onHover { hovering = $0 }
            .animation(.easeOut(duration: 0.12), value: hovering)

            if expanded {
                VStack(alignment: .leading, spacing: Theme.Spacing.xs + 2) {
                    ForEach(Array(chain.enumerated()), id: \.element.id) { index, hop in
                        HopRow(hop: hop, isOrigin: index == 0)
                    }
                }
                .padding(Theme.Spacing.md - 2)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Theme.Surface.inset, in: RoundedRectangle(cornerRadius: Theme.Radius.md, style: .continuous))
                .transition(.opacity.combined(with: .move(edge: .top)))
            }
        }
    }

    private var chainToggleLabel: LocalizedStringResource {
        expanded
            ? LocalizedStringResource("Hide process chain")
            : LocalizedStringResource("Show process chain")
    }
}

private struct HopRow: View {
    let hop: ProcessHop
    let isOrigin: Bool

    var body: some View {
        HStack(spacing: Theme.Spacing.sm) {
            Image(systemName: signatureSymbol)
                .foregroundStyle(signatureTint)
                .font(.caption)
                .frame(width: 14)
            Text(verbatim: hop.appName ?? hop.name)
                .font(.callout)
                .fontWeight(isOrigin ? .semibold : .regular)
                .lineLimit(1)
                .truncationMode(.middle)
            Text(verbatim: "pid \(hop.pid)")
                .font(.caption2)
                .foregroundStyle(.tertiary)
            Spacer()
            Text(signatureText)
                .font(.caption2.weight(.medium))
                .foregroundStyle(signatureTint)
                .fixedSize(horizontal: true, vertical: false)
        }
    }

    private var signatureSymbol: String {
        switch hop.validSignature {
        case .some(true): return "checkmark.seal.fill"
        case .some(false): return "xmark.seal.fill"
        case .none: return "questionmark.seal"
        }
    }
    private var signatureTint: Color {
        switch hop.validSignature {
        case .some(true): return Theme.verified
        case .some(false): return Theme.danger
        case .none: return .secondary
        }
    }
    private var signatureText: LocalizedStringResource {
        switch hop.validSignature {
        case .some(true): return LocalizedStringResource("Signed")
        case .some(false): return LocalizedStringResource("Unsigned")
        case .none: return LocalizedStringResource("Unknown")
        }
    }
}

/// Requesting application, action, and target.
struct OriginHeader: View {
    let request: ApprovalRequest

    var body: some View {
        HStack(alignment: .center, spacing: Theme.Spacing.md) {
            iconView
                .frame(width: 40, height: 40)
            VStack(alignment: .leading, spacing: 2) {
                Text(verbatim: request.provenance.origin.appName ?? request.provenance.origin.name)
                    .font(Theme.Typography.screenTitle)
                    .lineLimit(2)
                    .truncationMode(.middle)
                if request.action.tool == "sallyport.request_credential" {
                    // The specific credential is collected in the next sheet.
                    Text("Requests a credential")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                } else if let host = request.action.host, !host.isEmpty {
                    Text(LocalizedStringResource(
                        "Target: \(host)",
                        comment: "Approval target followed by a host name."))
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                } else {
                    Text(LocalizedStringResource(
                        "Action: \(localizedToolLabel)",
                        comment: "Approval action followed by a localized tool name or protocol identifier."))
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
            }
            .layoutPriority(1)
            Spacer()
        }
    }

    private var localizedToolLabel: String {
        switch request.action.tool {
        case "http.request": String(localized: "HTTP request")
        case "ssh.exec": String(localized: "SSH command")
        case "sallyport.request_credential": String(localized: "Credential request")
        default: request.action.tool
        }
    }

    @ViewBuilder private var iconView: some View {
        if let nsImage = AppIconResolver.icon(forPID: request.provenance.origin.pid) {
            Image(nsImage: nsImage).resizable().scaledToFit()
        } else {
            Image(systemName: "terminal.fill")
                .resizable().scaledToFit()
                .padding(8)
                .foregroundStyle(Theme.accent)
                .background(Theme.accent.opacity(0.12), in: RoundedRectangle(cornerRadius: Theme.Radius.md, style: .continuous))
        }
    }
}
