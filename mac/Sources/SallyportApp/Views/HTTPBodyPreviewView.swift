import SwiftUI

/// A bounded, selectable preview of the agent-supplied HTTP request body.
/// The engine supplies this only when the user is deciding a per-call action.
struct HTTPBodyPreviewView: View {
    let preview: String
    let originalByteCount: Int
    let truncated: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: Theme.Spacing.sm) {
            HStack(alignment: .firstTextBaseline, spacing: Theme.Spacing.sm) {
                Label("Request body", systemImage: "doc.plaintext")
                    .font(.caption.weight(.semibold))
                Spacer(minLength: Theme.Spacing.sm)
                Text(verbatim: ApprovalCopy.httpBodyMetadata(
                    byteCount: originalByteCount,
                    truncated: truncated))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            ScrollView(.vertical) {
                Text(verbatim: preview)
                    .font(Theme.Typography.monoSmall)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .frame(maxHeight: 180)
        }
        .padding(Theme.Spacing.md - 2)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Theme.Surface.inset,
                    in: RoundedRectangle(cornerRadius: Theme.Radius.md))
        .overlay(
            RoundedRectangle(cornerRadius: Theme.Radius.md)
                .strokeBorder(Theme.Surface.stroke)
        )
    }
}
