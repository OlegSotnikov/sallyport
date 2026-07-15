import SwiftUI
import SallyportKit

// MARK: - Error copy

/// Converts an error into text for a banner or toast.
func describe(_ error: Error) -> String {
    if let mgmt = error as? MgmtError { return mgmt.message }
    if let failure = error as? MgmtClient.Failure { return failure.errorDescription ?? "\(failure)" }
    return (error as? LocalizedError)?.errorDescription ?? "\(error)"
}

/// Detects errors that should be shown behind a technical-details disclosure.
private func looksTechnical(_ message: String) -> Bool {
    message.count > 90
        || message.contains("Error(")
        || message.contains("Decoding")
        || message.contains("{")
        || message.contains("Optional(")
}

// MARK: - Transient toast

/// A transient success or failure message.
struct Toast: Equatable, Identifiable {
    enum Kind { case success, failure }
    let id = UUID()
    var kind: Kind
    var text: String

    static func ok(_ text: String) -> Toast { Toast(kind: .success, text: text) }
    static func bad(_ text: String) -> Toast { Toast(kind: .failure, text: text) }
}

private struct ToastOverlay: ViewModifier {
    @Binding var toast: Toast?

    func body(content: Content) -> some View {
        content.overlay(alignment: .bottom) {
            if let toast {
                HStack(spacing: Theme.Spacing.sm) {
                    Image(systemName: toast.kind == .success ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                        .foregroundStyle(toast.kind == .success ? Theme.verified : Theme.danger)
                    Text(toast.text).font(.callout)
                }
                .padding(.horizontal, Theme.Spacing.lg).padding(.vertical, Theme.Spacing.md - 2)
                .background(.regularMaterial, in: Capsule())
                .overlay(Capsule().strokeBorder(Theme.Surface.stroke))
                .shadow(color: .black.opacity(0.18), radius: 12, y: 4)
                .padding(.bottom, Theme.Spacing.lg)
                .transition(.move(edge: .bottom).combined(with: .opacity))
                .task(id: toast.id) {
                    try? await Task.sleep(for: .seconds(2.4))
                    withAnimation { self.toast = nil }
                }
            }
        }
        .animation(.snappy, value: toast?.id)
    }
}

extension View {
    func toast(_ toast: Binding<Toast?>) -> some View { modifier(ToastOverlay(toast: toast)) }
}

// MARK: - Inline error card

/// An inline error with optional retry and technical details.
struct ErrorBanner: View {
    let message: String
    var onRetry: (() -> Void)?
    @State private var showDetail = false

    private var technical: Bool { looksTechnical(message) }
    private var headline: String { technical ? "Could not load data" : message }

    var body: some View {
        HStack(alignment: .top, spacing: Theme.Spacing.md) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(Theme.warning)
                .font(.title3)
            VStack(alignment: .leading, spacing: Theme.Spacing.xs) {
                Text(headline).font(.callout).fontWeight(.medium)
                if technical {
                    DisclosureGroup(isExpanded: $showDetail) {
                        // Limit long decoder output to the disclosure area.
                        ScrollView {
                            Text(message)
                                .font(Theme.Typography.monoSmall)
                                .foregroundStyle(.secondary)
                                .textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        .frame(maxHeight: 160)
                        .padding(.top, 2)
                    } label: {
                        Text("Technical details").font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
            Spacer(minLength: Theme.Spacing.sm)
            if let onRetry {
                Button("Retry", systemImage: "arrow.clockwise", action: onRetry)
                    .controlSize(.small)
            }
        }
        .padding(Theme.Spacing.md)
        .background(Theme.warning.opacity(0.08), in: RoundedRectangle(cornerRadius: Theme.Radius.lg, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: Theme.Radius.lg, style: .continuous).strokeBorder(Theme.warning.opacity(0.25)))
        .padding(.horizontal, Theme.screenPadding).padding(.top, Theme.Spacing.md)
    }
}

// MARK: - Management screen scaffold

/// Shared layout for management screens.
struct ManagementScaffold<Toolbar: View, Content: View>: View {
    let title: String
    let subtitle: String
    let symbol: String
    var isLoading: Bool = false
    var error: String?
    /// Replaces encrypted content with the locked-vault view.
    var locked: Bool = false
    var onUnlock: (() async -> Bool)?
    var onRefresh: (() -> Void)?
    @ViewBuilder var toolbar: () -> Toolbar
    @ViewBuilder var content: () -> Content

    var body: some View {
        VStack(spacing: 0) {
            ScreenHeader(title: title, subtitle: subtitle, symbol: symbol) {
                HStack(spacing: Theme.Spacing.sm) {
                    toolbar().disabled(locked)
                    if let onRefresh {
                        Button("Refresh", systemImage: "arrow.clockwise", action: onRefresh)
                            .labelStyle(.iconOnly)
                            .help("Refresh")
                            .disabled(isLoading || locked)
                    }
                }
            }
            Divider()
            if locked {
                LockedVaultView(onUnlock: onUnlock)
            } else {
                if let error {
                    ErrorBanner(message: error, onRetry: onRefresh)
                }
                // Keep child content below the header.
                Group {
                    if isLoading {
                        LoadingSkeleton()
                            .transition(.opacity)
                    } else {
                        content()
                            .transition(.opacity)
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .clipped()
            }
        }
        .animation(.easeOut(duration: 0.15), value: isLoading)
    }
}

/// Placeholder for management content while the vault is locked.
struct LockedVaultView: View {
    var onUnlock: (() async -> Bool)?
    @State private var unlocking = false

    var body: some View {
        VStack(spacing: Theme.Spacing.lg) {
            Image(systemName: "lock.fill")
                .font(.system(size: 34, weight: .medium))
                .foregroundStyle(.secondary)
            Text("The vault is locked")
                .font(.title3.weight(.semibold))
            Text("Names, hosts, settings, and history are encrypted. Unlock the vault to view them.")
                .font(.callout).foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 400)
            if let onUnlock {
                Button {
                    guard !unlocking else { return }
                    unlocking = true
                    Task { _ = await onUnlock(); unlocking = false }
                } label: {
                    Label("Unlock", systemImage: "touchid")
                }
                .buttonStyle(.borderedProminent)
                .disabled(unlocking)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

// MARK: - Reusable form fields

/// A form control with a right-aligned label and optional help text.
struct FormRow<Content: View>: View {
    let label: String
    var hint: String?
    /// Adds a visual marker and includes "required" in the accessibility label.
    var isRequired: Bool = false
    /// Replaces the hint after validation fails.
    var error: String?
    /// A non-blocking field warning.
    var warning: String?
    @ViewBuilder var content: () -> Content

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: Theme.Spacing.md) {
            HStack(spacing: 2) {
                Text(label)
                if isRequired {
                    Text("*")
                        .foregroundStyle(Theme.accent)
                        .accessibilityHidden(true)
                }
            }
            .font(.callout)
            .foregroundStyle(error == nil ? .secondary : Theme.danger)
            .frame(width: 116, alignment: .trailing)
            .accessibilityLabel(isRequired ? "\(label), required" : label)

            VStack(alignment: .leading, spacing: 3) {
                content()
                if let error {
                    Label(error, systemImage: "exclamationmark.circle.fill")
                        .font(.caption2).foregroundStyle(Theme.danger)
                        .fixedSize(horizontal: false, vertical: true)
                } else if let warning {
                    Label(warning, systemImage: "exclamationmark.triangle.fill")
                        .font(.caption2).foregroundStyle(Theme.warning)
                        .fixedSize(horizontal: false, vertical: true)
                } else if let hint {
                    Text(hint).font(.caption2).foregroundStyle(.tertiary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }
}

/// Adds a validation border without replacing the focusable control.
extension View {
    func invalidField(_ invalid: Bool) -> some View {
        overlay {
            RoundedRectangle(cornerRadius: 5, style: .continuous)
                .strokeBorder(invalid ? Theme.danger.opacity(0.85) : .clear, lineWidth: 1.5)
                .animation(.easeOut(duration: 0.15), value: invalid)
        }
    }
}

/// Editable list of short string tokens (tags, bind hosts, expose globs), shown
/// as removable chips with an inline add field.
struct TokenEditor: View {
    @Binding var tokens: [String]
    var placeholder: String
    @State private var draft = ""

    var body: some View {
        VStack(alignment: .leading, spacing: Theme.Spacing.sm) {
            if !tokens.isEmpty {
                FlowChips(tokens: tokens) { token in
                    tokens.removeAll { $0 == token }
                }
            }
            HStack(spacing: Theme.Spacing.sm) {
                TextField(placeholder, text: $draft)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit(add)
                Button("Add", action: add)
                    .disabled(draft.trimmingCharacters(in: .whitespaces).isEmpty)
                    .controlSize(.small)
            }
        }
    }

    private func add() {
        let value = draft.trimmingCharacters(in: .whitespaces)
        guard !value.isEmpty, !tokens.contains(value) else { draft = ""; return }
        tokens.append(value)
        draft = ""
    }
}

/// Wrapping row of removable chips.
struct FlowChips: View {
    let tokens: [String]
    var onRemove: (String) -> Void

    var body: some View {
        LazyVGrid(columns: [GridItem(.adaptive(minimum: 96), spacing: Theme.Spacing.sm, alignment: .leading)],
                  alignment: .leading, spacing: Theme.Spacing.sm) {
            ForEach(tokens, id: \.self) { token in
                HStack(spacing: Theme.Spacing.xs) {
                    Text(token).font(.caption).lineLimit(1)
                    Button {
                        onRemove(token)
                    } label: {
                        Image(systemName: "xmark.circle.fill").font(.caption2)
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(.secondary)
                }
                .padding(.horizontal, Theme.Spacing.sm).padding(.vertical, 3)
                .background(Theme.Surface.inset, in: Capsule())
            }
        }
    }
}

/// A small monospaced pill (name badges, versions).
struct MonoTag: View {
    let text: String
    var tint: Color = .secondary
    var body: some View {
        Text(text)
            .font(Theme.Typography.monoSmall)
            .padding(.horizontal, 6).padding(.vertical, 2)
            .background(tint.opacity(0.14), in: RoundedRectangle(cornerRadius: Theme.Radius.sm, style: .continuous))
            .foregroundStyle(tint)
    }
}

/// Shared layout for editor and detail sheets.
struct SheetScaffold<Content: View, Footer: View>: View {
    let title: String
    var systemImage: String = "square.and.pencil"
    var width: CGFloat = 480
    /// Scroll the body when it's taller than the sheet (long forms stay usable).
    var scrolls: Bool = true
    @ViewBuilder var content: () -> Content
    @ViewBuilder var footer: () -> Footer

    init(_ title: String, systemImage: String = "square.and.pencil", width: CGFloat = 480,
         scrolls: Bool = true,
         @ViewBuilder content: @escaping () -> Content,
         @ViewBuilder footer: @escaping () -> Footer = { EmptyView() }) {
        self.title = title
        self.systemImage = systemImage
        self.width = width
        self.scrolls = scrolls
        self.content = content
        self.footer = footer
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Label(title, systemImage: systemImage)
                .font(Theme.Typography.cardTitle)
                .padding(Theme.Spacing.xl)
                .padding(.bottom, 0)
            Divider()
            Group {
                if scrolls {
                    ScrollView { bodyStack }
                } else {
                    bodyStack
                }
            }
            Divider()
            footer()
                .padding(Theme.Spacing.xl)
        }
        .frame(width: width)
    }

    private var bodyStack: some View {
        VStack(alignment: .leading, spacing: Theme.Spacing.lg) {
            content()
        }
        .padding(Theme.Spacing.xl)
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// Sheet footer with cancel, primary action, and progress state.
struct SheetButtons: View {
    var saveTitle: String = "Save"
    var isBusy: Bool
    var isDisabled: Bool = false
    var onCancel: () -> Void
    var onSave: () -> Void

    var body: some View {
        HStack {
            Button("Cancel", role: .cancel, action: onCancel)
                .keyboardShortcut(.cancelAction)
            Spacer()
            Button(action: onSave) {
                HStack(spacing: Theme.Spacing.xs + 2) {
                    if isBusy { ProgressView().controlSize(.small) }
                    Text(saveTitle)
                }
                .frame(minWidth: 64)
            }
            .keyboardShortcut(.defaultAction)
            .buttonStyle(.borderedProminent)
            .disabled(isDisabled || isBusy)
        }
    }
}
