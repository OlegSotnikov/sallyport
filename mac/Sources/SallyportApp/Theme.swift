import SwiftUI
import AppKit
import SallyportKit

/// Shared colors, spacing, typography, and reusable UI components.
enum Theme {

    // MARK: Gate glyphs
    // Gate state symbols.
    static let gateCalm = "shield.lefthalf.filled"
    static let gateWaiting = "exclamationmark.shield.fill"
    static let gateLocked = "lock.shield.fill"

    // MARK: Semantic colors
    /// Fixed blue used where state must remain visible in inactive windows.
    static let accent = Color(light: Color(red: 0.00, green: 0.48, blue: 1.00),
                              dark: Color(red: 0.04, green: 0.52, blue: 1.00))
    static let danger = Color(red: 0.84, green: 0.22, blue: 0.24)
    static let verified = Color(red: 0.18, green: 0.64, blue: 0.34)
    static let success = verified
    static let warning = Color(red: 0.90, green: 0.60, blue: 0.10)

    // MARK: Spacing scale
    // Shared 2/4/8/12/16/20/24 spacing scale.
    enum Spacing {
        static let xxs: CGFloat = 2
        static let xs: CGFloat = 4
        static let sm: CGFloat = 8
        static let md: CGFloat = 12
        static let lg: CGFloat = 16
        static let xl: CGFloat = 20
        static let xxl: CGFloat = 24
    }

    /// The standard content inset for a screen's body.
    static let screenPadding: CGFloat = Spacing.xl

    // MARK: Corner radii
    enum Radius {
        static let sm: CGFloat = 6    // chips, code inlines, small tags
        static let md: CGFloat = 9    // buttons-in-cards, inputs
        static let lg: CGFloat = 12   // cards, list items
        static let xl: CGFloat = 16   // approval card
    }

    // MARK: Typography roles
    // Named roles keep weights/sizes consistent instead of ad-hoc `.headline` calls.
    enum Typography {
        static let screenTitle = Font.title3.weight(.semibold)
        static let cardTitle = Font.headline
        static let sectionLabel = Font.caption.weight(.semibold)   // rendered uppercased by SectionHeader
        static let body = Font.callout
        static let value = Font.callout
        static let caption = Font.caption
        static let mono = Font.system(.callout, design: .monospaced)
        static let monoSmall = Font.system(.caption, design: .monospaced)
    }

    /// Monospaced style for commands / raw payloads. (Back-compat alias.)
    static let mono = Typography.mono

    // MARK: Adaptive surfaces
    // Elevation-aware fills for light and dark window backgrounds.
    enum Surface {
        /// An elevated content card sitting on the window background.
        static let card = Color(nsColor: .controlBackgroundColor)
        /// Hairline border for cards and list items.
        static let stroke = Color.primary.opacity(0.09)
        /// A barely-there inset fill (code blocks, chips, inline wells).
        static let inset = Color.primary.opacity(0.05)
        /// A hover highlight for tappable rows.
        static let hover = Color.primary.opacity(0.06)
        /// A pressed highlight.
        static let pressed = Color.primary.opacity(0.10)
        /// A selection tint (accent-derived).
        static let selection = Color.accentColor.opacity(0.15)
    }
}

// MARK: - Trust badge / vault presentation

extension TrustBadge {
    var tint: Color {
        switch self {
        case .verified: return Theme.verified
        case .unsignedInChain: return Theme.danger
        case .unknown: return .secondary
        }
    }

    var symbol: String {
        switch self {
        case .verified: return "checkmark.seal.fill"
        case .unsignedInChain: return "exclamationmark.triangle.fill"
        case .unknown: return "hourglass"
        }
    }
}

extension VaultState {
    var symbol: String { locked ? "lock.fill" : "lock.open.fill" }
    var tint: Color { locked ? Theme.warning : Theme.verified }

    /// The *live* clock: the snapshot `ttlSec` was taken at `anchoredAt`, so this
    /// subtracts elapsed time up to `now`. Drive
    /// it from a `TimelineView` tick so it visibly counts down between refreshes.
    /// Returns "∞" when auto-lock is disabled.
    func ttlClock(anchoredAt: Date, now: Date = Date()) -> String {
        guard !locked else { return String(localized: "Locked") }
        guard ttlSec > 0 else { return "∞" }
        return VaultTTL.clock(VaultTTL.remaining(ttlSec: ttlSec, anchoredAt: anchoredAt, now: now))
    }
}

// MARK: - Card container

/// The standard elevated content surface: consistent padding, radius, fill and
/// hairline border. Use for every "card" so grouping reads uniformly.
struct Card<Content: View>: View {
    var padding: CGFloat
    var spacing: CGFloat
    var alignment: HorizontalAlignment
    @ViewBuilder var content: () -> Content

    init(padding: CGFloat = Theme.Spacing.lg,
         spacing: CGFloat = Theme.Spacing.md,
         alignment: HorizontalAlignment = .leading,
         @ViewBuilder content: @escaping () -> Content) {
        self.padding = padding
        self.spacing = spacing
        self.alignment = alignment
        self.content = content
    }

    var body: some View {
        VStack(alignment: alignment, spacing: spacing, content: content)
            .padding(padding)
            .frame(maxWidth: .infinity, alignment: alignment == .center ? .center : .leading)
            .cardSurface()
    }
}

extension View {
    /// Wrap any view in the standard card chrome (fill + radius + hairline border).
    func card(padding: CGFloat = Theme.Spacing.lg) -> some View {
        self
            .padding(padding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .cardSurface()
    }

    /// Applies the standard card background, border, radius, and shadow.
    func cardSurface(radius: CGFloat = Theme.Radius.lg) -> some View {
        self
            .background(Theme.Surface.card, in: RoundedRectangle(cornerRadius: radius, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: radius, style: .continuous)
                    .strokeBorder(Theme.Surface.stroke)
            )
            .shadow(color: .black.opacity(0.05), radius: 5, y: 1)
    }
}

// MARK: - Section header

/// Section label with an optional icon and trailing control.
struct SectionHeader<Trailing: View>: View {
    let title: Text
    var systemImage: String?
    @ViewBuilder var trailing: () -> Trailing

    init(_ title: LocalizedStringResource, systemImage: String? = nil,
         @ViewBuilder trailing: @escaping () -> Trailing = { EmptyView() }) {
        self.title = Text(title)
        self.systemImage = systemImage
        self.trailing = trailing
    }

    init(verbatim title: String, systemImage: String? = nil,
         @ViewBuilder trailing: @escaping () -> Trailing = { EmptyView() }) {
        self.title = Text(verbatim: title)
        self.systemImage = systemImage
        self.trailing = trailing
    }

    var body: some View {
        HStack(spacing: Theme.Spacing.xs) {
            if let systemImage {
                Image(systemName: systemImage).font(.caption2)
            }
            title
                .font(.caption2.weight(.semibold))
                .tracking(0.6)
            Spacer(minLength: Theme.Spacing.sm)
            trailing()
        }
        .foregroundStyle(.secondary)
    }
}

// MARK: - Screen header

/// Header with an icon, title, subtitle, and optional trailing control.
struct ScreenHeader<Trailing: View>: View {
    let title: LocalizedStringResource
    let subtitle: LocalizedStringResource
    let symbol: String
    @ViewBuilder var trailing: () -> Trailing

    init(title: LocalizedStringResource, subtitle: LocalizedStringResource, symbol: String,
         @ViewBuilder trailing: @escaping () -> Trailing = { EmptyView() }) {
        self.title = title
        self.subtitle = subtitle
        self.symbol = symbol
        self.trailing = trailing
    }

    var body: some View {
        HStack(alignment: .center, spacing: Theme.Spacing.md) {
            Image(systemName: symbol)
                .font(.title2)
                .foregroundStyle(Theme.accent)
                .frame(width: 28)
            VStack(alignment: .leading, spacing: 1) {
                Text(title).font(Theme.Typography.screenTitle)
                Text(subtitle).font(.caption).foregroundStyle(.secondary)
                    .lineLimit(2).fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: Theme.Spacing.md)
            trailing()
        }
        .padding(.horizontal, Theme.screenPadding)
        .padding(.vertical, Theme.Spacing.md + 2)
    }
}

// MARK: - Status pill / tag

/// Small status pill for decisions, health, versions, and badges.
struct StatusPill: View {
    let text: Text
    var systemImage: String?
    var tint: Color
    var style: Style

    enum Style { case filled, tinted, mono }

    init(_ text: LocalizedStringResource, systemImage: String? = nil,
         tint: Color = .secondary, style: Style = .tinted) {
        self.text = Text(text)
        self.systemImage = systemImage
        self.tint = tint
        self.style = style
    }

    init(verbatim text: String, systemImage: String? = nil,
         tint: Color = .secondary, style: Style = .tinted) {
        self.text = Text(verbatim: text)
        self.systemImage = systemImage
        self.tint = tint
        self.style = style
    }

    var body: some View {
        HStack(spacing: Theme.Spacing.xs) {
            if let systemImage { Image(systemName: systemImage).font(.caption2) }
            text.font(style == .mono ? Theme.Typography.monoSmall : .caption2.weight(.semibold))
                .lineLimit(1)
        }
        // Never let the pill get compressed and wrap its label ("ask→approved"
        // hyphenating to "ask→ap-proved"); size to content and win the layout.
        .fixedSize(horizontal: true, vertical: false)
        .padding(.horizontal, Theme.Spacing.sm)
        .padding(.vertical, 3)
        .background(background)
        .foregroundStyle(foreground)
        .overlay(style == .filled ? nil : Capsule().strokeBorder(tint.opacity(0.22)))
        .clipShape(Capsule())
    }

    @ViewBuilder private var background: some View {
        switch style {
        case .filled: Capsule().fill(tint)
        case .tinted, .mono: Capsule().fill(tint.opacity(0.14))
        }
    }
    private var foreground: Color { style == .filled ? .white : tint }
}

// MARK: - Aligned key/value row

/// A read-only row with a fixed-width key column and a value.
struct KeyValueRow<Value: View>: View {
    let key: LocalizedStringResource
    var keyWidth: CGFloat = 116
    @ViewBuilder var value: () -> Value

    init(_ key: LocalizedStringResource, keyWidth: CGFloat = 116, @ViewBuilder value: @escaping () -> Value) {
        self.key = key
        self.keyWidth = keyWidth
        self.value = value
    }

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: Theme.Spacing.md) {
            // Fixed key width aligns values across rows.
            Text(key)
                .font(.callout)
                .foregroundStyle(.secondary)
                .frame(width: keyWidth, alignment: .leading)
            value()
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

extension KeyValueRow where Value == Text {
    /// Plain text value.
    init(_ key: LocalizedStringResource, _ value: String, keyWidth: CGFloat = 116) {
        self.init(key, keyWidth: keyWidth) { Text(verbatim: value) }
    }
}

// MARK: - Loading skeleton

/// A single shimmering placeholder bar.
struct SkeletonBar: View {
    var height: CGFloat = 12
    var width: CGFloat?
    @State private var pulse = false

    var body: some View {
        RoundedRectangle(cornerRadius: Theme.Radius.sm, style: .continuous)
            .fill(Color.primary.opacity(pulse ? 0.11 : 0.05))
            .frame(width: width, height: height)
            .frame(maxWidth: width == nil ? .infinity : nil, alignment: .leading)
            .onAppear { withAnimation(.easeInOut(duration: 0.9).repeatForever(autoreverses: true)) { pulse = true } }
    }
}

/// A tasteful list-shaped loading state (a title + subtitle bar per row).
struct LoadingSkeleton: View {
    var rows: Int = 6

    var body: some View {
        VStack(spacing: Theme.Spacing.md) {
            ForEach(0..<rows, id: \.self) { _ in
                HStack(spacing: Theme.Spacing.md) {
                    Circle().fill(Color.primary.opacity(0.06)).frame(width: 22, height: 22)
                    VStack(alignment: .leading, spacing: Theme.Spacing.sm) {
                        SkeletonBar(height: 11, width: 180)
                        SkeletonBar(height: 9, width: 260)
                    }
                    Spacer()
                    SkeletonBar(height: 18, width: 54)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(Theme.screenPadding)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        .accessibilityLabel("Loading")
    }
}

// MARK: - Button & row styles

/// A small rounded pill button with hover + pressed feedback. Used for the
/// approval persist chips and other inline segmented choices. Hover state lives
/// on a nested `View` (a `ButtonStyle` struct isn't part of the view graph, so
/// `@State` on it wouldn't be managed by SwiftUI).
struct PillButtonStyle: ButtonStyle {
    var selected: Bool = false

    func makeBody(configuration: Configuration) -> some View {
        PillLabel(configuration: configuration, selected: selected)
    }

    private struct PillLabel: View {
        let configuration: Configuration
        let selected: Bool
        @State private var hovering = false

        var body: some View {
            configuration.label
                .font(.caption.weight(selected ? .semibold : .regular))
                .padding(.horizontal, Theme.Spacing.md)
                .padding(.vertical, 5)
                .background(fill(configuration.isPressed), in: Capsule())
                .overlay(Capsule().strokeBorder(selected ? Theme.accent : Color.primary.opacity(0.08)))
                .foregroundStyle(selected ? Theme.accent : .primary)
                .contentShape(Capsule())
                .onHover { hovering = $0 }
                .animation(.easeOut(duration: 0.12), value: hovering)
                .animation(.easeOut(duration: 0.12), value: selected)
        }

        private func fill(_ pressed: Bool) -> Color {
            if selected { return Theme.accent.opacity(pressed ? 0.26 : 0.18) }
            if pressed { return Theme.Surface.pressed }
            return hovering ? Theme.Surface.hover : Theme.Surface.inset
        }
    }
}

/// Adds a rounded hover/selection background to a tappable row (cards, list
/// items). Keeps the native feel: subtle, animated, generous hit area.
struct RowHighlight: ViewModifier {
    var selected: Bool = false
    var radius: CGFloat = Theme.Radius.md
    @State private var hovering = false

    func body(content: Content) -> some View {
        content
            .background(
                RoundedRectangle(cornerRadius: radius, style: .continuous)
                    .fill(selected ? Theme.Surface.selection : (hovering ? Theme.Surface.hover : .clear))
            )
            .contentShape(RoundedRectangle(cornerRadius: radius, style: .continuous))
            .onHover { hovering = $0 }
            .animation(.easeOut(duration: 0.12), value: hovering)
    }
}

extension View {
    func rowHighlight(selected: Bool = false, radius: CGFloat = Theme.Radius.md) -> some View {
        modifier(RowHighlight(selected: selected, radius: radius))
    }
}

// MARK: - Empty state

/// A compact, centered empty state used inside panes (the friendlier sibling of
/// `ContentUnavailableView`, styled to match the system).
struct EmptyStateView<Actions: View>: View {
    let title: LocalizedStringResource
    let message: LocalizedStringResource
    let symbol: String
    @ViewBuilder var actions: () -> Actions

    init(title: LocalizedStringResource, message: LocalizedStringResource, symbol: String,
         @ViewBuilder actions: @escaping () -> Actions = { EmptyView() }) {
        self.title = title
        self.message = message
        self.symbol = symbol
        self.actions = actions
    }

    var body: some View {
        VStack(spacing: Theme.Spacing.md) {
            Image(systemName: symbol)
                .font(.system(size: 34, weight: .light))
                .foregroundStyle(.tertiary)
            VStack(spacing: Theme.Spacing.xs) {
                Text(title).font(.headline)
                Text(message).font(.callout).foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 340)
            }
            actions().padding(.top, Theme.Spacing.xs)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding(Theme.screenPadding)
    }
}

#if DEBUG
/// Wraps a preview so both color schemes render side-by-side in the canvas.
struct ThemePreview<Content: View>: View {
    @ViewBuilder var content: () -> Content
    var body: some View {
        VStack(spacing: 0) {
            content().environment(\.colorScheme, .light)
            Divider()
            content().environment(\.colorScheme, .dark)
        }
    }
}

#if !SP_NO_PREVIEWS
#Preview("Design system") {
    ScrollView {
        VStack(alignment: .leading, spacing: Theme.Spacing.lg) {
            ScreenHeader(title: "Design system", subtitle: "Tokens & components", symbol: "paintpalette") {
                Button("Action") {}.buttonStyle(.borderedProminent)
            }
            Card {
                SectionHeader("Status pills")
                HStack {
                    StatusPill("allow", tint: Theme.verified)
                    StatusPill("ask", systemImage: "hand.raised.fill", tint: Theme.warning)
                    StatusPill("deny", tint: Theme.danger, style: .filled)
                    StatusPill("v3", tint: Theme.accent, style: .mono)
                }
                SectionHeader("Key / value")
                KeyValueRow("Socket", "/tmp/sallyport.sock")
                KeyValueRow("Version", "1.0.0")
            }
            .padding(.horizontal, Theme.screenPadding)
            LoadingSkeleton(rows: 3).frame(height: 180)
        }
        .padding(.vertical, Theme.Spacing.lg)
    }
    .frame(width: 620, height: 640)
}
#endif
#endif


// MARK: - Adaptive color helper

private extension Color {
    /// A light/dark adaptive color built on NSColor's dynamic provider, so fixed
    /// brand colors still respect appearance changes live.
    init(light: Color, dark: Color) {
        self.init(nsColor: NSColor(name: nil) { appearance in
            appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
                ? NSColor(dark) : NSColor(light)
        })
    }
}

/// Toggle style that keeps the on state blue in inactive windows.
struct AccentSwitchStyle: ToggleStyle {
    func makeBody(configuration: Configuration) -> some View {
        // Callers provide visible text; the accessibility representation keeps the label.
        Button {
            configuration.isOn.toggle()
        } label: {
            HStack(spacing: Theme.Spacing.sm) {
                Capsule(style: .continuous)
                    .fill(configuration.isOn ? Theme.accent : Color.primary.opacity(0.18))
                    .frame(width: 40, height: 24)
                    .overlay(alignment: configuration.isOn ? .trailing : .leading) {
                        Circle()
                            .fill(.white)
                            .shadow(color: .black.opacity(0.25), radius: 1, y: 0.5)
                            .padding(2)
                    }
                    .animation(.spring(duration: 0.18), value: configuration.isOn)
            }
        }
        .buttonStyle(.plain)
        .accessibilityRepresentation {
            Toggle(isOn: configuration.$isOn) { configuration.label }
        }
    }
}
