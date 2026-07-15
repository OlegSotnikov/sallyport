import SwiftUI

/// Displays app identity, version, source, and copyright.
struct AboutView: View {
    /// Author link shared with the standard About panel.
    static let authorURL = URL(string: "https://oleg.is/?utm_source=sallyport&utm_medium=app&utm_campaign=about")
    /// Source link shared with the standard About panel.
    static let sourceURL = URL(string: "https://github.com/OlegSotnikov/sallyport")

    private var version: String {
        let short = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "Unknown"
        let build = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "Unknown"
        return "Version \(short) (\(build))"
    }

    /// Copyright line with an author link.
    private var copyright: AttributedString {
        var line = AttributedString("© 2025-2026 ")
        var name = AttributedString("Oleg Sotnikov")
        name.link = Self.authorURL
        line.append(name)
        return line
    }

    /// Source repository link.
    private var source: AttributedString {
        var line = AttributedString("Source code: ")
        var repo = AttributedString("github.com/OlegSotnikov/sallyport")
        repo.link = Self.sourceURL
        line.append(repo)
        return line
    }

    var body: some View {
        VStack(spacing: 0) {
            ScreenHeader(title: "About",
                         subtitle: "Version and source.",
                         symbol: "info.circle") { EmptyView() }
            Divider()

            VStack(spacing: Theme.Spacing.md) {
                Spacer(minLength: Theme.Spacing.lg)

                Image(nsImage: NSApp.applicationIconImage)
                    .resizable()
                    .interpolation(.high)
                    .frame(width: 120, height: 120)
                    .shadow(color: .black.opacity(0.18), radius: 12, y: 6)

                Text("Sallyport")
                    .font(.system(size: 30, weight: .semibold))
                Text(version)
                    .font(.callout).foregroundStyle(.secondary)

                Text("Stores credentials and uses them for configured agent actions without returning them to the agent.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: 440)
                    .padding(.top, 2)

                Spacer(minLength: Theme.Spacing.lg)

                VStack(spacing: 4) {
                    Text(source)
                    Text(copyright)
                    Text("AppMaster")
                }
                .font(.caption)
                .foregroundStyle(.tertiary)
                .tint(Theme.accent)
                .padding(.bottom, Theme.Spacing.xl)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .padding(Theme.screenPadding)
        }
    }
}
