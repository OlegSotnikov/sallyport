import SwiftUI

/// Displays app identity, version, source, and copyright.
struct AboutView: View {
    var updater: SoftwareUpdater? = nil

    /// Author link shared with the standard About panel.
    static let authorURL = URL(string: "https://oleg.is/?utm_source=sallyport&utm_medium=app&utm_campaign=about")
    /// Source link shared with the standard About panel.
    static let sourceURL = URL(string: "https://github.com/OlegSotnikov/sallyport")

    private var version: String {
        let unknown = String(localized: "Unknown")
        let short = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? unknown
        let build = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? unknown
        return String(localized: "Version \(short) (\(build))",
                      comment: "App version followed by its build number.")
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
        var line = AttributedString(String(localized: "Source code: "))
        var repo = AttributedString("github.com/OlegSotnikov/sallyport")
        repo.link = Self.sourceURL
        line.append(repo)
        return line
    }

    var body: some View {
        VStack(spacing: 0) {
            ScreenHeader(title: LocalizedStringResource("About"),
                         subtitle: LocalizedStringResource("Version and source."),
                         symbol: "info.circle") { EmptyView() }
            Divider()

            VStack(spacing: Theme.Spacing.md) {
                Spacer(minLength: Theme.Spacing.lg)

                Image(nsImage: NSApp.applicationIconImage)
                    .resizable()
                    .interpolation(.high)
                    .frame(width: 120, height: 120)
                    .shadow(color: .black.opacity(0.18), radius: 12, y: 6)
                    .accessibilityHidden(true)

                Text(verbatim: "Sallyport")
                    .font(.system(size: 30, weight: .semibold))
                Text(verbatim: version)
                    .font(.callout).foregroundStyle(.secondary)

                Button("Check for Updates…", systemImage: "arrow.down.circle",
                       action: checkForUpdates)
                    .buttonStyle(.bordered)
                    .disabled(updater?.canCheck != true)

                Text("Uses vault credentials for configured actions without exposing the vault to the agent. Target responses are returned without content filtering.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: 520)
                    .padding(.top, 2)

                Spacer(minLength: Theme.Spacing.lg)

                VStack(spacing: 4) {
                    Text(source)
                    Text(copyright)
                    Text(verbatim: "AppMaster")
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

    private func checkForUpdates() {
        updater?.checkForUpdates()
    }
}
