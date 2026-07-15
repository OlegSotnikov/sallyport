import SwiftUI
import SallyportKit

/// Configuration snippets for supported MCP clients.
struct IntegrationsView: View {
    @State private var selected: Integration = .claudeCode

    var body: some View {
        VStack(spacing: 0) {
            ScreenHeader(
                title: "Integrations",
                subtitle: "Copy the Sallyport configuration for your MCP client.",
                symbol: "puzzlepiece.extension")
            Divider()
            HStack(spacing: 0) {
                List(Integration.allCases, selection: $selected) { integration in
                    Label(integration.title, systemImage: integration.symbol).tag(integration)
                }
                .listStyle(.sidebar)
                .frame(width: 200)

                Divider()

                ScrollView {
                    VStack(alignment: .leading, spacing: Theme.Spacing.lg) {
                        HStack(spacing: Theme.Spacing.md) {
                            Image(systemName: selected.symbol)
                                .font(.title2).foregroundStyle(Theme.accent).frame(width: 30)
                            VStack(alignment: .leading, spacing: 1) {
                                Text(selected.title).font(Theme.Typography.screenTitle)
                                Text(selected.subtitle).font(.caption).foregroundStyle(.secondary)
                            }
                            Spacer()
                        }
                        Text(selected.instructions).font(.callout).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                        SnippetBox(title: selected.snippetTitle, snippet: selected.snippet)
                        Spacer(minLength: 0)
                    }
                    .padding(Theme.screenPadding)
                }
            }
        }
    }
}

private struct SnippetBox: View {
    let title: String
    let snippet: String
    @State private var copied = false

    var body: some View {
        VStack(alignment: .leading, spacing: Theme.Spacing.sm) {
            SectionHeader(verbatim: title, systemImage: "chevron.left.forwardslash.chevron.right") {
                Button {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(snippet, forType: .string)
                    withAnimation { copied = true }
                    Task { try? await Task.sleep(nanoseconds: 1_500_000_000); copied = false }
                } label: {
                    Label(copied ? "Copied" : "Copy", systemImage: copied ? "checkmark" : "doc.on.doc")
                        .font(.caption)
                        .foregroundStyle(copied ? Theme.verified : Theme.accent)
                }
                .buttonStyle(.borderless)
            }
            ScrollView(.horizontal, showsIndicators: false) {
                Text(verbatim: snippet)
                    .font(.callout.monospaced())
                    .textSelection(.enabled)
                    .padding(Theme.Spacing.md)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Theme.Surface.inset, in: RoundedRectangle(cornerRadius: Theme.Radius.md, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: Theme.Radius.md, style: .continuous).strokeBorder(Theme.Surface.stroke))
        }
    }
}

enum Integration: String, CaseIterable, Identifiable {
    case claudeCode, cursor, vsCode, genericMCP
    var id: String { rawValue }

    /// Path to the bundled MCP shim.
    static let spPath: String =
        SallyportSetup.bundledBinary("sp")?.path
        ?? Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS/sp").path

    var title: LocalizedStringResource {
        switch self {
        case .claudeCode: return "Claude Code"
        case .cursor: return "Cursor"
        case .vsCode: return "VS Code"
        case .genericMCP: return "Generic MCP"
        }
    }
    var symbol: String {
        switch self {
        case .claudeCode: return "terminal"
        case .cursor: return "cursorarrow.rays"
        case .vsCode: return "chevron.left.forwardslash.chevron.right"
        case .genericMCP: return "puzzlepiece.extension"
        }
    }
    var subtitle: LocalizedStringResource {
        switch self {
        case .claudeCode: return "Terminal command or .mcp.json entry"
        case .cursor: return "Add to ~/.cursor/mcp.json"
        case .vsCode: return "Add to .vscode/mcp.json"
        case .genericMCP: return "Any stdio MCP client"
        }
    }
    var instructions: LocalizedStringResource {
        switch self {
        case .claudeCode:
            return "Run the command once, or add the same entry to your project's .mcp.json. Sallyport attaches credentials only when sending requests."
        case .cursor:
            return "Cursor reads MCP servers from ~/.cursor/mcp.json."
        case .vsCode:
            return "VS Code reads MCP servers from .vscode/mcp.json."
        case .genericMCP:
            return "Any MCP client that spawns a stdio server can launch the shim directly. It speaks MCP on stdin/stdout and talks to this app over its private socket."
        }
    }
    var snippetTitle: String {
        switch self {
        case .claudeCode: return "terminal"
        case .cursor: return "~/.cursor/mcp.json"
        case .vsCode: return ".vscode/mcp.json"
        case .genericMCP: return "mcp.json"
        }
    }
    var snippet: String {
        switch self {
        case .claudeCode:
            return "claude mcp add sallyport -- \"\(Self.spPath)\" mcp"
        case .cursor, .vsCode, .genericMCP:
            return """
            {
              "mcpServers": {
                "sallyport": {
                  "command": "\(Self.spPath)",
                  "args": ["mcp"]
                }
              }
            }
            """
        }
    }
}

#if DEBUG && !SP_NO_PREVIEWS
#Preview("Integrations (light)") {
    IntegrationsView().frame(width: 860, height: 560).preferredColorScheme(.light)
}

#if !SP_NO_PREVIEWS
#Preview("Integrations (dark)") {
    IntegrationsView().frame(width: 860, height: 560).preferredColorScheme(.dark)
}
#endif
#endif
