import Foundation

/// A well-known agent app: label, expected signing identity, and standard
/// install locations. The registry is a UX map and a cross-check for
/// captures, never an authority — entries are still captured from the binary
/// on disk and verified by Security.framework like any other executable.
public struct KnownAgent: Sendable, Identifiable {
    public var id: String { bundleID }
    public let label: String
    public let bundleID: String
    public let teamID: String
    /// Standard install locations, checked in order. "~" expands to home.
    public let paths: [String]

    public init(label: String, bundleID: String, teamID: String, paths: [String]) {
        self.label = label; self.bundleID = bundleID; self.teamID = teamID
        self.paths = paths
    }
}

/// Signing identities captured from real installs (Developer ID leaf
/// certificates), not transcribed from documentation.
public enum KnownAgents {
    public static let all: [KnownAgent] = [
        KnownAgent(label: "Claude Desktop",
                   bundleID: "com.anthropic.claudefordesktop",
                   teamID: "Q6L2SF6YDW",
                   paths: ["/Applications/Claude.app"]),
        KnownAgent(label: "Claude Code",
                   bundleID: "com.anthropic.claude-code",
                   teamID: "Q6L2SF6YDW",
                   paths: ["~/.local/bin/claude", "/opt/homebrew/bin/claude",
                           "/usr/local/bin/claude"]),
        KnownAgent(label: "Codex CLI",
                   bundleID: "codex",
                   teamID: "2DC432GLL2",
                   paths: ["~/.local/bin/codex", "/opt/homebrew/bin/codex",
                           "/usr/local/bin/codex"]),
    ]

    /// The registry entry matching a captured identity. Requires a Team ID:
    /// an unsigned or ad-hoc capture never matches a known agent.
    public static func match(teamID: String, bundleID: String) -> KnownAgent? {
        guard !teamID.isEmpty else { return nil }
        return all.first { $0.teamID == teamID && $0.bundleID == bundleID }
    }

    /// Known agents present on disk, each with its first existing install path.
    public static func installed(home: String = NSHomeDirectory()) -> [(agent: KnownAgent, path: String)] {
        all.compactMap { agent in
            let found = agent.paths
                .map { $0.hasPrefix("~") ? home + $0.dropFirst() : $0 }
                .first { FileManager.default.fileExists(atPath: $0) }
            return found.map { (agent, $0) }
        }
    }
}
