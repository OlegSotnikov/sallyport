import Foundation
import Testing
@testable import SallyportKit

@Suite("Known agents registry and pin updates")
struct KnownAgentsTests {
    @Test("registry matches only a signed identity with the exact team and bundle")
    func registryMatch() {
        #expect(KnownAgents.match(teamID: "Q6L2SF6YDW",
                                  bundleID: "com.anthropic.claudefordesktop")?.label
                == "Claude Desktop")
        #expect(KnownAgents.match(teamID: "Q6L2SF6YDW",
                                  bundleID: "com.anthropic.claude-code")?.label == "Claude Code")
        #expect(KnownAgents.match(teamID: "2DC432GLL2", bundleID: "codex")?.label == "Codex CLI")

        // The team is load-bearing: the right bundle id under the wrong team
        // is exactly the impersonation the cross-check exists to catch.
        #expect(KnownAgents.match(teamID: "ATTACKER00", bundleID: "codex") == nil)
        #expect(KnownAgents.match(teamID: "", bundleID: "com.anthropic.claude-code") == nil)
    }

    @Test("installed() expands ~ and only reports agents present on disk")
    func installedDetection() throws {
        let home = "/tmp/spx-known-\(UUID().uuidString.prefix(8))"
        try FileManager.default.createDirectory(atPath: home + "/.local/bin",
                                                withIntermediateDirectories: true)
        FileManager.default.createFile(atPath: home + "/.local/bin/codex", contents: Data())
        defer { try? FileManager.default.removeItem(atPath: home) }

        let found = KnownAgents.installed(home: home)
        #expect(found.contains { $0.agent.label == "Codex CLI" && $0.path == home + "/.local/bin/codex" })
        #expect(!found.contains { $0.agent.label == "Claude Code" },
                "an agent absent from every standard path must not be offered")
    }

    @Test("a stale pin is recognized only for the same signed identity")
    func stalePinDetection() {
        let pinned = AllowlistItem(
            id: "entry-1", label: "Codex CLI", kind: "cdhash",
            teamID: "2DC432GLL2", bundleID: "codex", cdhashes: ["aa11"],
            scopeHosts: ["api.example.com"])
        let updated = AllowlistCapturePreview(
            label: "codex", cdhashes: ["bb22"], teamID: "2DC432GLL2", bundleID: "codex",
            signed: true, authority: "Developer ID Application: OpenAI OpCo, LLC (2DC432GLL2)",
            capturedFrom: "/usr/local/bin/codex")
        #expect(updated.stalePin(in: [pinned])?.id == "entry-1")

        // The same build is not stale; nothing to update.
        let same = AllowlistCapturePreview(
            label: "codex", cdhashes: ["aa11"], teamID: "2DC432GLL2", bundleID: "codex",
            signed: true, authority: "", capturedFrom: "/usr/local/bin/codex")
        #expect(same.stalePin(in: [pinned]) == nil)

        // A different signer must never update someone else's pin.
        let impostor = AllowlistCapturePreview(
            label: "codex", cdhashes: ["cc33"], teamID: "ATTACKER00", bundleID: "codex",
            signed: true, authority: "", capturedFrom: "/tmp/codex")
        #expect(impostor.stalePin(in: [pinned]) == nil)

        // An unsigned capture carries no publisher continuity.
        let unsigned = AllowlistCapturePreview(
            label: "codex", cdhashes: ["dd44"], teamID: "2DC432GLL2", bundleID: "codex",
            signed: false, authority: "", capturedFrom: "/tmp/codex")
        #expect(unsigned.stalePin(in: [pinned]) == nil)

        // Publisher entries follow updates by construction; nothing to re-pin.
        let publisher = AllowlistItem(
            id: "entry-2", label: "Codex CLI", kind: "publisher",
            teamID: "2DC432GLL2", bundleID: "codex", requirement: "anchor apple generic")
        #expect(updated.stalePin(in: [publisher]) == nil)
    }
}
