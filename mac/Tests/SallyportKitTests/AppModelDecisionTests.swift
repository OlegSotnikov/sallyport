import Foundation
import Testing
@testable import SallyportKit
@testable import SallyportApp
import SallyportVault

/// The single-process approval bridge: the engine's `requestApproval` suspends on
/// the approval card, and `approve`/`deny` resolve that exact in-flight ask (no
/// daemon, no grant signing, no wire round-trip). Fail-closed: an unresolved ask
/// times out to a denial (not covered here — the timeout is 120s).
@MainActor
@Suite("AppModel approval bridge (in-process)")
struct AppModelDecisionTests {

    private func makeModel() -> AppModel {
        let model = AppModel(signer: SoftwareKeyCustodian(), authenticator: DevAuthenticator())
        model.isDemo = true   // keep the AppKit panel + notifier inert
        return model
    }

    private func ask(id: String, mode: String = "session") -> EngineApproval {
        EngineApproval(
            id: id, mode: mode, rule: "session.gate", reason: "New agent process",
            channel: "ssh", tool: "ssh.exec", summary: "restart nginx on ws-kz", host: "ws-kz",
            origin: SallyportVault.Origin(
                pid: 4321, startedAt: 111, name: "claude", path: "/usr/local/bin/claude",
                appName: "Claude Code", signedBy: "Developer ID Application: Anthropic PBC",
                validSignature: true),
            chain: [])
    }

    /// Waits for the engine's ask to surface as a pending card (it enqueues across
    /// a couple of main-actor hops).
    private func waitForCard(_ model: AppModel, id: String) async {
        for _ in 0..<200 where !model.pending.contains(where: { $0.id == id }) { await Task.yield() }
    }

    @Test("approve resolves the engine's in-flight ask and clears the card")
    func approveResolvesAsk() async {
        let model = makeModel()
        async let verdict = model.requestApproval(ask(id: "ask-1"))
        await waitForCard(model, id: "ask-1")
        #expect(model.pending.contains { $0.id == "ask-1" })

        await model.approve(model.pending.first { $0.id == "ask-1" }!)
        let outcome = await verdict
        #expect(outcome.verdict == .approved)
        #expect(!model.pending.contains { $0.id == "ask-1" })
    }

    @Test("deny resolves the ask as a denial and clears the card")
    func denyResolvesAsk() async {
        let model = makeModel()
        async let verdict = model.requestApproval(ask(id: "ask-2"))
        await waitForCard(model, id: "ask-2")

        await model.deny(model.pending.first { $0.id == "ask-2" }!)
        let outcome = await verdict
        #expect(outcome.verdict == .denied)
        #expect(!model.pending.contains { $0.id == "ask-2" })
    }
}
