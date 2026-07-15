import Foundation
import Testing
@testable import SallyportKit
@testable import SallyportApp

/// The native-notification approval surface (modeled on Secretive's Notifier).
/// UNUserNotificationCenter and real banners can't be unit-tested, so the pure
/// logic — the content builder, the tapped-action → decision mapping, and the
/// surface-selection — is factored into `ApprovalNotification` and covered here.
@Suite("ApprovalNotification (native approval surface)")
struct ApprovalNotificationTests {

    // MARK: Content builder

    @Test("content: title is the requesting agent, subtitle carries the action")
    func contentFields() {
        let request = Fixtures.sshRestartNginx
        let c = ApprovalNotification.content(for: request)

        // Title = origin app name (Fixtures.hopClaudeCode.appName).
        #expect(c.title == "Claude Code")
        // Subtitle contains the primary action text and the host.
        #expect(c.subtitle.contains("systemctl restart nginx"))
        #expect(c.subtitle.contains("203.0.113.10"))
        // Body = the policy reason; identifier / requestID == the request id.
        #expect(c.body == request.why.reason)
        #expect(c.identifier == request.id)
        #expect(c.requestID == request.id)
        #expect(c.categoryIdentifier == ApprovalNotification.categoryIdentifier)
        // Icon source is the origin executable path (best-effort attachment).
        #expect(c.iconSourcePath == Fixtures.hopClaudeCode.path)
    }

    @Test("content: falls back to the process name when there is no app name")
    func contentTitleFallsBackToProcessName() {
        var req = Fixtures.sshRestartNginx
        req.provenance.origin.appName = nil        // no GUI app name
        let c = ApprovalNotification.content(for: req)
        #expect(c.title == Fixtures.hopClaudeCode.name)   // "claude"
    }

    @Test("actionLine: SSH backticks the command; HTTP shows the summary")
    func actionLineFormatting() {
        let ssh = ApprovalNotification.actionLine(for: Fixtures.sshRestartNginx.action)
        #expect(ssh == "ssh.exec `systemctl restart nginx` on 203.0.113.10")

        let http = ApprovalNotification.actionLine(for: Fixtures.httpCloudflareDNS.action)
        #expect(http.contains("POST"))
        #expect(http.contains("on api.cloudflare.com"))
    }

    // MARK: Action → decision mapping

    @Test("decision: approve → .approve (an approval carries no scope any more)")
    func decisionApprove() {
        let d = ApprovalNotification.decision(forActionID: ApprovalNotification.ActionID.approve)
        #expect(d == .approve)
    }

    @Test("decision: deny → .deny")
    func decisionDeny() {
        #expect(ApprovalNotification.decision(forActionID: ApprovalNotification.ActionID.deny) == .deny)
    }

    @Test("decision: default action (tapped body) → .detail")
    func decisionDefaultIsDetail() {
        // The system default-action id maps to opening the floating panel.
        let d = ApprovalNotification.decision(forActionID: "anything", isDefault: true)
        #expect(d == .detail)
    }

    @Test("decision: dismiss / unknown → .ignore (leave pending)")
    func decisionDismissAndUnknown() {
        #expect(ApprovalNotification.decision(forActionID: "x", isDismiss: true) == .ignore)
        #expect(ApprovalNotification.decision(forActionID: "not-a-known-action") == .ignore)
    }

    // MARK: Surface selection

    @Test("surface: authorized-family → notification; otherwise the panel")
    func surfaceSelection() {
        #expect(ApprovalNotification.surface(for: .authorized) == .notification)
        #expect(ApprovalNotification.surface(for: .provisional) == .notification)
        #expect(ApprovalNotification.surface(for: .ephemeral) == .notification)
        #expect(ApprovalNotification.surface(for: .denied) == .panel)
        #expect(ApprovalNotification.surface(for: .notDetermined) == .panel)
    }
}

/// The delegate → model wiring: a tapped-notification decision drives the same
/// approve/deny paths as the panel, and a decision for an already-resolved
/// request is a no-op. Driven through `AppModel` directly (isDemo so no disk /
/// AppKit / notification center is touched). In the single-process build a
/// decision resolves the engine's in-flight ask and clears the card.
@MainActor
@Suite("AppModel notification wiring")
struct AppModelNotificationWiringTests {

    private func makeModel() -> AppModel {
        let model = AppModel(signer: SoftwareKeyCustodian(), authenticator: DevAuthenticator())
        model.isDemo = true
        return model
    }

    @Test("approve from a notification takes the approve path (clears the card)")
    func approveDecisionDrivesApprove() async {
        let model = makeModel()
        let request = Fixtures.sshRestartNginx
        model.pending = [request]

        await model.handleNotificationDecision(.approve, requestID: request.id)

        // Routed into `approve` → the card is resolved and removed.
        #expect(!model.pending.contains { $0.id == request.id })
    }

    @Test("deny from a notification takes the deny path (clears the card)")
    func denyDecisionDrivesDeny() async {
        let model = makeModel()
        let request = Fixtures.httpCloudflareDNS
        model.pending = [request]

        await model.handleNotificationDecision(.deny, requestID: request.id)

        #expect(!model.pending.contains { $0.id == request.id })
    }

    @Test("a decision for an already-resolved request is a no-op")
    func staleDecisionIsNoOp() async {
        let model = makeModel()
        model.pending = []           // nothing pending — the banner is stale

        await model.handleNotificationDecision(.approve, requestID: "req-gone")
        await model.handleNotificationDecision(.deny, requestID: "req-gone")

        #expect(model.pending.isEmpty)
        #expect(model.activity.rows.isEmpty)   // nothing happened
    }

    @Test("ignore never resolves or records anything")
    func ignoreIsInert() async {
        let model = makeModel()
        let request = Fixtures.sshRestartNginx
        model.pending = [request]

        await model.handleNotificationDecision(.ignore, requestID: request.id)

        #expect(model.pending.contains { $0.id == request.id })   // still pending
        #expect(model.activity.rows.isEmpty)
    }
}
