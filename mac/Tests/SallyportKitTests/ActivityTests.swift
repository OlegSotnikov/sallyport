import Foundation
import Testing
@testable import SallyportKit
@testable import SallyportApp

@Suite("Activity feed store & filter")
struct ActivityTests {

    @Test("append puts newest first")
    func newestFirst() {
        var log = ActivityLog()
        log.append(Fixtures.activityRows[3])   // oldest
        log.append(Fixtures.activityRows[0])   // newest
        #expect(log.rows.first?.ts == Fixtures.activityRows[0].ts)
        #expect(log.rows.count == 2)
    }

    @Test("capacity drops the oldest rows")
    func capacityCap() {
        var log = ActivityLog(capacity: 2)
        for i in 0..<5 {
            log.append(ActivityRow(ts: "t\(i)", identity: "id", channel: "http",
                                   tool: "t", argsPreview: "", target: "", decision: "allow"))
        }
        #expect(log.rows.count == 2)
        #expect(log.rows.first?.ts == "t4")
        #expect(log.rows.last?.ts == "t3")
    }

    @Test("inactive filter returns everything")
    func inactiveFilter() {
        let log = ActivityLog(rows: Fixtures.activityRows)
        #expect(log.filtered(ActivityFilter()).count == Fixtures.activityRows.count)
    }

    @Test("free-text query searches identity, tool, and target")
    func textQuery() {
        let log = ActivityLog(rows: Fixtures.activityRows)
        #expect(log.filtered(ActivityFilter(query: "cloudflare")).count == 2)
        #expect(log.filtered(ActivityFilter(query: "koder")).count == 1)
        #expect(log.filtered(ActivityFilter(query: "nonexistent")).isEmpty)
    }

    @Test("channel and decision filters combine")
    func channelDecision() {
        let log = ActivityLog(rows: Fixtures.activityRows)
        #expect(log.filtered(ActivityFilter(channel: "ssh")).count == 1)
        #expect(log.filtered(ActivityFilter(decision: "deny")).count == 1)
        #expect(log.filtered(ActivityFilter(decision: "allow")).count == 2)
    }

    @Test("only-flagged surfaces denials and errors")
    func onlyFlagged() {
        let log = ActivityLog(rows: Fixtures.activityRows)
        let flagged = log.filtered(ActivityFilter(onlyFlagged: true))
        #expect(flagged.count == 1)
        #expect(flagged.first?.target == "evil.tld")
    }

    @Test("distinct channels are listed sorted")
    func channels() {
        let log = ActivityLog(rows: Fixtures.activityRows)
        #expect(log.channels == ["http", "ssh"])
    }

    @Test("duration formatting is total at corrupt audit-log integer boundaries")
    @MainActor
    func durationFormattingBoundaries() {
        #expect(ActivityRowView.formatDuration(Int.min) == "0ms")
        #expect(ActivityRowView.formatDuration(-1) == "0ms")
        #expect(ActivityRowView.formatDuration(0) == "0ms")
        #expect(ActivityRowView.formatDuration(59_499) == "59s")
        #expect(ActivityRowView.formatDuration(59_500) == "1m 0s")
        #expect(!ActivityRowView.formatDuration(Int.max).isEmpty)
    }
}

@Suite("Approval presentation")
struct ApprovalPresentationTests {

    @Test("Touch ID reason is built from the action, not generic")
    func touchIDReason() {
        let reason = Fixtures.sshRestartNginx.touchIDReason
        #expect(reason == "Approve: systemctl restart nginx on 203.0.113.10 (Claude Code)")
    }

    @Test("primary action text prefers the SSH command body")
    func primaryText() {
        #expect(ApprovalPresentation.primaryActionText(Fixtures.sshRestartNginx.action)
                == "systemctl restart nginx")
        #expect(ApprovalPresentation.primaryActionText(Fixtures.httpCloudflareDNS.action)
                .hasPrefix("POST https://api.cloudflare.com"))
    }

    @Test("danger token ranges are found case-insensitively")
    func dangerRanges() {
        let text = "systemctl restart nginx"
        let ranges = ApprovalPresentation.dangerRanges(in: text, tokens: ["restart"])
        #expect(ranges.count == 1)
        #expect(String(text[ranges[0]]) == "restart")
    }

    @Test("multiple danger tokens are returned left-to-right")
    func multipleDangerTokens() {
        let text = "rm -rf /var/log/*"
        let ranges = ApprovalPresentation.dangerRanges(in: text, tokens: ["rm", "-rf"])
        #expect(ranges.count == 2)
        #expect(String(text[ranges[0]]) == "rm")
        #expect(String(text[ranges[1]]) == "-rf")
    }


}
