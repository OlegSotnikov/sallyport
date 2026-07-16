import Foundation
import SallyportKit

/// Approval interface for session admission and per-call keys. The app presents
/// the request; tests can inject a substitute. Missing or timed-out approval is denied.
public protocol Approver: Sendable {
    func requestApproval(_ req: EngineApproval) async -> ApprovalOutcome
}

/// Approval request. `mode` selects the interaction:
/// "session" (one-click admit this agent), "per-call" (confirm this one call),
/// "per-call-touchid" (biometric per call).
public struct EngineApproval: Sendable {
    public var id: String
    public var mode: String
    public var rule: String
    public var reason: String
    public var channel: String
    public var tool: String
    public var summary: String
    public var host: String
    /// Display-only preview of the agent-supplied HTTP body, before credential injection.
    /// Present only for per-call HTTP approvals.
    public var bodyPreview: String?
    /// Original request-body size, not the possibly pretty-printed preview size.
    public var bodyByteCount: Int?
    public var bodyPreviewTruncated: Bool
    public var origin: Origin
    public var chain: [Hop]
    public init(id: String, mode: String, rule: String, reason: String, channel: String,
                tool: String, summary: String, host: String,
                bodyPreview: String? = nil, bodyByteCount: Int? = nil,
                bodyPreviewTruncated: Bool = false,
                origin: Origin, chain: [Hop]) {
        self.id = id; self.mode = mode; self.rule = rule; self.reason = reason
        self.channel = channel; self.tool = tool; self.summary = summary
        self.host = host
        self.bodyPreview = bodyPreview
        self.bodyByteCount = bodyByteCount
        self.bodyPreviewTruncated = bodyPreviewTruncated
        self.origin = origin; self.chain = chain
    }
}

public struct ApprovalOutcome: Sendable {
    public enum Verdict: Sendable { case approved, denied, timedOut, noApprover }
    public var verdict: Verdict
    public init(_ verdict: Verdict) { self.verdict = verdict }

    public static let approved = ApprovalOutcome(.approved)
    public static let denied = ApprovalOutcome(.denied)
    public static let timedOut = ApprovalOutcome(.timedOut)
    public static let noApprover = ApprovalOutcome(.noApprover)
}
