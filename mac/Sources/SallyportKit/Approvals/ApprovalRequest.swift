import Foundation

/// Data shown for a pending approval.
public struct ApprovalRequest: Sendable, Hashable, Identifiable {
    public var id: String
    public var action: ActionDescriptor
    public var why: WhyDescriptor
    public var provenance: Provenance
    /// Approval mode: session, session-touchid, per-call, or per-call-touchid.
    public var mode: String

    public init(id: String, action: ActionDescriptor, why: WhyDescriptor,
                provenance: Provenance, mode: String = "") {
        self.id = id
        self.action = action
        self.why = why
        self.provenance = provenance
        self.mode = mode
    }

    /// Reconstruct an `ApprovalRequest` from a decoded inbound message.
    public init?(_ message: InboundMessage) {
        guard case let .approvalRequest(id, action, why, provenance, mode) = message else {
            return nil
        }
        self.init(id: id, action: action, why: why,
                  provenance: provenance, mode: mode)
    }


    /// The Touch ID reason string built from this request.
    /// Modes that require Touch ID.
    public static let biometricModes: Set<String> = ["per-call-touchid", "session-touchid", "strict"]

    public var touchIDReason: String {
        ApprovalPresentation.touchIDReason(action: action, origin: provenance.origin)
    }
}
