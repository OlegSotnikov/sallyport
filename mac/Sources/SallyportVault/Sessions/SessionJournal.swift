import Foundation

/// Writes session lifecycle events to the sealed audit log. Live sessions are
/// cleared on lock. On the next unlock, reconciliation records sessions left
/// open by an unclean stop with an unknown end time.
public enum SessionJournal {

    public static let endedTool = "session.ended"
    public static let revokedTool = "session.revoked"
    public static let orphanedTool = "session.orphaned"
    public static let lockedTool = "vault.locked"
    public static let unlockedTool = "vault.unlocked"
    public static let channel = "session"
    public static let vaultChannel = "vault"

    /// Finds sessions without an end row after the last vault boundary.
    public static func orphans(in events: [AuditEvent]) -> [(key: String, identity: String, name: String)] {
        var live: [String: (identity: String, name: String)] = [:]
        var order: [String] = []
        func drop(_ key: String) {
            live[key] = nil
            order.removeAll { $0 == key }
        }
        for e in events {
            switch e.tool {
            case lockedTool, unlockedTool:
                // Lock and unlock boundaries clear the live-session set.
                live.removeAll(); order.removeAll()
            case endedTool, revokedTool, orphanedTool:
                drop(e.target)
            default:
                guard !e.session.isEmpty else { continue }
                if live[e.session] == nil { order.append(e.session) }
                live[e.session] = (e.identity, e.origin?.name ?? "")
            }
        }
        return order.compactMap { key in live[key].map { (key, $0.identity, $0.name) } }
    }

    /// The `session.ended` row for a finished session.
    public static func endedEvent(_ s: SessionInfo) -> AuditEvent {
        let duration = Int64(((s.endedAt ?? Date()).timeIntervalSince(s.approvedAt)) * 1000)
        var ev = AuditEvent(
            identity: "", session: s.key, channel: channel, tool: endedTool,
            target: s.key,
            argsPreview: "\(s.name.isEmpty ? "agent" : s.name): \(s.calls) call\(s.calls == 1 ? "" : "s")"
                + (s.reason.map { ", \($0.rawValue)" } ?? ""),
            decision: "info", rule: "session.lifecycle",
            durationMs: max(0, duration))
        ev.origin = AuditEvent.Origin(name: s.name, app: s.app, pid: s.pid,
                                      signed: s.signed, signedBy: s.signedBy)
        return ev
    }

    /// Builds a `session.revoked` event.
    public static func revokedEvent(key: String) -> AuditEvent {
        AuditEvent(session: key, channel: channel, tool: revokedTool, target: key,
                   argsPreview: "Revoked by the user", decision: "info",
                   rule: "session.lifecycle")
    }

    /// The `session.orphaned` reconciliation row.
    public static func orphanedEvent(key: String, identity: String, name: String) -> AuditEvent {
        AuditEvent(identity: identity, session: key, channel: channel, tool: orphanedTool,
                   target: key,
                   argsPreview: "\(name.isEmpty ? "Agent" : name): session was open when the app stopped; end time unknown",
                   decision: "info", rule: "session.lifecycle")
    }

    /// A vault lock or unlock boundary row.
    public static func boundaryEvent(locked: Bool) -> AuditEvent {
        AuditEvent(channel: vaultChannel, tool: locked ? lockedTool : unlockedTool,
                   argsPreview: locked ? "All active sessions ended" : "",
                   decision: "info", rule: "vault.lifecycle")
    }
}
