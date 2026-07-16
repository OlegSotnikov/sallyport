import Foundation
import SallyportKit

/// Localized framing for approval data produced by Sallyport's engine.
/// Unknown tool output and caller-supplied values are returned unchanged.
enum ApprovalCopy {
    /// Localizes the finite set of reasons emitted by `Engine.reason`.
    static func reason(_ rawValue: String, locale: Locale = .current) -> String {
        switch rawValue {
        case "Approve this agent for the current session.":
            return String(localized: "Allow this process for the current session.",
                          bundle: .main, locale: locale,
                          comment: "Approval reason for one agent session")
        case "Confirm this agent with Touch ID for the current session.":
            return String(localized: "Allow this process for the current session with Touch ID.",
                          bundle: .main, locale: locale,
                          comment: "Approval reason for a Touch ID-protected agent session")
        case "This action requires approval every time.":
            return String(localized: "This action requires approval every time.",
                          bundle: .main, locale: locale,
                          comment: "Approval reason for a per-call policy")
        case "Approve this action.":
            return String(localized: "Approve this action.",
                          bundle: .main, locale: locale,
                          comment: "Fallback approval reason")
        case "class=write · session recorded":
            return String(localized: "Write action · session recorded",
                          bundle: .main, locale: locale,
                          comment: "Demo approval reason for an action that writes data")
        case "class=destructive · session recorded":
            return String(localized: "Destructive action · session recorded",
                          bundle: .main, locale: locale,
                          comment: "Demo approval reason for a destructive action")
        case "first call from this agent this session":
            return String(localized: "First call from this agent in this session.",
                          bundle: .main, locale: locale,
                          comment: "Demo approval reason for a new agent session")
        default:
            let prefix = "bound credential: "
            guard rawValue.hasPrefix(prefix), rawValue.count > prefix.count else {
                return rawValue
            }
            let credential = String(rawValue.dropFirst(prefix.count))
            return String(localized: "Bound credential: \(credential)",
                          bundle: .main, locale: locale,
                          comment: "Demo approval reason; the credential name is external data")
        }
    }

    /// Removes engine-owned transport framing and localizes known summary text.
    /// Commands, URLs, host names, tool names, and unknown summaries stay verbatim.
    static func actionText(_ action: ActionDescriptor, locale: Locale = .current) -> String {
        let rawValue = ApprovalPresentation.primaryActionText(action)

        switch action.tool {
        case "ssh.exec":
            return sshCommand(from: rawValue, host: action.host)
        case "http.request":
            let suffix = " (mutating)"
            guard rawValue.hasSuffix(suffix) else { return rawValue }
            let operation = String(rawValue.dropLast(suffix.count))
            return String(localized: "\(operation) (changes data)",
                          bundle: .main, locale: locale,
                          comment: "HTTP operation followed by a localized warning that it changes data")
        case "sallyport.request_credential":
            if rawValue == "Add a credential" {
                return String(localized: "Add a credential", bundle: .main, locale: locale,
                              comment: "Approval summary for adding a credential")
            }
            if let host = action.host, !host.isEmpty, rawValue == "Add a key for \(host)" {
                return String(localized: "Add a key for \(host)",
                              bundle: .main, locale: locale,
                              comment: "Approval summary for adding a key; host is external data")
            }
            return rawValue
        default:
            if rawValue == "\(action.tool): (no arguments)" {
                return String(localized: "\(action.tool): no arguments",
                              bundle: .main, locale: locale,
                              comment: "Tool name followed by an empty-arguments summary")
            }
            return rawValue
        }
    }

    /// Native-notification subtitle with localized app framing.
    static func notificationSubtitle(for request: ApprovalRequest,
                                     locale: Locale = .current) -> String {
        if request.mode == "session" || request.mode == "session-touchid" {
            return String(localized: "Requests a Sallyport session",
                          bundle: .main, locale: locale)
        }

        let action = actionText(request.action, locale: locale)
        let base = request.action.channel.lowercased() == "ssh"
            ? "\(request.action.tool) `\(action)`"
            : action

        if let host = request.action.host, !host.isEmpty {
            return String(localized: "\(base) on \(host)",
                          bundle: .main, locale: locale,
                          comment: "Approval notification subtitle; action and host are external data")
        }
        return base
    }

    /// The scope disclosed anywhere a session can be granted. This is kept in
    /// one place so the card, queue, and native notification cannot drift.
    static func sessionDisclosure(locale: Locale = .current) -> String {
        String(localized: "The session ends when this process exits, you revoke access, or the vault locks. Future requests won't prompt again unless per-call approval applies.",
               bundle: .main, locale: locale,
               comment: "Scope and repeat-prompt disclosure for a process session")
    }

    /// Exact original size and clipping state for a request-body preview.
    static func httpBodyMetadata(byteCount: Int, truncated: Bool,
                                 locale: Locale = .current) -> String {
        let bytes = byteCount.formatted(
            .byteCount(style: .file, allowedUnits: .bytes).locale(locale))
        if truncated {
            return String(localized: "Preview truncated · \(bytes) total",
                          bundle: .main, locale: locale,
                          comment: "HTTP approval body preview metadata; byte count is external data")
        }
        return bytes
    }

    /// Native-notification body. A session prompt describes the continuing
    /// grant; a per-call prompt keeps the policy reason for that action.
    static func notificationBody(for request: ApprovalRequest,
                                 locale: Locale = .current) -> String {
        if request.mode == "session" || request.mode == "session-touchid" {
            return sessionDisclosure(locale: locale)
        }
        return reason(request.why.reason, locale: locale)
    }

    /// Touch ID prompt with localized app framing.
    static func touchIDReason(for request: ApprovalRequest,
                              locale: Locale = .current) -> String {
        let origin = request.provenance.origin.appName ?? request.provenance.origin.name
        if request.mode == "session" || request.mode == "session-touchid" {
            return String(localized: "Allow a Sallyport session for \(origin)",
                          bundle: .main, locale: locale,
                          comment: "Touch ID prompt; the app name is external data")
        }
        let action = actionText(request.action, locale: locale)
        if let host = request.action.host, !host.isEmpty {
            return String(localized: "Approve: \(action) on \(host) (\(origin))",
                          bundle: .main, locale: locale,
                          comment: "Touch ID prompt. The action, host, and app name are external data.")
        }
        return String(localized: "Approve: \(action) (\(origin))",
                      bundle: .main, locale: locale,
                      comment: "Touch ID prompt. The action and app name are external data.")
    }

    /// `Engine.summarize` wraps SSH commands as `$ command on host`.
    private static func sshCommand(from rawValue: String, host: String?) -> String {
        guard let host, !host.isEmpty else { return rawValue }
        let prefix = "$ "
        let suffix = " on \(host)"
        guard rawValue.hasPrefix(prefix), rawValue.hasSuffix(suffix),
              rawValue.count >= prefix.count + suffix.count else { return rawValue }
        return String(rawValue.dropFirst(prefix.count).dropLast(suffix.count))
    }
}
