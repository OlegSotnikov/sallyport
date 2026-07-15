import Foundation

/// Builds approval notification content and maps notification actions to app decisions.
public enum ApprovalNotification {

    /// The single notification category registered with the center.
    public static let categoryIdentifier = "dev.sallyport.approval"

    /// Identifiers for the category's buttons (parsed back from a tapped action).
    public enum ActionID {
        public static let approve = "approve"
        public static let deny = "deny"
    }

    // MARK: - Content

    /// The fields posted as a `UNMutableNotificationContent`, computed purely
    /// from a request so they can be asserted in tests without the framework.
    public struct Content: Sendable, Equatable {
        /// Notification identifier == request id, so `clear(requestID:)` finds it.
        public var identifier: String
        /// Title = the requesting agent (its app name, else the process name).
        public var title: String
        /// Subtitle = the concise, channel-aware action line.
        public var subtitle: String
        /// Request reason shown below the action line.
        public var body: String
        public var categoryIdentifier: String
        /// Carried in `userInfo` so the delegate can find the request again.
        public var requestID: String
        /// Origin executable path used for the app-icon attachment.
        public var iconSourcePath: String?

        public init(identifier: String, title: String, subtitle: String, body: String,
                    categoryIdentifier: String, requestID: String, iconSourcePath: String?) {
            self.identifier = identifier
            self.title = title
            self.subtitle = subtitle
            self.body = body
            self.categoryIdentifier = categoryIdentifier
            self.requestID = requestID
            self.iconSourcePath = iconSourcePath
        }
    }

    /// Build the notification content for a request. Title is the requesting
    /// agent; subtitle is the action line; body is the approval reason.
    public static func content(for request: ApprovalRequest) -> Content {
        let origin = request.provenance.origin
        // Session approval covers the process. Other modes cover the current action.
        let isSession = request.mode == "session" || request.mode == "session-touchid"
        return Content(
            identifier: request.id,
            title: origin.appName ?? origin.name,
            subtitle: isSession ? "Requests access to Sallyport" : actionLine(for: request.action),
            body: request.why.reason,
            categoryIdentifier: categoryIdentifier,
            requestID: request.id,
            iconSourcePath: origin.path)
    }

    /// Builds a notification subtitle from the action and target host.
    public static func actionLine(for action: ActionDescriptor) -> String {
        let what = ApprovalPresentation.primaryActionText(action)
        let base: String
        switch action.channel.lowercased() {
        case "ssh":
            base = "\(action.tool) `\(what)`"
        default:
            base = what
        }
        if let host = action.host, !host.isEmpty {
            return "\(base) on \(host)"
        }
        return base
    }

    // MARK: - Decision mapping

    /// Decision produced by a notification action.
    public enum Decision: Sendable, Equatable {
        case approve
        case deny
        /// Opens the floating panel for full detail.
        case detail
        /// Leaves the request pending.
        case ignore
    }

    /// Map a response's action identifier to a decision. `isDefault` / `isDismiss`
    /// carry the system pseudo-actions (`UNNotificationDefaultActionIdentifier` /
    /// `UNNotificationDismissActionIdentifier`) so this stays free of the
    /// UserNotifications import and is fully unit-testable.
    public static func decision(forActionID actionID: String,
                                isDefault: Bool = false,
                                isDismiss: Bool = false) -> Decision {
        if isDefault { return .detail }
        if isDismiss { return .ignore }
        switch actionID {
        case ActionID.approve: return .approve
        case ActionID.deny: return .deny
        default: return .ignore
        }
    }

    // MARK: - Surface selection

    /// Surface used to present an approval.
    public enum Surface: Sendable, Equatable {
        case notification
        case panel
    }

    /// Framework-independent mirror of `UNAuthorizationStatus`.
    public enum Authorization: Sendable, Equatable {
        case notDetermined
        case denied
        case authorized
        case provisional
        case ephemeral
    }

    public static func surface(for authorization: Authorization) -> Surface {
        switch authorization {
        case .authorized, .provisional, .ephemeral: return .notification
        case .denied, .notDetermined: return .panel
        }
    }

    // MARK: - Delivery style (persistent vs auto-hiding)

    /// A view-independent mirror of `UNAlertStyle`.
    /// `.banner` auto-hides; `.alert` remains until the user acts.
    public enum AlertStyle: Sendable, Equatable {
        case none      // notifications off / no alert style
        case banner
        case alert
    }

    /// True when the notification remains until dismissed.
    public static func willPersist(_ style: AlertStyle) -> Bool { style == .alert }
}
