import AppKit
import UserNotifications
import SallyportKit

/// Posts native approval notifications and routes their actions to `AppModel`.
/// When notifications are unavailable, `AppModel` uses `ApprovalPanelController`.
@MainActor
final class ApprovalNotifier: NSObject {
    /// The model the delegate calls back into. Weak: the model owns the notifier.
    weak var model: AppModel?

    /// Created on first use because `current()` requires an app bundle.
    /// `current()` raises an Objective-C exception (not a catchable Swift error)
    /// when the process has no application bundle, as in `swift test`/`swift run`.
    /// In that environment notifications are unavailable and the caller
    /// falls back to the in-app panel.
    private lazy var center: UNUserNotificationCenter? = {
        guard Bundle.main.bundleURL.pathExtension == "app" else { return nil }
        return UNUserNotificationCenter.current()
    }()
    /// Category and delegate registration guard.
    private var registered = false

    // MARK: - Registration / authorization

    /// Registers the approval category and notification delegate once.
    private func registerIfNeeded() {
        guard !registered else { return }
        guard let center else { return }
        registered = true
        // Approve activates the app so biometric modes can present Touch ID.
        let approve = UNNotificationAction(
            identifier: ApprovalNotification.ActionID.approve,
            title: "Approve",
            options: [.foreground])
        let deny = UNNotificationAction(
            identifier: ApprovalNotification.ActionID.deny,
            title: "Deny",
            options: [.destructive])
        let category = UNNotificationCategory(
            identifier: ApprovalNotification.categoryIdentifier,
            actions: [approve, deny],
            intentIdentifiers: [],
            options: [])
        center.setNotificationCategories([category])
        center.delegate = self
    }

    /// Requests notification permission and returns the current authorization result.
    @discardableResult
    func requestAuthorization() async -> Bool {
        registerIfNeeded()
        guard let center else { return false }
        // Use the completion-handler API because the notification center is not
        // Sendable on older SDKs. The callback may run off the main thread.
        let (granted, error) = await withCheckedContinuation { (cont: CheckedContinuation<(Bool, (any Error)?), Never>) in
            center.requestAuthorization(options: [.alert, .sound]) { @Sendable granted, error in
                cont.resume(returning: (granted, error))
            }
        }
        if let error {
            Log.line("notification auth request failed: \(error)")
        }
        return granted
    }

    /// Maps current authorization to the view-independent Kit enum.
    func authorizationStatus() async -> ApprovalNotification.Authorization {
        guard let center else { return .denied }
        let status = await withCheckedContinuation { (cont: CheckedContinuation<UNAuthorizationStatus, Never>) in
            center.getNotificationSettings { @Sendable settings in cont.resume(returning: settings.authorizationStatus) }
        }
        return status.kitAuthorization
    }

    /// Maps the macOS notification style to the Kit enum.
    func alertStyle() async -> ApprovalNotification.AlertStyle {
        guard let center else { return .none }
        let style = await withCheckedContinuation { (cont: CheckedContinuation<UNAlertStyle, Never>) in
            center.getNotificationSettings { @Sendable settings in cont.resume(returning: settings.alertStyle) }
        }
        return style.kitAlertStyle
    }

    // MARK: - Present / clear

    /// Posts an immediate approval notification with the requesting app icon when available.
    func present(_ request: ApprovalRequest) {
        registerIfNeeded()
        guard let center else { return }
        let spec = ApprovalNotification.content(for: request)
        let content = UNMutableNotificationContent()
        content.title = spec.title
        content.subtitle = spec.subtitle
        content.body = spec.body
        content.categoryIdentifier = spec.categoryIdentifier
        content.userInfo = ["requestID": spec.requestID]
        content.interruptionLevel = .timeSensitive
        content.sound = .default
        if let attachment = Self.iconAttachment(provenance: request.provenance, id: request.id) {
            content.attachments = [attachment]
        }
        // Use the request ID so resolution can remove the notification.
        let req = UNNotificationRequest(identifier: spec.identifier, content: content, trigger: nil)
        center.add(req) { @Sendable error in
            if let error { Log.line("notification post failed: \(error)") }
        }
    }

    /// Remove the banner for a resolved request (both delivered and pending).
    func clear(requestID: String) {
        guard let center else { return }
        center.removeDeliveredNotifications(withIdentifiers: [requestID])
        center.removePendingNotificationRequests(withIdentifiers: [requestID])
    }

    /// Posts a credential-request notification without approval actions.
    func presentCredentialRequest(_ req: CredentialRequest) {
        registerIfNeeded()
        guard let center else { return }
        let origin = req.provenance.origin.appName ?? req.provenance.origin.name
        let content = UNMutableNotificationContent()
        content.title = "\(origin) needs a key"
        content.subtitle = "Add a credential for \(req.host)"
        content.body = req.purpose.isEmpty ? "Open Sallyport to add the key." : req.purpose
        content.userInfo = ["requestID": req.id]
        content.interruptionLevel = .timeSensitive
        content.sound = .default
        if let attachment = Self.iconAttachment(provenance: req.provenance, id: req.id) {
            content.attachments = [attachment]
        }
        let r = UNNotificationRequest(identifier: req.id, content: content, trigger: nil)
        center.add(r) { @Sendable error in
            if let error { Log.line("credential-request notification failed: \(error)") }
        }
    }

    /// Posts a test notification without approval actions.
    func presentTest() {
        registerIfNeeded()
        guard let center else { return }
        let content = UNMutableNotificationContent()
        content.title = "Sallyport"
        content.subtitle = "Test notification"
        content.body = "Approvals will appear here."
        content.interruptionLevel = .timeSensitive
        content.sound = .default
        // A test notification has no requesting-app attachment.
        let req = UNNotificationRequest(identifier: "sallyport.test", content: content, trigger: nil)
        center.add(req) { @Sendable error in
            if let error { Log.line("test notification failed: \(error)") }
        }
    }

    // MARK: - Requesting app icon

    /// Resolves the nearest GUI application in the process chain and attaches its icon.
    private static func iconAttachment(provenance: Provenance, id: String) -> UNNotificationAttachment? {
        // Omit the attachment when no GUI application is available.
        let pids = [provenance.origin.pid] + provenance.chain.map(\.pid)
        guard let guiIcon = pids.lazy.compactMap({ AppIconResolver.icon(forPID: $0) }).first else { return nil }
        return attach(guiIcon, id: id)
    }

    /// Write an NSImage to a temp PNG and wrap it as a notification attachment.
    private static func attach(_ icon: NSImage?, id: String) -> UNNotificationAttachment? {
        guard let icon, let png = icon.sallyportPNGData() else { return nil }
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("sallyport-notif-icons", isDirectory: true)
        do {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            let url = dir.appendingPathComponent("icon-\(id).png")
            try png.write(to: url, options: .atomic)
            return try UNNotificationAttachment(identifier: "icon-\(id)", url: url, options: nil)
        } catch {
            Log.line("notification icon attach failed: \(error)")
            return nil
        }
    }
}

// MARK: - UNUserNotificationCenterDelegate

extension ApprovalNotifier: UNUserNotificationCenterDelegate {
    /// Maps a notification response to an application decision.
    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse,
        withCompletionHandler completionHandler: @escaping () -> Void
    ) {
        let actionID = response.actionIdentifier
        let requestID = response.notification.request.content.userInfo["requestID"] as? String
        let decision = ApprovalNotification.decision(
            forActionID: actionID,
            isDefault: actionID == UNNotificationDefaultActionIdentifier,
            isDismiss: actionID == UNNotificationDismissActionIdentifier)
        if let requestID {
            Task { @MainActor [weak self] in
                await self?.model?.handleNotificationDecision(decision, requestID: requestID)
            }
        }
        completionHandler()
    }

    /// Show the banner (with sound) even when the app is frontmost.
    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        completionHandler([.banner, .sound])
    }
}

// MARK: - Framework to Kit bridging

extension UNAuthorizationStatus {
    /// Map the framework status onto the view-free Kit enum used by the
    /// surface-selection logic.
    var kitAuthorization: ApprovalNotification.Authorization {
        switch self {
        case .notDetermined: return .notDetermined
        case .denied: return .denied
        case .authorized: return .authorized
        case .provisional: return .provisional
        case .ephemeral: return .ephemeral
        @unknown default: return .denied
        }
    }
}

extension UNAlertStyle {
    /// Map the framework alert style onto the view-free Kit enum so the
    /// "switch to Alerts" nudge logic stays testable.
    var kitAlertStyle: ApprovalNotification.AlertStyle {
        switch self {
        case .none: return .none
        case .banner: return .banner
        case .alert: return .alert
        @unknown default: return .banner
        }
    }
}

private extension NSImage {
    /// Encodes PNG data for a notification attachment.
    func sallyportPNGData() -> Data? {
        guard let tiff = tiffRepresentation,
              let rep = NSBitmapImageRep(data: tiff) else { return nil }
        return rep.representation(using: .png, properties: [:])
    }
}
