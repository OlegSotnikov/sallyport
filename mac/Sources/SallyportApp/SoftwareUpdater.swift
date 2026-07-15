import Foundation
import Observation
import Sparkle

/// Configures Sparkle for signed app bundles. Update checks are automatic, but
/// installation requires confirmation.
@MainActor
@Observable
final class SoftwareUpdater {
    @ObservationIgnored
    private let controller: SPUStandardUpdaterController?
    @ObservationIgnored
    private var canCheckObservation: NSKeyValueObservation?

    /// Whether Sparkle can start or foreground a user-initiated update check.
    private(set) var canCheck = false

    init() {
        if Bundle.main.object(forInfoDictionaryKey: "SUFeedURL") != nil {
            let controller = SPUStandardUpdaterController(startingUpdater: true,
                                                          updaterDelegate: nil,
                                                          userDriverDelegate: nil)
            self.controller = controller
            canCheck = controller.updater.canCheckForUpdates
            canCheckObservation = controller.updater.observe(
                \.canCheckForUpdates,
                options: [.new]
            ) { [weak self] _, change in
                let canCheck = change.newValue ?? false
                Task { @MainActor [weak self] in
                    self?.canCheck = canCheck
                }
            }
        } else {
            controller = nil
        }
    }

    /// Whether the app bundle includes a Sparkle update feed.
    var isAvailable: Bool { controller != nil }

    /// Opens Sparkle's standard update window.
    func checkForUpdates() {
        guard canCheck else { return }
        controller?.updater.checkForUpdates()
    }
}
