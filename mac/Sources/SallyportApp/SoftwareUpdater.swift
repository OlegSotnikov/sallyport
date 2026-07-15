import Foundation
import Sparkle

/// Configures Sparkle for signed app bundles. Update checks are automatic, but
/// installation requires confirmation.
@MainActor
final class SoftwareUpdater {
    private let controller: SPUStandardUpdaterController?

    init() {
        if Bundle.main.object(forInfoDictionaryKey: "SUFeedURL") != nil {
            controller = SPUStandardUpdaterController(startingUpdater: true,
                                                      updaterDelegate: nil,
                                                      userDriverDelegate: nil)
        } else {
            controller = nil
        }
    }

    /// Whether the app bundle includes an update feed.
    var canCheck: Bool { controller != nil }

    /// Opens Sparkle's standard update window.
    func checkForUpdates() { controller?.updater.checkForUpdates() }
}
