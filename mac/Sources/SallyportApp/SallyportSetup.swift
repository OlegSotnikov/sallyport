import Foundation
import SallyportKit

/// Paths and signed-bundle helper lookup.
struct SallyportSetup: Sendable {
    let paths: OnboardingPaths

    init(paths: OnboardingPaths = .live) { self.paths = paths }

    // MARK: Bundled binaries

    /// Locates a bundled helper binary.
    ///
    /// - Signed `.app`: `Contents/MacOS/<name>` via `url(forAuxiliaryExecutable:)`
    ///   (build-app.sh copies + signs them there).
    /// - Dev/test override: `$SALLYPORT_CORE_BIN/<name>`.
    /// - Fallback: a sibling of the app's own executable.
    static func bundledBinary(_ name: String) -> URL? {
        let fm = FileManager.default
        // The environment override is limited to debug builds. Release builds
        // use the helper signed inside the app bundle.
        #if DEBUG
        if let dir = ProcessInfo.processInfo.environment["SALLYPORT_CORE_BIN"] {
            let url = URL(fileURLWithPath: dir).appendingPathComponent(name)
            if fm.isExecutableFile(atPath: url.path) { return url }
        }
        #endif
        if let url = Bundle.main.url(forAuxiliaryExecutable: name),
           fm.isExecutableFile(atPath: url.path) {
            return url
        }
        if let exe = Bundle.main.executableURL {
            let url = exe.deletingLastPathComponent().appendingPathComponent(name)
            if fm.isExecutableFile(atPath: url.path) { return url }
        }
        return nil
    }

}

// MARK: - Errors

/// User-facing failures for irreversible gate/reset operations.
enum SetupError: LocalizedError, Equatable {
    case gateEnable(String)
    case reset(String)

    var errorDescription: String? {
        switch self {
        case .gateEnable(let detail):
            return String(localized: "Enabling the hardware gate failed: \(detail)",
                          comment: "Hardware-gate error followed by a localized detail.")
        case .reset(let detail):
            return detail
        }
    }
}
