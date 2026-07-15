import Foundation

/// Runtime options read from the environment and build configuration.
enum SallyportRuntime {

    /// Debug-only headless mode that skips biometric approval.
    static var devAutoApprove: Bool {
        #if DEBUG
        return ProcessInfo.processInfo.environment["SALLYPORT_DEV_AUTOAPPROVE"] == "1"
        #else
        return false
        #endif
    }

    /// Enables stderr logging explicitly or in debug auto-approval mode.
    static var verboseLog: Bool {
        devAutoApprove || ProcessInfo.processInfo.environment["SALLYPORT_LOG"] == "1"
    }
}

/// Stderr logger controlled by `SallyportRuntime.verboseLog`.
enum Log {
    nonisolated static func line(_ message: @autoclosure () -> String) {
        guard SallyportRuntime.verboseLog else { return }
        let text = "sallyport-app: " + message() + "\n"
        FileHandle.standardError.write(Data(text.utf8))
    }
}
