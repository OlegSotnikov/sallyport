import AppKit

/// Resolves the GUI app name + icon for a PID via `NSRunningApplication`, the
/// display half of provenance enrichment (the signature half lives in the Kit).
@MainActor
enum AppIconResolver {
    static func runningApp(forPID pid: Int) -> NSRunningApplication? {
        NSRunningApplication(processIdentifier: pid_t(pid))
    }

    static func icon(forPID pid: Int) -> NSImage? {
        runningApp(forPID: pid)?.icon
    }

    static func appName(forPID pid: Int) -> String? {
        runningApp(forPID: pid)?.localizedName
    }
}
