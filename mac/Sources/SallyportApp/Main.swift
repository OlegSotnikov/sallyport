import AppKit
import Foundation

/// Handles `--selftest` and `--init` without launching the GUI, then starts the
/// SwiftUI app for normal launches.
@main
enum AppMain {
    static func main() {
        if CommandLine.arguments.contains("--selftest") {
            SelfTest.run()   // calls exit(), never returns
        }
        if CommandLine.arguments.contains("--init") {
            VaultInitCLI.run()   // calls exit(), never returns
        }
        // Single instance: two GUIs would fight over the vault home + agent
        // socket. macOS de-dupes a normal `open`, but running the executable
        // directly or during a launch race can spawn a second instance.
        // Check after standalone CLI flags, which are meant to run alone.
        if let bid = Bundle.main.bundleIdentifier {
            let mePID = NSRunningApplication.current.processIdentifier
            if let sourcePID = AppRelaunch.sourcePID(in: CommandLine.arguments) {
                AppRelaunch.waitForSourceExit(pid: sourcePID)
            }
            func liveSibling() -> NSRunningApplication? {
                NSRunningApplication.runningApplications(withBundleIdentifier: bid)
                    .first { $0.processIdentifier != mePID && !$0.isTerminated }
            }
            // A Sparkle relaunch can briefly overlap with the previous instance.
            // Wait up to one second before treating a sibling as a duplicate.
            var sibling = liveSibling()
            for _ in 0..<10 where sibling != nil {
                Thread.sleep(forTimeInterval: 0.1)
                sibling = liveSibling()
            }
            if let sibling {
                sibling.activate()
                exit(0)
            }
        }
        #if DEBUG
        if CommandLine.arguments.contains("--render-ui") {
            MainActor.assumeIsolated { RenderUI.run() }   // calls exit(), never returns
        }
        if CommandLine.arguments.contains("--verify-unlock") {
            VaultInitCLI.verifyUnlock()   // opens ~/.sallyport, unlocks, prints, exits
        }
        #endif
        SallyportApp.main()
    }
}
