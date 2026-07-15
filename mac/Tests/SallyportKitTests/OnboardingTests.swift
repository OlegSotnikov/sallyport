import Foundation
import Testing
@testable import SallyportKit

@Suite("Onboarding state probe")
struct OnboardingProbeTests {

    /// A probe over an injected set of "existing" paths — no real filesystem.
    private func probe(home: String = "/Users/tester",
                       existing: Set<String>,
                       agentLoaded: Bool? = nil) -> OnboardingProbe {
        let paths = OnboardingPaths(home: home)
        let loadedChecker: (@Sendable () -> Bool)?
        if let agentLoaded {
            loadedChecker = { agentLoaded }
        } else {
            loadedChecker = nil
        }
        return OnboardingProbe(
            paths: paths,
            fileExists: { existing.contains($0) },
            isAgentLoaded: loadedChecker)
    }

    @Test("fresh machine: nothing done")
    func fresh() {
        let p = probe(existing: [])
        #expect(p.agentInstalled == false)
        #expect(p.vaultCreated == false)
    }

    @Test("agentInstalled follows the LaunchAgent plist when no loaded-checker")
    func agentPlistPresence() {
        let paths = OnboardingPaths(home: "/Users/tester")
        #expect(probe(existing: [paths.launchAgentPlist]).agentInstalled == true)
        #expect(probe(existing: []).agentInstalled == false)
    }

    @Test("a loaded-checker gates agentInstalled: plist present but not loaded → false")
    func agentPlistPresentNotLoaded() {
        let paths = OnboardingPaths(home: "/Users/tester")
        #expect(probe(existing: [paths.launchAgentPlist], agentLoaded: false).agentInstalled == false)
        #expect(probe(existing: [paths.launchAgentPlist], agentLoaded: true).agentInstalled == true)
    }

    @Test("loaded-checker is not consulted when the plist is absent")
    func loadedIgnoredWhenNoPlist() {
        // Even if launchctl claims a service is loaded, no plist ⇒ not installed.
        #expect(probe(existing: [], agentLoaded: true).agentInstalled == false)
    }

    @Test("vaultCreated needs BOTH vault.db and keystore.json")
    func vaultNeedsBoth() {
        let paths = OnboardingPaths(home: "/Users/tester")
        #expect(probe(existing: [paths.vaultDB]).vaultCreated == false)
        #expect(probe(existing: [paths.keystore]).vaultCreated == false)
        #expect(probe(existing: [paths.vaultDB, paths.keystore]).vaultCreated == true)
    }

    @Test("all three artifacts present → both file-facts true")
    func allPresent() {
        let paths = OnboardingPaths(home: "/Users/tester")
        let p = probe(existing: [paths.launchAgentPlist, paths.vaultDB, paths.keystore], agentLoaded: true)
        #expect(p.agentInstalled == true)
        #expect(p.vaultCreated == true)
    }
}

@Suite("Onboarding paths")
struct OnboardingPathsTests {

    @Test("paths derive from home with the expected layout")
    func derivation() {
        let p = OnboardingPaths(home: "/Users/tester")
        #expect(p.sallyportHome == "/Users/tester/.sallyport")
        #expect(p.vaultDB == "/Users/tester/.sallyport/vault.db")
        #expect(p.keystore == "/Users/tester/.sallyport/keystore.json")
        #expect(p.launchAgentPlist == "/Users/tester/Library/LaunchAgents/dev.sallyport.daemon.plist")
        #expect(p.daemonLog == "/Users/tester/Library/Logs/sallyport/daemon.log")
    }

    @Test("the plist filename uses the LaunchAgent label")
    func labelMatchesPlist() {
        let p = OnboardingPaths(home: "/h")
        #expect(p.launchAgentPlist.hasSuffix("/\(LaunchAgent.label).plist"))
    }
}

@Suite("LaunchAgent plist")
struct LaunchAgentSpecTests {

    @Test("daemon spec carries the required launchd keys")
    func daemonSpec() {
        let paths = OnboardingPaths(home: "/Users/tester")
        let spec = LaunchAgentSpec.daemon(daemonPath: "/Apps/Sallyport.app/Contents/MacOS/sallyportd", paths: paths)
        #expect(spec.label == "dev.sallyport.daemon")
        #expect(spec.programArguments == ["/Apps/Sallyport.app/Contents/MacOS/sallyportd", "daemon"])
        #expect(spec.runAtLoad == true)
        #expect(spec.keepAlive == true)
        #expect(spec.standardOutPath == paths.daemonLog)
        #expect(spec.standardErrorPath == paths.daemonLog)
    }

    @Test("xmlData is a valid XML plist that round-trips to the same values")
    func xmlRoundTrip() throws {
        let paths = OnboardingPaths(home: "/Users/tester")
        let spec = LaunchAgentSpec.daemon(daemonPath: "/bin/sallyportd", paths: paths)
        let data = try spec.xmlData()

        // It is genuinely XML (launchd rejects non-XML LaunchAgents written by hand).
        let head = String(decoding: data.prefix(6), as: UTF8.self)
        #expect(head == "<?xml ")

        let obj = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any]
        #expect(obj?["Label"] as? String == "dev.sallyport.daemon")
        #expect(obj?["ProgramArguments"] as? [String] == ["/bin/sallyportd", "daemon"])
        #expect(obj?["RunAtLoad"] as? Bool == true)
        #expect(obj?["KeepAlive"] as? Bool == true)
        #expect(obj?["StandardOutPath"] as? String == paths.daemonLog)
        #expect(obj?["StandardErrorPath"] as? String == paths.daemonLog)
    }
}


