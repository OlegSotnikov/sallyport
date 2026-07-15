import Foundation

/// Legacy setup paths and launch-agent models retained for compatibility.

// MARK: - Paths

/// Sallyport paths derived from a home directory.
public struct OnboardingPaths: Sendable, Equatable {
    /// Current user's home directory.
    public let home: String
    /// Legacy launch-agent property list.
    public let launchAgentPlist: String
    /// Vault database.
    public let vaultDB: String
    /// Keystore metadata.
    public let keystore: String
    /// Legacy service log.
    public let daemonLog: String
    /// Sallyport data directory.
    public let sallyportHome: String

    public init(home: String) {
        self.home = home
        let ns = home as NSString
        self.sallyportHome = ns.appendingPathComponent(".sallyport")
        self.launchAgentPlist = ns.appendingPathComponent("Library/LaunchAgents/\(LaunchAgent.label).plist")
        self.vaultDB = ns.appendingPathComponent(".sallyport/vault.db")
        self.keystore = ns.appendingPathComponent(".sallyport/keystore.json")
        self.daemonLog = ns.appendingPathComponent("Library/Logs/sallyport/daemon.log")
    }

    /// Paths under `NSHomeDirectory()`.
    public static var live: OnboardingPaths { OnboardingPaths(home: NSHomeDirectory()) }
}

// MARK: - State probe

/// Reads legacy setup state from the filesystem.
public struct OnboardingProbe: Sendable {
    public let paths: OnboardingPaths
    private let fileExists: @Sendable (String) -> Bool
    /// Optional check for the legacy launch agent.
    private let isAgentLoaded: (@Sendable () -> Bool)?

    public init(
        paths: OnboardingPaths,
        fileExists: @escaping @Sendable (String) -> Bool = { FileManager.default.fileExists(atPath: $0) },
        isAgentLoaded: (@Sendable () -> Bool)? = nil
    ) {
        self.paths = paths
        self.fileExists = fileExists
        self.isAgentLoaded = isAgentLoaded
    }

    /// Whether the legacy launch agent is installed and, when checked, loaded.
    public var agentInstalled: Bool {
        guard fileExists(paths.launchAgentPlist) else { return false }
        return isAgentLoaded?() ?? true
    }

    /// Whether both vault files exist.
    public var vaultCreated: Bool {
        fileExists(paths.vaultDB) && fileExists(paths.keystore)
    }
}

// MARK: - LaunchAgent

/// Legacy launch-agent identifiers.
public enum LaunchAgent {
    /// Launchd job label.
    public static let label = "dev.sallyport.daemon"
}

/// Serializable legacy launch-agent property list.
public struct LaunchAgentSpec: Sendable, Equatable {
    public var label: String
    public var programArguments: [String]
    public var runAtLoad: Bool
    public var keepAlive: Bool
    public var standardOutPath: String
    public var standardErrorPath: String

    public init(
        label: String,
        programArguments: [String],
        runAtLoad: Bool,
        keepAlive: Bool,
        standardOutPath: String,
        standardErrorPath: String
    ) {
        self.label = label
        self.programArguments = programArguments
        self.runAtLoad = runAtLoad
        self.keepAlive = keepAlive
        self.standardOutPath = standardOutPath
        self.standardErrorPath = standardErrorPath
    }

    /// Builds the retired service specification.
    public static func daemon(daemonPath: String, paths: OnboardingPaths) -> LaunchAgentSpec {
        LaunchAgentSpec(
            label: LaunchAgent.label,
            programArguments: [daemonPath, "daemon"],
            runAtLoad: true,
            keepAlive: true,
            standardOutPath: paths.daemonLog,
            standardErrorPath: paths.daemonLog)
    }

    /// The launchd property-list dictionary (Foundation object graph).
    public var plistObject: [String: Any] {
        [
            "Label": label,
            "ProgramArguments": programArguments,
            "RunAtLoad": runAtLoad,
            "KeepAlive": keepAlive,
            "StandardOutPath": standardOutPath,
            "StandardErrorPath": standardErrorPath,
        ]
    }

    /// Serializes the property list as XML.
    public func xmlData() throws -> Data {
        try PropertyListSerialization.data(fromPropertyList: plistObject, format: .xml, options: 0)
    }
}
