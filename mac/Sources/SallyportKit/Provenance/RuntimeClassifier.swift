import Foundation

/// How an executable relates to the code it runs. A shell or interpreter's
/// code signature names the runtime's vendor, not the script it executes, so
/// any identity built on it covers every script on the machine.
public enum RuntimeClass: String, Sendable, Codable {
    case shell
    case interpreter
}

/// Classifies executables that run other people's code (shells, script
/// runtimes). Display and policy context only — the classification derives
/// from the executable name, which is an honest kernel fact but not a
/// security boundary by itself.
public enum RuntimeClassifier {
    /// Executable basenames that execute arbitrary command strings.
    private static let shells: Set<String> = [
        "sh", "bash", "zsh", "fish", "dash", "ksh", "tcsh", "csh",
    ]

    /// Executable basenames that execute arbitrary scripts. Version suffixes
    /// ("python3.13", "php8") are stripped before matching.
    private static let interpreters: Set<String> = [
        "node", "bun", "deno", "python", "ruby", "perl", "php", "java",
        "osascript", "lua", "rscript", "electron",
    ]

    /// Classifies an executable, preferring the path basename over the
    /// (truncated) kernel process name.
    public static func classify(path: String, name: String) -> RuntimeClass? {
        let fromPath = basename(path)
        let base = fromPath.isEmpty ? name : fromPath
        let normalized = stripVersion(base.lowercased())
        if shells.contains(normalized) { return .shell }
        if interpreters.contains(normalized) { return .interpreter }
        return nil
    }

    private static func basename(_ path: String) -> String {
        guard let i = path.lastIndex(of: "/") else { return path }
        return String(path[path.index(after: i)...])
    }

    /// "python3.13" → "python", "php8" → "php", "node" → "node".
    private static func stripVersion(_ name: String) -> String {
        var s = Substring(name)
        while let last = s.last, last.isNumber || last == "." { s = s.dropLast() }
        return String(s)
    }
}
