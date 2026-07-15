import Foundation

/// A classified ssh command (danger-token highlighting for the approval card).
public struct CmdInfo: Sendable, Equatable {
    public var raw: String
    public var argv: [String]
    public var cls: String      // readonly | write | composite | unknown
    public var binary: String
    public init(raw: String = "", argv: [String] = [], cls: String = "", binary: String = "") {
        self.raw = raw; self.argv = argv; self.cls = cls; self.binary = binary
    }
}

/// Labels an SSH command by risk class.
/// Pipes, redirects, subshells, sudo, and unknown binaries use a conservative class.
public enum Classify {
    public static func classify(_ cmd: String) -> CmdInfo {
        let raw = cmd.trimmingCharacters(in: .whitespacesAndNewlines)
        var info = CmdInfo(raw: raw)
        if raw.isEmpty { info.cls = "unknown"; return info }
        if hasComposition(raw) { info.cls = "composite"; return info }

        let fields = raw.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
        info.argv = fields
        info.binary = fields[0]

        // RouterOS commands such as `/system identity print` are classified by verb.
        if let cls = classifyRouterOS(fields) { info.cls = cls; return info }

        if readonlyBinaries.contains(info.binary) {
            info.cls = "readonly"
        } else if writeBinaries.contains(info.binary) {
            info.cls = "write"
        } else {
            info.cls = "unknown"
        }
        return info
    }

    /// Labels a MikroTik/RouterOS command by verb; nil when not RouterOS.
    static func classifyRouterOS(_ fields: [String]) -> String? {
        let first = fields[0]
        guard first.hasPrefix("/") else { return nil }
        let seg = first.dropFirst().split(separator: "/", maxSplits: 1).first.map(String.init) ?? ""
        guard routerOSMenus.contains(seg) else { return nil }

        var toks: [String] = []
        for f in fields { toks.append(contentsOf: f.split(separator: "/").map(String.init)) }
        for t in toks where routerOSWriteVerbs.contains(t) { return "write" }
        for t in toks where routerOSReadVerbs.contains(t) { return "readonly" }
        return "write" // Unknown RouterOS verbs default to write.
    }

    /// True when the command uses shell composition.
    static func hasComposition(_ cmd: String) -> Bool {
        let tokens = [";", "&&", "||", "|", "$(", "`", ">", "<", "&"]
        for t in tokens where cmd.contains(t) { return true }
        for w in cmd.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init) {
            switch w {
            case "sudo", "for", "while", "if", "do", "then", "eval", "exec", "source", ".":
                return true
            default: break
            }
        }
        return cmd.contains("bash -c") || cmd.contains("sh -c")
    }

    static let routerOSMenus: Set<String> = [
        "system", "ip", "ipv6", "interface", "routing", "user", "file", "tool",
        "ppp", "queue", "certificate", "log", "snmp", "radius", "disk", "port",
        "bridge", "mpls", "ospf", "bgp", "console", "export", "import", "caps-man",
        "container", "partitions", "password", "wireless", "ethernet", "vlan",
    ]
    static let routerOSReadVerbs: Set<String> = ["print", "export", "get", "monitor", "find"]
    static let routerOSWriteVerbs: Set<String> = [
        "set", "add", "remove", "enable", "disable", "reset", "reboot", "shutdown",
        "move", "unset", "comment", "edit", "upgrade", "downgrade", "make-backup",
        "restore", "import", "run",
    ]
    static let readonlyBinaries: Set<String> = [
        "cat", "ls", "df", "du", "uptime", "uname", "hostname", "whoami", "id",
        "free", "ps", "top", "date", "echo", "pwd", "stat", "head", "tail", "wc",
        "journalctl", "dmesg", "who", "w", "env", "printenv", "lsblk", "lscpu",
        "getent", "dig", "nslookup", "ip", "ss", "netstat", "mount",
    ]
    static let writeBinaries: Set<String> = [
        "apt", "apt-get", "yum", "dnf", "systemctl", "service", "docker",
        "kill", "pkill", "mv", "cp", "chmod", "chown", "ln", "mkdir", "touch",
    ]
}
