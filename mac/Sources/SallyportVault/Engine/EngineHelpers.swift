import Foundation
import SallyportKit

/// SSH connection metadata. The key is fetched by `keyName`.
public struct HostRef: Sendable, Hashable {
    public var name: String
    public var addr: String
    public var user: String
    public var port: Int
    public var hostKeyPolicy: String   // "accept-new" | "strict"
    public var keyName: String
    public var tags: [String]
    public init(name: String, addr: String = "", user: String = "root", port: Int = 22,
                hostKeyPolicy: String = "accept-new", keyName: String = "", tags: [String] = []) {
        self.name = name; self.addr = addr; self.user = user; self.port = port
        self.hostKeyPolicy = hostKeyPolicy; self.keyName = keyName; self.tags = tags
    }
}

/// Executes SSH commands through the bundled helper.
public protocol SSHExecuting: Sendable {
    /// Resolve an inventory host by the name an agent passed to `ssh.exec`.
    func host(_ name: String) -> HostRef?
    /// Run `command` on `host` with the vault-held `keyPEM`; DLP-redact the output.
    func execute(host: HostRef, command: String, timeoutS: Int, keyPEM: Data) async throws -> ExecOutput
}

extension Engine {
    static func channel(for tool: String) -> String {
        if tool.hasPrefix("http") { return "http" }
        if tool.hasPrefix("ssh") { return "ssh" }
        return "mcp"
    }

    /// hostname + path from a URL JSONValue arg.
    static func hostPath(_ v: JSONValue?) -> (String, String) {
        guard let s = v?.stringValue, let u = URLComponents(string: s) else { return ("", "") }
        return (u.host ?? "", u.path.isEmpty ? "/" : u.path)
    }

    static func intArg(_ v: JSONValue?) -> Int {
        switch v {
        case .int(let i): return i
        case .double(let d):
            // Direct `Int(Double)` conversion traps at either numeric boundary
            // (Double(Int.max) itself rounds one past Int.max). Truncate first,
            // then use exact conversion for untrusted JSON numbers.
            return Int(exactly: d.rounded(.towardZero)) ?? 0
        case .string(let s): return Int(s) ?? 0
        default: return 0
        }
    }

    /// Returns a unique request identifier.
    static func reqID() -> String { "req-\(UUID().uuidString.lowercased())" }

    static func reason(_ mode: String) -> String {
        switch mode {
        case "session": return "Approve this agent for the current session."
        case "session-touchid": return "Confirm this agent with Touch ID for the current session."
        case "per-call", "per-call-touchid": return "This action requires approval every time."
        default: return "Approve this action."
        }
    }

    /// Returns the stronger approval requirement.
    static func strongest(_ a: String, _ b: String) -> String {
        func rank(_ s: String) -> Int { s == "touchid" ? 2 : (s == "click" ? 1 : 0) }
        return rank(a) >= rank(b) ? a : b
    }

    static func summarize(_ action: Action, host: String) -> String {
        switch action.tool {
        case "http.request":
            let m = (action.args["method"]?.stringValue ?? "GET").uppercased()
            let url = action.args["url"]?.stringValue ?? host
            let mut = (m == "GET" || m == "HEAD") ? "" : " (mutating)"
            return "\(m) \(url)\(mut)"
        case "ssh.exec":
            return "$ \(action.args["cmd"]?.stringValue ?? "") on \(host)"
        case "sallyport.request_credential":
            let h = action.args["host"]?.stringValue ?? host
            return h.isEmpty ? "Add a credential" : "Add a key for \(h)"
        default:
            return "\(action.tool): \(argsSummary(action.args))"
        }
    }

    /// A short, redaction-safe args preview for the audit row.
    static func preview(_ action: Action) -> String {
        switch action.tool {
        case "http.request":
            let m = (action.args["method"]?.stringValue ?? "GET").uppercased()
            let (_, p) = hostPath(action.args["url"])
            return "\(m) \(p)"
        case "ssh.exec":
            return action.args["cmd"]?.stringValue ?? ""
        case "sallyport.request_credential":
            // Preview the requested credential purpose.
            return String((action.args["purpose"]?.stringValue ?? "add a key").prefix(80))
        default:
            return argsSummary(action.args)
        }
    }

    /// Returns a clipped argument summary for cards and audit rows.
    static func argsSummary(_ args: [String: JSONValue]) -> String {
        guard !args.isEmpty else { return "(no arguments)" }
        let parts = args.keys.sorted().prefix(6).map { key -> String in
            let v = args[key]?.displayString ?? ""
            return "\(key): \(v.count > 40 ? String(v.prefix(40)) + "…" : v)"
        }
        let text = parts.joined(separator: ", ")
        return text.count > 160 ? String(text.prefix(160)) + "…" : text
    }
}
