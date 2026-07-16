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
    /// Run `command` on `host` with the vault-held `keyPEM`.
    func execute(host: HostRef, command: String, timeoutS: Int, keyPEM: Data) async throws -> ExecOutput
}

extension Engine {
    /// Display-only limits. Raw actions keep their full values for validation and execution.
    static let approvalSummaryMaxUTF8Bytes = 1_024
    static let httpBodyPreviewMaxUTF8Bytes = 4_096
    static let auditPreviewMaxUTF8Bytes = 256
    static let displayToolMaxUTF8Bytes = 256
    static let displayTargetMaxUTF8Bytes = 512

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

    /// Clips display text to a UTF-8 byte budget without splitting a Character.
    /// The returned ellipsis is included in `maxUTF8Bytes`.
    static func clippedPrefix(_ text: String, maxUTF8Bytes: Int) -> String {
        let ellipsis = "…"
        precondition(maxUTF8Bytes >= ellipsis.utf8.count)
        let bytes = text.utf8
        guard let probe = bytes.index(bytes.startIndex, offsetBy: maxUTF8Bytes,
                                      limitedBy: bytes.endIndex),
              probe != bytes.endIndex else { return text }

        let contentBytes = maxUTF8Bytes - ellipsis.utf8.count
        var end = bytes.index(bytes.startIndex, offsetBy: contentBytes)
        while end > bytes.startIndex, String.Index(end, within: text) == nil {
            end = bytes.index(before: end)
        }
        let stringEnd = String.Index(end, within: text) ?? text.startIndex
        return String(text[..<stringEnd]) + ellipsis
    }

    /// Clips the middle of display text so a command or URL's trailing payload
    /// remains visible. The returned ellipsis is included in `maxUTF8Bytes`.
    static func clippedMiddle(_ text: String, maxUTF8Bytes: Int) -> String {
        let ellipsis = "…"
        precondition(maxUTF8Bytes >= ellipsis.utf8.count)
        let bytes = text.utf8
        guard let probe = bytes.index(bytes.startIndex, offsetBy: maxUTF8Bytes,
                                      limitedBy: bytes.endIndex),
              probe != bytes.endIndex else { return text }

        let contentBytes = maxUTF8Bytes - ellipsis.utf8.count
        let headBytes = (contentBytes + 1) / 2
        let tailBytes = contentBytes - headBytes

        var headEnd = bytes.index(bytes.startIndex, offsetBy: headBytes)
        while headEnd > bytes.startIndex, String.Index(headEnd, within: text) == nil {
            headEnd = bytes.index(before: headEnd)
        }

        var tailStart = bytes.index(bytes.endIndex, offsetBy: -tailBytes)
        while tailStart < bytes.endIndex, String.Index(tailStart, within: text) == nil {
            tailStart = bytes.index(after: tailStart)
        }

        let stringHeadEnd = String.Index(headEnd, within: text) ?? text.startIndex
        let stringTailStart = String.Index(tailStart, within: text) ?? text.endIndex
        return String(text[..<stringHeadEnd]) + ellipsis + String(text[stringTailStart...])
    }

    static func displayTool(_ tool: String) -> String {
        clippedMiddle(tool, maxUTF8Bytes: displayToolMaxUTF8Bytes)
    }

    static func displayTarget(_ target: String) -> String {
        clippedMiddle(target, maxUTF8Bytes: displayTargetMaxUTF8Bytes)
    }

    /// Bounded display data for a per-call HTTP approval. This reads only the
    /// agent-supplied action body: credential injection happens later, inside
    /// `HTTPExecutor.execute`, so vault-held credential bytes cannot enter it.
    struct HTTPBodyDisplayPreview: Sendable, Equatable {
        let text: String
        let byteCount: Int
        let truncated: Bool
    }

    static func httpBodyDisplayPreview(_ action: Action) -> HTTPBodyDisplayPreview? {
        guard action.tool == "http.request",
              let body = action.args["body"]?.stringValue,
              !body.isEmpty else { return nil }

        let originalByteCount = body.utf8.count
        var display = body

        // Pretty-print only input that already fits the display budget. This
        // keeps a hostile multi-megabyte body out of the JSON parser.
        // If formatting itself would exceed the budget, keep the complete raw
        // body instead of losing information just to add whitespace.
        if originalByteCount <= httpBodyPreviewMaxUTF8Bytes,
           let pretty = prettyJSONPreservingTokens(body),
           pretty.utf8.count <= httpBodyPreviewMaxUTF8Bytes {
            display = pretty
        }

        let escaped = escapedBodyDisplayPrefix(
            display, maxUTF8Bytes: httpBodyPreviewMaxUTF8Bytes)
        return HTTPBodyDisplayPreview(
            text: escaped.text,
            byteCount: originalByteCount,
            truncated: escaped.truncated)
    }

    /// Makes invisible control characters explicit in the security UI while
    /// producing at most `maxUTF8Bytes`, including the truncation ellipsis.
    /// Tabs and line feeds remain layout characters; other C0/C1 controls and
    /// Unicode bidi controls are rendered as `\u{NNNN}`.
    private static func escapedBodyDisplayPrefix(
        _ text: String, maxUTF8Bytes: Int
    ) -> (text: String, truncated: Bool) {
        let ellipsis = "…"
        precondition(maxUTF8Bytes >= ellipsis.utf8.count)
        var pieces: [String] = []
        var byteCount = 0
        var truncated = false

        for character in text {
            let piece = character.unicodeScalars.map { scalar in
                bodyDisplayEscape(for: scalar) ?? String(scalar)
            }.joined()
            let pieceBytes = piece.utf8.count
            guard byteCount + pieceBytes <= maxUTF8Bytes else {
                truncated = true
                break
            }
            pieces.append(piece)
            byteCount += pieceBytes
        }

        if truncated {
            while byteCount + ellipsis.utf8.count > maxUTF8Bytes,
                  let removed = pieces.popLast() {
                byteCount -= removed.utf8.count
            }
            pieces.append(ellipsis)
        }
        return (pieces.joined(), truncated)
    }

    private static func bodyDisplayEscape(for scalar: Unicode.Scalar) -> String? {
        let value = scalar.value
        let isPreservedWhitespace = value == 0x09 || value == 0x0A
        let isControl = value <= 0x1F || (0x7F...0x9F).contains(value)
        let isBidiControl = value == 0x061C || (0x200E...0x200F).contains(value)
            || (0x202A...0x202E).contains(value) || (0x2066...0x2069).contains(value)
        guard (!isPreservedWhitespace && isControl) || isBidiControl else { return nil }

        let hex = String(value, radix: 16, uppercase: true)
        let padding = String(repeating: "0", count: max(0, 4 - hex.count))
        return "\\u{\(padding)\(hex)}"
    }

    /// Adds JSON layout without re-encoding values. In particular, large JSON
    /// numbers and key order remain exactly as the agent supplied them.
    /// Called only after the caller has enforced the 4 KiB input ceiling.
    private static func prettyJSONPreservingTokens(_ body: String) -> String? {
        guard (try? JSONDecoder().decode(JSONValue.self, from: Data(body.utf8))) != nil else {
            return nil
        }

        let characters = Array(body)
        var output = ""
        output.reserveCapacity(body.utf8.count)
        var depth = 0
        var inString = false
        var escaped = false

        func adjacentNonWhitespace(from index: Int, step: Int) -> Character? {
            var cursor = index + step
            while characters.indices.contains(cursor) {
                let character = characters[cursor]
                if !character.isWhitespace { return character }
                cursor += step
            }
            return nil
        }

        func appendLineIndent() {
            output.append("\n")
            output.append(String(repeating: "  ", count: depth))
        }

        for (index, character) in characters.enumerated() {
            if inString {
                output.append(character)
                if escaped {
                    escaped = false
                } else if character == "\\" {
                    escaped = true
                } else if character == "\"" {
                    inString = false
                }
                continue
            }

            switch character {
            case "\"":
                inString = true
                output.append(character)
            case "{", "[":
                output.append(character)
                depth += 1
                let closing: Character = character == "{" ? "}" : "]"
                if adjacentNonWhitespace(from: index, step: 1) != closing {
                    appendLineIndent()
                }
            case "}", "]":
                depth = max(0, depth - 1)
                let opening: Character = character == "}" ? "{" : "["
                if adjacentNonWhitespace(from: index, step: -1) != opening {
                    appendLineIndent()
                }
                output.append(character)
            case ",":
                output.append(character)
                appendLineIndent()
            case ":":
                output.append(": ")
            default:
                if !character.isWhitespace { output.append(character) }
            }
        }
        return output
    }

    static func summarize(_ action: Action, host: String) -> String {
        let raw: String
        switch action.tool {
        case "http.request":
            let method = clippedPrefix(action.args["method"]?.stringValue ?? "GET",
                                       maxUTF8Bytes: 32)
            let m = clippedPrefix(method.uppercased(), maxUTF8Bytes: 32)
            let url = clippedMiddle(action.args["url"]?.stringValue ?? host,
                                    maxUTF8Bytes: 896)
            let mut = (m == "GET" || m == "HEAD") ? "" : " (mutating)"
            raw = "\(m) \(url)\(mut)"
        case "ssh.exec":
            let command = clippedMiddle(action.args["cmd"]?.stringValue ?? "",
                                        maxUTF8Bytes: 768)
            let shownHost = clippedMiddle(host, maxUTF8Bytes: 224)
            raw = "$ \(command) on \(shownHost)"
        case "sallyport.request_credential":
            let h = displayTarget(action.args["host"]?.stringValue ?? host)
            raw = h.isEmpty ? "Add a credential" : "Add a key for \(h)"
        default:
            raw = "\(displayTool(action.tool)): \(argsSummary(action.args))"
        }
        return clippedMiddle(raw, maxUTF8Bytes: approvalSummaryMaxUTF8Bytes)
    }

    /// A bounded caller-data preview for the audit row. It may contain sensitive data.
    static func preview(_ action: Action) -> String {
        let raw: String
        switch action.tool {
        case "http.request":
            let method = clippedPrefix(action.args["method"]?.stringValue ?? "GET",
                                       maxUTF8Bytes: 32)
            let m = clippedPrefix(method.uppercased(), maxUTF8Bytes: 32)
            let (_, p) = hostPath(action.args["url"])
            raw = "\(m) \(clippedMiddle(p, maxUTF8Bytes: 208))"
        case "ssh.exec":
            raw = action.args["cmd"]?.stringValue ?? ""
        case "sallyport.request_credential":
            // Preview the requested credential purpose.
            raw = clippedMiddle(action.args["purpose"]?.stringValue ?? "add a key",
                                maxUTF8Bytes: 160)
        default:
            raw = argsSummary(action.args)
        }
        return clippedMiddle(raw, maxUTF8Bytes: auditPreviewMaxUTF8Bytes)
    }

    /// Returns a clipped argument summary for cards and audit rows.
    static func argsSummary(_ args: [String: JSONValue]) -> String {
        guard !args.isEmpty else { return "(no arguments)" }
        let parts = args.keys.sorted().prefix(6).map { key -> String in
            let displayKey = clippedMiddle(key, maxUTF8Bytes: 48)
            let value = args[key].map { boundedValueSummary($0, maxUTF8Bytes: 64) } ?? ""
            return "\(displayKey): \(value)"
        }
        let text = parts.joined(separator: ", ")
        return clippedMiddle(text, maxUTF8Bytes: 160)
    }

    /// Renders untrusted JSON for a summary without first materializing its
    /// potentially multi-megabyte `displayString` representation.
    private static func boundedValueSummary(_ value: JSONValue, maxUTF8Bytes: Int,
                                            depth: Int = 0) -> String {
        let raw: String
        switch value {
        case .null:
            raw = "null"
        case .bool(let value):
            raw = value ? "true" : "false"
        case .int(let value):
            raw = String(value)
        case .double(let value):
            raw = String(value)
        case .string(let value):
            return clippedMiddle(value, maxUTF8Bytes: maxUTF8Bytes)
        case .array(let values):
            guard depth < 3 else { return "[…]" }
            var parts = values.prefix(4).map {
                boundedValueSummary($0, maxUTF8Bytes: 24, depth: depth + 1)
            }
            if values.count > 4 { parts.append("…") }
            raw = "[" + parts.joined(separator: ", ") + "]"
        case .object(let values):
            guard depth < 3 else { return "{…}" }
            var parts = values.keys.sorted().prefix(4).map { key in
                let displayKey = clippedMiddle(key, maxUTF8Bytes: 16)
                let displayValue = values[key].map {
                    boundedValueSummary($0, maxUTF8Bytes: 24, depth: depth + 1)
                } ?? ""
                return "\(displayKey): \(displayValue)"
            }
            if values.count > 4 { parts.append("…") }
            raw = "{" + parts.joined(separator: ", ") + "}"
        }
        return clippedMiddle(raw, maxUTF8Bytes: maxUTF8Bytes)
    }
}
