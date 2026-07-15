import Foundation

/// Text and highlighting helpers for approval cards and Touch ID prompts.
public enum ApprovalPresentation {

    /// Display labels for built-in tools.
    public static func toolLabel(_ tool: String) -> String {
        switch tool {
        case "http.request": return "HTTP request"
        case "ssh.exec": return "SSH command"
        case "sallyport.request_credential": return "Credential request"
        default: return tool
        }
    }

    /// Primary action text used on cards and in Touch ID prompts.
    public static func primaryActionText(_ action: ActionDescriptor) -> String {
        switch action.channel.lowercased() {
        case "ssh":
            if let body = action.bodyPreview?.trimmingCharacters(in: .whitespacesAndNewlines),
               !body.isEmpty {
                return body
            }
            if let cmd = action.argsPreview?.objectValue?["command"]?.stringValue {
                return cmd
            }
            return action.summary
        default:
            return action.summary
        }
    }

    /// "Approve: systemctl restart nginx on web-prod-1 (Claude Code)"
    public static func touchIDReason(action: ActionDescriptor, origin: ProcessHop) -> String {
        let who = origin.appName ?? origin.name
        let what = primaryActionText(action)
        if let host = action.host, !host.isEmpty {
            return "Approve: \(what) on \(host) (\(who))"
        }
        return "Approve: \(what) (\(who))"
    }

    /// Case-insensitive danger-token ranges, merged left to right.
    public static func dangerRanges(in text: String, tokens: [String]) -> [Range<String.Index>] {
        var ranges: [Range<String.Index>] = []
        let lowerText = text.lowercased()
        for token in tokens where !token.isEmpty {
            let lowerToken = token.lowercased()
            var searchStart = lowerText.startIndex
            while let found = lowerText.range(of: lowerToken, range: searchStart..<lowerText.endIndex) {
                // Map ASCII-token indices back to the original string.
                let lower = text.index(text.startIndex,
                                       offsetBy: lowerText.distance(from: lowerText.startIndex, to: found.lowerBound))
                let upper = text.index(text.startIndex,
                                       offsetBy: lowerText.distance(from: lowerText.startIndex, to: found.upperBound))
                ranges.append(lower..<upper)
                searchStart = found.upperBound
            }
        }
        return ranges.sorted { $0.lowerBound < $1.lowerBound }
    }
}

public extension JSONValue {
    var objectValue: [String: JSONValue]? {
        if case .object(let o) = self { return o }
        return nil
    }
}
