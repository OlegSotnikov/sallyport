import Foundation

/// Redacts known secret patterns and values injected for the current request.
/// This is a response filter, not a complete DLP system.
public enum DLP {
    static let maskGeneric = "«redacted»"
    static let maskCredential = "«redacted:sallyport-credential»"

    private static let patternSources: [(String, NSRegularExpression.Options)] = [
        (#"bearer\s+[A-Za-z0-9._\-]{8,}"#, .caseInsensitive),
        (#"gh[pousr]_[A-Za-z0-9]{20,}"#, []),                       // GitHub
        (#"glpat-[A-Za-z0-9_\-]{16,}"#, []),                        // GitLab PAT
        (#"AKIA[0-9A-Z]{16}"#, []),                                 // AWS access key id
        (#"(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}"#, []),      // Stripe
        (#"sk-(?:ant-)?[A-Za-z0-9_\-]{20,}"#, []),                  // OpenAI / Anthropic
        (#"xox[baprse]-[A-Za-z0-9\-]{10,}"#, []),                   // Slack
        (#"AIza[0-9A-Za-z_\-]{35}"#, []),                           // Google API key
        (#"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----"#,
         .dotMatchesLineSeparators),
        (#"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"#, []), // JWT
    ]

    /// Retains regex compilation errors for redaction instead of failing at static initialization.
    private static let compiledPatterns: Result<[NSRegularExpression], Error> = Result {
        try patternSources.map { source, options in
            try NSRegularExpression(pattern: source, options: options)
        }
    }

    /// Mask known secret shapes; returns the redaction count.
    public static func redact(_ data: Data) -> (Data, Int) {
        redactWith(data, secrets: [])
    }

    /// Masks exact injected values before known generic patterns. The caller owns
    /// and should zeroize `secrets` after this call.
    public static func redactWith(_ data: Data, secrets: [Data]) -> (Data, Int) {
        guard case .success(let patterns) = compiledPatterns else {
            guard !data.isEmpty else { return (data, 0) }
            return (Data(maskGeneric.utf8), 1)
        }
        // Work on the UTF-8 string form (API bodies are text/JSON); a lossy decode
        // of a binary body still redacts the matching bytes.
        var s = String(decoding: data, as: UTF8.self)
        var count = 0

        // Match exact injected credentials first.
        for secret in secrets where !secret.isEmpty {
            let needle = String(decoding: secret, as: UTF8.self)
            guard !needle.isEmpty else { continue }
            var n = 0
            var range = s.startIndex..<s.endIndex
            while let hit = s.range(of: needle, range: range) {
                n += 1
                range = hit.upperBound..<s.endIndex
            }
            if n > 0 {
                count += n
                s = s.replacingOccurrences(of: needle, with: maskCredential)
            }
        }

        // Generic shapes.
        for re in patterns {
            let ns = s as NSString
            let matches = re.matches(in: s, range: NSRange(location: 0, length: ns.length))
            if matches.isEmpty { continue }
            count += matches.count
            // Replace right-to-left so earlier ranges stay valid.
            let mutable = NSMutableString(string: s)
            for m in matches.reversed() {
                mutable.replaceCharacters(in: m.range, with: maskGeneric)
            }
            s = mutable as String
        }

        return (Data(s.utf8), count)
    }
}
