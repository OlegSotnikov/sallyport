import Foundation

/// Deterministic compact JSON used by signed audit data.
///
/// Encoding rules:
///   * Object keys sorted ascending by Unicode scalar value.
///   * No insignificant whitespace: `{"a":1,"b":2}`.
///   * Strings escape JSON-required characters but not `/`, `<`, `>`, or `&`.
///   * U+2028 and U+2029 are escaped.
public enum CanonicalJSON {

    public indirect enum Value: Sendable, Equatable {
        case string(String)
        case int(Int)
        case bool(Bool)
        case object([String: Value])
        case array([Value])
    }

    /// Serialize to canonical UTF-8 bytes.
    public static func data(_ value: Value) -> Data {
        var out = String()
        write(value, into: &out)
        return Data(out.utf8)
    }

    /// Serializes to a canonical string.
    public static func string(_ value: Value) -> String {
        var out = String()
        write(value, into: &out)
        return out
    }

    private static func write(_ value: Value, into out: inout String) {
        switch value {
        case .string(let s):
            writeString(s, into: &out)
        case .int(let i):
            out += String(i)
        case .bool(let b):
            out += b ? "true" : "false"
        case .array(let arr):
            out += "["
            for (idx, element) in arr.enumerated() {
                if idx > 0 { out += "," }
                write(element, into: &out)
            }
            out += "]"
        case .object(let obj):
            out += "{"
            let pairs = obj.sorted { $0.key.unicodeScalars.lexicographicallyPrecedes($1.key.unicodeScalars) }
            for (idx, pair) in pairs.enumerated() {
                if idx > 0 { out += "," }
                writeString(pair.key, into: &out)
                out += ":"
                write(pair.value, into: &out)
            }
            out += "}"
        }
    }

    private static func writeString(_ s: String, into out: inout String) {
        out += "\""
        for scalar in s.unicodeScalars {
            switch scalar {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\u{08}": out += "\\b"
            case "\u{0C}": out += "\\f"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            // Escape Unicode line and paragraph separators.
            case "\u{2028}": out += "\\u2028"
            case "\u{2029}": out += "\\u2029"
            default:
                if scalar.value < 0x20 {
                    out += String(format: "\\u%04x", scalar.value)
                } else {
                    out.unicodeScalars.append(scalar)
                }
            }
        }
        out += "\""
    }
}
