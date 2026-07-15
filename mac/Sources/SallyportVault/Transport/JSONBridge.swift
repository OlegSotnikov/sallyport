import Foundation
import SallyportKit

/// Bridges JSONValue ⇄ Foundation JSON objects (the wire uses JSONSerialization).

enum JSONBridgeError: Error, Equatable {
    case tooDeep
    case tooManyNodes
    case unsupportedValue
    case nonFiniteNumber
}

/// Resource-bounded conversion at every untrusted JSON boundary. Foundation's
/// parser has its own nesting limit, but it is much deeper than Sallyport needs,
/// and the recursive JSONValue/display bridges otherwise inherit that depth.
enum BoundedJSONBridge {
    static let maxDepth = 64
    static let maxNodes = 4_096

    private struct Budget {
        var nodes = 0

        mutating func enter(depth: Int) throws {
            guard depth <= BoundedJSONBridge.maxDepth else { throw JSONBridgeError.tooDeep }
            guard nodes < BoundedJSONBridge.maxNodes else { throw JSONBridgeError.tooManyNodes }
            nodes += 1
        }
    }

    static func decode(_ value: Any) throws -> JSONValue {
        var budget = Budget()
        return try decode(value, depth: 0, budget: &budget)
    }

    static func encode(_ value: JSONValue) throws -> Any {
        var budget = Budget()
        return try encode(value, depth: 0, budget: &budget)
    }

    private static func decode(_ value: Any, depth: Int, budget: inout Budget) throws -> JSONValue {
        try budget.enter(depth: depth)
        switch value {
        case let s as String:
            return .string(s)
        case let n as NSNumber:
            if CFGetTypeID(n) == CFBooleanGetTypeID() { return .bool(n.boolValue) }
            if CFNumberIsFloatType(n as CFNumber) {
                let value = n.doubleValue
                guard value.isFinite else { throw JSONBridgeError.nonFiniteNumber }
                return .double(value)
            }
            return .int(n.intValue)
        case let a as [Any]:
            var decoded: [JSONValue] = []
            decoded.reserveCapacity(a.count)
            for item in a { decoded.append(try decode(item, depth: depth + 1, budget: &budget)) }
            return .array(decoded)
        case let o as [String: Any]:
            var decoded: [String: JSONValue] = [:]
            decoded.reserveCapacity(o.count)
            for (key, item) in o {
                decoded[key] = try decode(item, depth: depth + 1, budget: &budget)
            }
            return .object(decoded)
        case is NSNull:
            return .null
        default:
            throw JSONBridgeError.unsupportedValue
        }
    }

    private static func encode(_ value: JSONValue, depth: Int, budget: inout Budget) throws -> Any {
        try budget.enter(depth: depth)
        switch value {
        case .string(let s): return s
        case .int(let i): return i
        case .double(let d):
            guard d.isFinite else { throw JSONBridgeError.nonFiniteNumber }
            return d
        case .bool(let b): return b
        case .null: return NSNull()
        case .array(let values):
            var encoded: [Any] = []
            encoded.reserveCapacity(values.count)
            for item in values { encoded.append(try encode(item, depth: depth + 1, budget: &budget)) }
            return encoded
        case .object(let values):
            var encoded: [String: Any] = [:]
            encoded.reserveCapacity(values.count)
            for (key, item) in values {
                encoded[key] = try encode(item, depth: depth + 1, budget: &budget)
            }
            return encoded
        }
    }
}

extension JSONValue {
    static func boundedObject(fromFoundation object: [String: Any]) throws -> [String: JSONValue] {
        guard case .object(let result) = try BoundedJSONBridge.decode(object) else {
            throw JSONBridgeError.unsupportedValue
        }
        return result
    }

    func boundedFoundation() throws -> Any {
        try BoundedJSONBridge.encode(self)
    }

    /// A Foundation value suitable for `JSONSerialization.data(withJSONObject:)`.
    var asFoundation: Any {
        // Preserve the legacy non-throwing API without preserving its former
        // unbounded recursion. Callers that care about the error use
        // `boundedFoundation()`; compatibility callers get a closed null.
        (try? boundedFoundation()) ?? NSNull()
    }

    /// Build a JSONValue from a Foundation JSON scalar/container.
    init(fromFoundation value: Any) {
        self = (try? BoundedJSONBridge.decode(value)) ?? .null
    }

    /// Foundation object dictionary.
    static func object(fromFoundation o: [String: Any]) -> [String: JSONValue] {
        guard case .object(let decoded) = try? BoundedJSONBridge.decode(o) else { return [:] }
        return decoded
    }
}

extension InvokeResult {
    func boundedFoundation() throws -> [String: Any] {
        var m: [String: Any] = ["ok": ok]
        if !output.isEmpty { m["output"] = try JSONValue.object(output).boundedFoundation() }
        if !errorCode.isEmpty { m["error_code"] = errorCode }
        if !reason.isEmpty { m["reason"] = reason }
        if !rule.isEmpty { m["rule"] = rule }
        if !decision.isEmpty { m["decision"] = decision }
        return m
    }

    /// The wire shape of an invoke result.
    var asFoundation: [String: Any] {
        (try? boundedFoundation()) ?? [
            "ok": false,
            "error_code": "SALLYPORT_UNAVAILABLE",
            "reason": "result exceeds JSON resource limits",
        ]
    }
}
