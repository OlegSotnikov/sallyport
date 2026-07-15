import Foundation
import Testing
import SallyportKit
@testable import SallyportVault

@Suite("JSON bridge — depth and node resource limits")
struct JSONBridgeSecurityTests {
    @Test("depth 63 round-trips within the explicit stack bound")
    func acceptedDepth() throws {
        var nested: Any = "leaf"
        for _ in 0..<63 { nested = [nested] }
        let decoded = try JSONValue.boundedObject(fromFoundation: ["nested": nested])
        let encoded = try JSONValue.object(decoded).boundedFoundation()
        #expect(JSONSerialization.isValidJSONObject(encoded))
    }

    @Test("depth 65 is rejected in both conversion directions")
    func rejectedDepth() {
        var foundation: Any = "leaf"
        var value = JSONValue.string("leaf")
        for _ in 0..<65 {
            foundation = [foundation]
            value = .array([value])
        }
        #expect(throws: JSONBridgeError.tooDeep) {
            _ = try JSONValue.boundedObject(fromFoundation: ["nested": foundation])
        }
        #expect(throws: JSONBridgeError.tooDeep) {
            _ = try JSONValue.object(["nested": value]).boundedFoundation()
        }
    }

    @Test("a wide node bomb is rejected even when it is shallow")
    func rejectedWidth() {
        let wide = Array(repeating: NSNull() as Any, count: BoundedJSONBridge.maxNodes)
        #expect(throws: JSONBridgeError.tooManyNodes) {
            _ = try JSONValue.boundedObject(fromFoundation: ["wide": wide])
        }
    }

    @Test("non-finite programmatic numbers never reach JSONSerialization")
    func rejectedNonFinite() {
        for number in [Double.nan, Double.infinity, -Double.infinity] {
            #expect(throws: JSONBridgeError.nonFiniteNumber) {
                _ = try JSONValue.double(number).boundedFoundation()
            }
        }
    }

    @Test("legacy non-throwing bridges also fail closed instead of recursing without bounds")
    func legacyBridgesAreBounded() {
        var foundation: Any = "leaf"
        var value = JSONValue.string("leaf")
        for _ in 0..<65 {
            foundation = [foundation]
            value = .array([value])
        }
        #expect(JSONValue(fromFoundation: foundation) == .null)
        #expect(value.asFoundation is NSNull)
        #expect(JSONValue.object(fromFoundation: ["nested": foundation]).isEmpty)

        let result = InvokeResult(ok: true, output: ["nested": value])
        #expect(result.asFoundation["ok"] as? Bool == false)
        #expect(result.asFoundation["error_code"] as? String == "SALLYPORT_UNAVAILABLE")
    }
}
