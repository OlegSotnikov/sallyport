import Foundation
import Testing
@testable import SallyportKit

@Suite("Canonical JSON — signature byte contract")
struct CanonicalJSONTests {
    @Test("objects are scalar-sorted and containers have no incidental whitespace")
    func deterministicStructure() {
        let value = CanonicalJSON.Value.object([
            "z": .array([.int(-7), .bool(false)]),
            "a": .object(["b": .bool(true), "a": .int(0)]),
            "é": .string("unicode"),
        ])

        let expected = #"{"a":{"a":0,"b":true},"z":[-7,false],"é":"unicode"}"#
        #expect(CanonicalJSON.string(value) == expected)
        #expect(CanonicalJSON.data(value) == Data(expected.utf8))
        #expect(CanonicalJSON.string(value) == CanonicalJSON.string(value))
    }

    @Test("escaping matches the signed JSON contract exactly")
    func exhaustiveEscaping() {
        let input = "\"\\/\u{08}\u{0C}\n\r\t\u{00}\u{1F}<>&\u{2028}\u{2029}é😀"
        let expected = [
            "\"", "\\\"", "\\\\", "/", "\\b", "\\f", "\\n", "\\r", "\\t",
            "\\u0000", "\\u001f", "<>&", "\\u2028", "\\u2029", "é😀", "\"",
        ].joined()

        #expect(CanonicalJSON.string(.string(input)) == expected)
    }

    @Test("dictionary insertion order and escaped keys cannot change signed bytes")
    func keyOrderAndEscaping() {
        let first = CanonicalJSON.Value.object([
            "line\nbreak": .int(Int.max),
            "quote\"": .int(Int.min),
        ])
        let second = CanonicalJSON.Value.object([
            "quote\"": .int(Int.min),
            "line\nbreak": .int(Int.max),
        ])

        #expect(CanonicalJSON.data(first) == CanonicalJSON.data(second))
        #expect(CanonicalJSON.string(first).contains(#""line\nbreak""#))
        #expect(CanonicalJSON.string(first).contains(#""quote\"""#))
    }
}
