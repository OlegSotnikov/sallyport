import Foundation
import Testing
import SallyportKit
@testable import SallyportVault

@Suite("Engine display text bounds")
struct EngineDisplayBoundsTests {
    @Test("UTF-8 clipping is valid, bounded, and preserves a useful suffix")
    func unicodeClipping() {
        let text = String(repeating: "👩🏽‍💻", count: 20) + "dangerous-tail"

        let middle = Engine.clippedMiddle(text, maxUTF8Bytes: 64)
        #expect(middle.utf8.count <= 64)
        #expect(middle.contains("…"))
        #expect(middle.hasSuffix("dangerous-tail"))
        #expect(!middle.contains("�"))

        let prefix = Engine.clippedPrefix(text, maxUTF8Bytes: 64)
        #expect(prefix.utf8.count <= 64)
        #expect(prefix.hasSuffix("…"))
        #expect(!prefix.contains("�"))
    }

    @Test("HTTP and SSH approval summaries are byte-bounded and retain command tails")
    func actionSummaries() {
        let url = "https://api.example.com/" + String(repeating: "a", count: 4_000)
            + "?confirm=delete"
        let http = Engine.summarize(Action(tool: "http.request", args: [
            "method": .string("GET"), "url": .string(url),
        ]), host: "api.example.com")
        #expect(http.utf8.count <= Engine.approvalSummaryMaxUTF8Bytes)
        #expect(http.contains("…"))
        #expect(http.hasSuffix("?confirm=delete"))

        let command = "printf start;" + String(repeating: "x", count: 4_000) + "; rm -rf /tmp/demo"
        let sshAction = Action(tool: "ssh.exec", args: ["cmd": .string(command)])
        let ssh = Engine.summarize(sshAction, host: "production.example.com")
        #expect(ssh.utf8.count <= Engine.approvalSummaryMaxUTF8Bytes)
        #expect(ssh.contains("…"))
        #expect(ssh.contains("; rm -rf /tmp/demo on production.example.com"))

        let preview = Engine.preview(sshAction)
        #expect(preview.utf8.count <= Engine.auditPreviewMaxUTF8Bytes)
        #expect(preview.hasSuffix("; rm -rf /tmp/demo"))
    }

    @Test("MCP argument summaries never expand a giant nested displayString")
    func nestedArgumentSummary() {
        let huge = String(repeating: "payload", count: 200_000)
        let action = Action(tool: "vendor.deploy", args: [
            "request": .object([
                "items": .array([.string(huge), .string("tail")]),
            ]),
        ])

        let summary = Engine.summarize(action, host: "vendor")
        let preview = Engine.preview(action)
        #expect(summary.utf8.count <= Engine.approvalSummaryMaxUTF8Bytes)
        #expect(preview.utf8.count <= Engine.auditPreviewMaxUTF8Bytes)
        #expect(summary.contains("…"))
        #expect(preview.contains("…"))
    }

    @Test("approval and audit tool and target fields have independent bounds")
    func metadataFields() {
        let tool = "vendor." + String(repeating: "tool", count: 1_000) + ".delete"
        let target = "target-" + String(repeating: "x", count: 2_000) + ".internal"

        let shownTool = Engine.displayTool(tool)
        let shownTarget = Engine.displayTarget(target)
        #expect(shownTool.utf8.count <= Engine.displayToolMaxUTF8Bytes)
        #expect(shownTarget.utf8.count <= Engine.displayTargetMaxUTF8Bytes)
        #expect(shownTool.hasSuffix(".delete"))
        #expect(shownTarget.hasSuffix(".internal"))
    }

    @Test("HTTP body previews are byte-bounded and cheap JSON is legible")
    func httpBodyPreview() throws {
        let compact = #"{"z":1,"a":{"enabled":true}}"#
        let json = try #require(Engine.httpBodyDisplayPreview(Action(
            tool: "http.request", args: ["body": .string(compact)])))
        #expect(json.byteCount == compact.utf8.count)
        #expect(!json.truncated)
        #expect(json.text.contains("\n"))
        let a = try #require(json.text.firstIndex(of: "a"))
        let z = try #require(json.text.firstIndex(of: "z"))
        #expect(z < a, "formatting must preserve the request body's key order")

        let preciseNumber = #"{"id":123456789012345678901234567890}"#
        let precise = try #require(Engine.httpBodyDisplayPreview(Action(
            tool: "http.request", args: ["body": .string(preciseNumber)])))
        #expect(precise.text.contains("123456789012345678901234567890"),
                "display formatting must not round JSON numbers")

        let huge = String(repeating: "👩🏽‍💻", count: 1_000) + "never-materialize-a-full-copy"
        let bounded = try #require(Engine.httpBodyDisplayPreview(Action(
            tool: "http.request", args: ["body": .string(huge)])))
        #expect(bounded.byteCount == huge.utf8.count)
        #expect(bounded.truncated)
        #expect(bounded.text.utf8.count <= Engine.httpBodyPreviewMaxUTF8Bytes)
        #expect(bounded.text.hasSuffix("…"))
        #expect(!bounded.text.contains("�"))

        let ascii = try #require(Engine.httpBodyDisplayPreview(Action(
            tool: "http.request", args: ["body": .string(String(repeating: "x", count: 5_000))])))
        #expect(ascii.text.utf8.count == Engine.httpBodyPreviewMaxUTF8Bytes,
                "the UTF-8 budget includes the three-byte ellipsis")

        let binaryish = "A\0👩🏽‍💻B"
        let raw = try #require(Engine.httpBodyDisplayPreview(Action(
            tool: "http.request", args: ["body": .string(binaryish)])))
        #expect(raw.text == "A\\u{0000}👩🏽‍💻B")
        #expect(raw.byteCount == Data(binaryish.utf8).count,
                "preview size must match the bytes HTTPExecutor sends")
        #expect(!raw.truncated)

        let spoof = "invoice.pdf\u{202E}gpj.exe\u{2066}\u{0001}"
        let escaped = try #require(Engine.httpBodyDisplayPreview(Action(
            tool: "http.request", args: ["body": .string(spoof)])))
        #expect(!escaped.text.contains("\u{202E}"))
        #expect(!escaped.text.contains("\u{2066}"))
        #expect(!escaped.text.contains("\u{0001}"))
        #expect(escaped.text.contains("\\u{202E}"))
        #expect(escaped.text.contains("\\u{2066}"))
        #expect(escaped.text.contains("\\u{0001}"))
        #expect(escaped.byteCount == Data(spoof.utf8).count)

        #expect(Engine.httpBodyDisplayPreview(Action(
            tool: "http.request", args: [:])) == nil)
        #expect(Engine.httpBodyDisplayPreview(Action(
            tool: "ssh.exec", args: ["body": .string("not HTTP")])) == nil)
    }

    @Test("upstream description fields are capped without changing schema data")
    func mcpDescriptions() {
        let huge = String(repeating: "documentation ", count: 1_000)
        let definition: JSONValue = .object([
            "name": .string("deploy"),
            "description": .string(huge),
            "inputSchema": .object([
                "description": .string(huge),
                "default": .string(huge),
            ]),
        ])

        let bounded = UpstreamManager.boundedToolDescriptions(definition)
        guard let object = bounded.objectValue,
              let topDescription = object["description"]?.stringValue,
              let schema = object["inputSchema"]?.objectValue,
              let nestedDescription = schema["description"]?.stringValue else {
            Issue.record("bounded definition lost its MCP schema structure")
            return
        }

        #expect(object["name"] == .string("deploy"))
        #expect(topDescription.utf8.count <= UpstreamManager.toolDescriptionMaxUTF8Bytes)
        #expect(nestedDescription.utf8.count <= UpstreamManager.toolDescriptionMaxUTF8Bytes)
        #expect(topDescription.hasSuffix("…"))
        #expect(nestedDescription.hasSuffix("…"))
        #expect(schema["default"] == .string(huge),
                "only documentation fields are display-bounded")
    }
}
