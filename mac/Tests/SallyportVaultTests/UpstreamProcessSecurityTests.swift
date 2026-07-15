import Foundation
import Testing
@testable import SallyportVault

@Suite("Stdio upstream — process-exit signal safety", .serialized)
struct UpstreamProcessSecurityTests {
    @Test("request ids exhaust without integer overflow or collision")
    func requestIDOverflowIsTotal() throws {
        var ids = JSONRPCRequestIDSequence(nextValue: UInt64.max - 1)
        #expect(try ids.take() == String(UInt64.max - 1))
        #expect(try ids.take() == String(UInt64.max))
        #expect(throws: JSONRPCRequestIDError.exhausted) { _ = try ids.take() }
    }

    @Test("timeout conversion is total for hostile floating-point values")
    func timeoutConversionIsTotal() async throws {
        for invalid in [-Double.infinity, Double.nan, -1, 0] {
            #expect(timeoutNanoseconds(invalid) == 0)
            await #expect(throws: UpstreamError.self) {
                _ = try await withTimeout(invalid, upstream: "invalid") { 7 }
            }
        }
        #expect(timeoutNanoseconds(Double.greatestFiniteMagnitude) == UInt64.max)
        let immediate = try await withTimeout(Double.greatestFiniteMagnitude,
                                              upstream: "huge") { 7 }
        #expect(immediate == 7)
    }

    @Test("a child that closes stdin turns the write race into EPIPE, never SIGPIPE")
    func closedChildStdinFailsNormally() async throws {
        let connection = try StdioMCPConnection(
            name: "closed-stdin",
            command: "/bin/sh",
            args: ["-c", "exec 0<&-; sleep 1"],
            extraEnv: [:], injected: [], onExit: { _ in })
        defer { connection.terminate() }
        try await Task.sleep(for: .milliseconds(50))
        #expect(connection.isAlive, "the process must still be alive after closing only stdin")
        await #expect(throws: (any Error).self) {
            try await connection.start(timeout: 0.1)
        }
    }

    @Test("a live child that never reads cannot wedge an oversized JSON-RPC write")
    func nonReadingChildWriteTimesOut() async throws {
        let connection = try StdioMCPConnection(
            name: "never-reads",
            command: "/bin/sleep",
            args: ["5"],
            extraEnv: [:], injected: [], onExit: { _ in })
        defer { connection.terminate() }

        let oversizedForPipe = String(repeating: "x", count: 2 * 1024 * 1024)
        let start = ContinuousClock.now
        await #expect(throws: UpstreamError.self) {
            _ = try await connection.callTool(
                "blocked", arguments: ["payload": .string(oversizedForPipe)], timeout: 0.05)
        }
        #expect(start.duration(to: .now) < .seconds(2),
                "the write deadline must be armed before pipe capacity is exhausted")
    }
}
