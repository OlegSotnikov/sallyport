import Darwin
import Foundation
import Testing
@testable import SallyportCLI

private enum CLITestError: Error {
    case socketPair(Int32)
    case missingOutput
}

private final class StubSocketClient: SocketRequesting {
    private(set) var requests: [[String: Any]] = []
    let response: [String: Any]?

    init(response: [String: Any]?) {
        self.response = response
    }

    func request(_ object: [String: Any]) -> [String: Any]? {
        requests.append(object)
        return response
    }
}

@Suite("sp control-socket security boundaries")
struct SocketClientTests {
    @Test("the client deadline preserves the longest human workflow")
    func productionDeadlineCoversCredentialFlow() {
        #expect(SocketClient.defaultTimeout > 16 * 60)
        #expect(SocketClient.defaultTimeout <= 3_600)
    }

    @Test("kernel peer PID is captured and a rejected peer closes the descriptor")
    func peerAuthenticationBoundary() throws {
        let descriptors = try socketPair()
        defer { close(descriptors.1) }

        #expect(ServerPeerAuthenticator.peerPID(fd: descriptors.0) == getpid())
        #expect(!ServerPeerAuthenticator.isTrusted(fd: descriptors.0))

        var inspectedFD: Int32 = -1
        let client = SocketClient(
            connectedFileDescriptor: descriptors.0,
            timeout: 1,
            maxFrameBytes: 64,
            peerAuthenticator: { fd in
                inspectedFD = fd
                return false
            }
        )
        #expect(client == nil)
        #expect(inspectedFD == descriptors.0)
        errno = 0
        #expect(fcntl(descriptors.0, F_GETFD) == -1)
        #expect(errno == EBADF)
        #expect(ServerPeerAuthenticator.peerPID(fd: -1) == nil)
    }

    @Test("Unix socket paths cannot truncate, alias, or contain embedded NULs")
    func socketPathValidation() {
        #expect(SocketClient.isValidSocketPath("/tmp/sallyport.sock"))
        #expect(SocketClient.isValidSocketPath("/" + String(repeating: "a", count: 102)))
        #expect(!SocketClient.isValidSocketPath(""))
        #expect(!SocketClient.isValidSocketPath("relative.sock"))
        #expect(!SocketClient.isValidSocketPath("/tmp/real.sock\0/tmp/decoy.sock"))
        #expect(!SocketClient.isValidSocketPath("/" + String(repeating: "a", count: 103)))
        #expect(!SocketClient.isValidSocketPath("/" + String(repeating: "é", count: 52)))
    }

    @Test("a fragmented bounded response is reassembled and decoded")
    func fragmentedResponse() throws {
        let descriptors = try socketPair()
        let peer = descriptors.1
        Thread.detachNewThread {
            defer { close(peer) }
            var request = [UInt8](repeating: 0, count: 256)
            _ = Darwin.read(peer, &request, request.count)
            writeAll(peer, Data(#"{"result":{"ok":true}}"#.utf8))
            writeAll(peer, Data("\n".utf8))
        }

        let client = try #require(SocketClient(
            connectedFileDescriptor: descriptors.0,
            timeout: 1,
            maxFrameBytes: 64
        ))
        let response = try #require(client.request(["type": "ping"]))
        let result = try #require(response["result"] as? [String: Any])
        #expect(result["ok"] as? Bool == true)
    }

    @Test("an over-cap newline-terminated reply is rejected without parsing")
    func oversizedResponse() throws {
        let descriptors = try socketPair()
        let peer = descriptors.1
        Thread.detachNewThread {
            defer { close(peer) }
            var request = [UInt8](repeating: 0, count: 256)
            _ = Darwin.read(peer, &request, request.count)
            writeAll(peer, Data(repeating: 0x61, count: 33) + Data([0x0A]))
        }

        let client = try #require(SocketClient(
            connectedFileDescriptor: descriptors.0,
            timeout: 1,
            maxFrameBytes: 32
        ))
        #expect(client.request(["x": 1]) == nil)
    }

    @Test("an oversized outbound request is rejected before any socket write")
    func oversizedRequest() throws {
        let descriptors = try socketPair()
        defer { close(descriptors.1) }
        let client = try #require(SocketClient(
            connectedFileDescriptor: descriptors.0,
            timeout: 1,
            maxFrameBytes: 16
        ))
        #expect(client.request(["value": String(repeating: "x", count: 64)]) == nil)
    }

    @Test("a peer that accepts but never replies cannot hang the CLI")
    func stalledPeerTimesOut() throws {
        let descriptors = try socketPair()
        defer { close(descriptors.1) }
        let client = try #require(SocketClient(
            connectedFileDescriptor: descriptors.0,
            timeout: 0.1,
            maxFrameBytes: 64
        ))
        let started = ContinuousClock.now
        #expect(client.request(["x": 1]) == nil)
        #expect(ContinuousClock.now - started < .seconds(2))
    }

    @Test("hostile timeout magnitudes cannot trap timeval conversion")
    func timeoutConversionBoundaries() throws {
        let descriptors = try socketPair()
        defer { close(descriptors.1) }
        #expect(SocketClient(
            connectedFileDescriptor: descriptors.0,
            timeout: .greatestFiniteMagnitude,
            maxFrameBytes: 64
        ) != nil)

        let invalidDescriptors = try socketPair()
        defer {
            close(invalidDescriptors.0)
            close(invalidDescriptors.1)
        }
        #expect(SocketClient(
            connectedFileDescriptor: invalidDescriptors.0,
            timeout: .infinity,
            maxFrameBytes: 64
        ) == nil)
    }

    private func socketPair() throws -> (Int32, Int32) {
        var descriptors: [Int32] = [-1, -1]
        guard Darwin.socketpair(AF_UNIX, SOCK_STREAM, 0, &descriptors) == 0 else {
            throw CLITestError.socketPair(errno)
        }
        return (descriptors[0], descriptors[1])
    }
}

@Suite("sp MCP stdio boundary")
struct MCPShimTests {
    @Test("initialize and unknown-method responses remain valid JSON-RPC")
    func protocolResponses() throws {
        let messages = try runShim(
            #"{"jsonrpc":"2.0","id":1,"method":"initialize"}"# + "\n" +
            #"{"jsonrpc":"2.0","id":2,"method":"dangerous/new-method"}"# + "\n"
        )
        #expect(messages.count == 2)
        #expect((messages[0]["result"] as? [String: Any])?["protocolVersion"] as? String == "2024-11-05")
        #expect((messages[1]["error"] as? [String: Any])?["code"] as? Int == -32601)
    }

    @Test("tools/call forwards the fixed identity and preserves a failed result")
    func toolCallForwarding() throws {
        let stub = StubSocketClient(response: [
            "result": ["ok": false, "error": "denied"],
        ])
        let messages = try runShim(
            #"{"jsonrpc":"2.0","id":"c1","method":"tools/call","params":{"name":"ssh.exec","arguments":{"host":"example"}}}"# + "\n",
            clientFactory: { stub }
        )
        let result = try #require(messages.first?["result"] as? [String: Any])
        #expect(result["isError"] as? Bool == true)
        let request = try #require(stub.requests.first)
        #expect(request["identity"] as? String == "agent://mac.mcp")
        let action = try #require(request["action"] as? [String: Any])
        #expect(action["tool"] as? String == "ssh.exec")
        #expect((action["args"] as? [String: Any])?["host"] as? String == "example")
    }

    @Test("malformed and over-cap input receives a bounded parse error")
    func invalidInput() throws {
        let malformed = try runShim("not-json\n")
        #expect((malformed.first?["error"] as? [String: Any])?["code"] as? Int == -32700)

        let oversized = try runShim(String(repeating: "x", count: 33) + "\n", maxFrameBytes: 32)
        #expect(oversized.count == 1)
        #expect((oversized.first?["error"] as? [String: Any])?["code"] as? Int == -32700)
    }

    private func runShim(
        _ inputText: String,
        maxFrameBytes: Int = 8 * 1024 * 1024,
        clientFactory: @escaping () -> (any SocketRequesting)? = { nil }
    ) throws -> [[String: Any]] {
        let input = Pipe()
        let output = Pipe()
        try input.fileHandleForWriting.write(contentsOf: Data(inputText.utf8))
        try input.fileHandleForWriting.close()

        MCPShim(maxFrameBytes: maxFrameBytes, clientFactory: clientFactory)
            .run(input: input.fileHandleForReading, output: output.fileHandleForWriting)
        try output.fileHandleForWriting.close()

        guard let data = try output.fileHandleForReading.readToEnd() else {
            throw CLITestError.missingOutput
        }
        return try data.split(separator: 0x0A).map { line in
            let value = try JSONSerialization.jsonObject(with: Data(line))
            return try #require(value as? [String: Any])
        }
    }
}

private func writeAll(_ fd: Int32, _ data: Data) {
    data.withUnsafeBytes { raw in
        guard let base = raw.baseAddress else { return }
        var sent = 0
        while sent < raw.count {
            let count = Darwin.write(fd, base.advanced(by: sent), raw.count - sent)
            if count < 0, errno == EINTR { continue }
            guard count > 0 else { return }
            sent += count
        }
    }
}
