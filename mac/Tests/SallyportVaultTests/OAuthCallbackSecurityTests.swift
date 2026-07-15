import Darwin
import Foundation
import Testing
@testable import SallyportVault

private enum CallbackTestError: Error { case posix(Int32), unexpectedSuccess }

private enum CallbackHTTPClient {
    static func connect(port: Int) throws -> Int32 {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw CallbackTestError.posix(errno) }
        var noSigPipe: Int32 = 1
        _ = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe,
                       socklen_t(MemoryLayout<Int32>.size))
        var timeout = timeval(tv_sec: 2, tv_usec: 0)
        _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                       socklen_t(MemoryLayout<timeval>.size))
        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = in_port_t(UInt16(port)).bigEndian
        address.sin_addr.s_addr = INADDR_LOOPBACK.bigEndian
        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard result == 0 else {
            let code = errno
            Darwin.close(fd)
            throw CallbackTestError.posix(code)
        }
        return fd
    }

    static func request(port: Int, target: String) throws -> String {
        let fd = try connect(port: port)
        defer { Darwin.close(fd) }
        let request = Data("GET \(target) HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n".utf8)
        try writeAll(fd, request)
        return try readAll(fd)
    }

    static func writeAll(_ fd: Int32, _ data: Data) throws {
        try data.withUnsafeBytes { raw in
            var offset = 0
            while offset < raw.count {
                let n = Darwin.write(fd, raw.baseAddress!.advanced(by: offset), raw.count - offset)
                if n < 0 {
                    if errno == EINTR { continue }
                    throw CallbackTestError.posix(errno)
                }
                guard n > 0 else { throw CallbackTestError.posix(EIO) }
                offset += n
            }
        }
    }

    static func readAll(_ fd: Int32) throws -> String {
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let n = Darwin.read(fd, &buffer, buffer.count)
            if n < 0 {
                if errno == EINTR { continue }
                throw CallbackTestError.posix(errno)
            }
            if n == 0 { break }
            data.append(contentsOf: buffer[0..<n])
        }
        return String(decoding: data, as: UTF8.self)
    }
}

@Suite("OAuth loopback callback — live hostile-client behavior", .serialized)
struct OAuthCallbackSecurityTests {
    @Test("out-of-range and occupied preferred ports safely fall back to an ephemeral port")
    func preferredPortFallback() throws {
        let outOfRange = try LoopbackCallbackServer(preferredPort: Int.max)
        #expect((1...65_535).contains(outOfRange.port))
        outOfRange.close()

        let blocker = socket(AF_INET, SOCK_STREAM, 0)
        guard blocker >= 0 else { throw CallbackTestError.posix(errno) }
        defer { Darwin.close(blocker) }
        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = 0
        address.sin_addr.s_addr = INADDR_LOOPBACK.bigEndian
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(blocker, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bound == 0, listen(blocker, 1) == 0 else { throw CallbackTestError.posix(errno) }
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(blocker, $0, &length)
            }
        }
        let occupiedPort = Int(UInt16(bigEndian: address.sin_port))
        let fallback = try LoopbackCallbackServer(preferredPort: occupiedPort)
        #expect(fallback.port != occupiedPort)
        fallback.close()
    }

    @Test("favicon and code-less requests are rejected, then a real callback still succeeds")
    func junkBeforeSuccess() async throws {
        let server = try LoopbackCallbackServer()
        let waiter = Task { try await server.wait(timeout: 2) }

        let favicon = try CallbackHTTPClient.request(port: server.port, target: "/favicon.ico")
        #expect(favicon.contains("404 Not Found"))
        let noCode = try CallbackHTTPClient.request(port: server.port,
                                                    target: "/callback?state=only")
        #expect(noCode.contains("400 Bad Request"))
        let success = try CallbackHTTPClient.request(port: server.port,
                                                     target: "/callback?code=abc&state=xyz")
        #expect(success.contains("200 OK"))
        let callback = try await waiter.value
        #expect(callback.code == "abc")
        #expect(callback.state == "xyz")
    }

    @Test("a callback request line fragmented across TCP reads is reassembled")
    func fragmentedRequestLine() async throws {
        let server = try LoopbackCallbackServer()
        let waiter = Task { try await server.wait(timeout: 2) }
        let fd = try CallbackHTTPClient.connect(port: server.port)
        defer { Darwin.close(fd) }
        for fragment in [
            "GET /call", "back?code=fragmented", "&state=split HTTP/1.1\r", "\nHost: 127.0.0.1\r\n\r\n",
        ] {
            try CallbackHTTPClient.writeAll(fd, Data(fragment.utf8))
            try await Task.sleep(for: .milliseconds(5))
        }
        let response = try CallbackHTTPClient.readAll(fd)
        #expect(response.contains("200 OK"))
        let callback = try await waiter.value
        #expect(callback.code == "fragmented")
        #expect(callback.state == "split")
    }

    @Test("authorization-server error text is HTML-escaped but preserved in the thrown denial")
    func errorPageEscapesHostileText() async throws {
        let server = try LoopbackCallbackServer()
        let waiter = Task { try await server.wait(timeout: 2) }
        let response = try CallbackHTTPClient.request(
            port: server.port,
            target: "/callback?error=access_denied&error_description=%3Cscript%3Eboom%3C/script%3E%26")
        #expect(response.contains("&lt;script&gt;boom&lt;/script&gt;&amp;"))
        #expect(!response.contains("<script>boom</script>"))
        do {
            _ = try await waiter.value
            throw CallbackTestError.unexpectedSuccess
        } catch let error as LoopbackCallbackServer.CallbackError {
            if case .denied(let detail) = error {
                #expect(detail == "<script>boom</script>&")
            } else {
                Issue.record("expected denied, got \(error)")
            }
        }
    }

    @Test("timeout and cancellation close accept/read promptly, including a silent connected client")
    func timeoutAndCancellationCleanup() async throws {
        let timed = try LoopbackCallbackServer()
        let timeoutStart = Date.now
        await #expect(throws: LoopbackCallbackServer.CallbackError.self) {
            _ = try await timed.wait(timeout: 0.03)
        }
        #expect(Date.now.timeIntervalSince(timeoutStart) < 1)

        let cancelled = try LoopbackCallbackServer()
        let waiter = Task { try await cancelled.wait(timeout: 30) }
        let silent = try CallbackHTTPClient.connect(port: cancelled.port)
        try await Task.sleep(for: .milliseconds(20)) // let accept enter its blocking read
        let cancelStart = Date.now
        waiter.cancel()
        await #expect(throws: (any Error).self) { _ = try await waiter.value }
        #expect(Date.now.timeIntervalSince(cancelStart) < 1,
                "cancellation must shut down the accepted client, not wait for its 5s read timeout")
        Darwin.close(silent)

        // Invalid non-finite/negative deadlines are total and expire immediately.
        let invalidDeadline = try LoopbackCallbackServer()
        await #expect(throws: LoopbackCallbackServer.CallbackError.self) {
            _ = try await invalidDeadline.wait(timeout: .nan)
        }
    }
}
