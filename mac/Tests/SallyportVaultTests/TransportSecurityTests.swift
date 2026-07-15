import Darwin
import Foundation
import Testing
import SallyportKit
@testable import SallyportVault

private struct SecurityAutoApprove: Approver {
    func requestApproval(_ req: EngineApproval) async -> ApprovalOutcome { .approved }
}

private struct SecurityHostFixture {
    let root: URL
    let recordDir: URL
    let socketPath: String
    let store: VaultStore
    let host: VaultHost

    static func make(socketPath: String? = nil, start: Bool = false) async throws -> Self {
        let root = URL(fileURLWithPath: "/tmp/sp-sec-\(UUID().uuidString.prefix(8))", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let recordDir = root.appendingPathComponent("recordings", isDirectory: true)
        try FileManager.default.createDirectory(at: recordDir, withIntermediateDirectories: true)
        let configuredSocket = socketPath ?? root.appendingPathComponent("run/sallyport.sock").path
        let store = try VaultStore(creatingAt: root.appendingPathComponent("vault.db"),
                                   keystore: FileAgeKeystore())
        let paths = VaultHost.Paths(
            socket: configuredSocket,
            auditDir: root.appendingPathComponent("audit").path,
            knownHosts: root.appendingPathComponent("known_hosts").path,
            recordDir: recordDir.path,
            sshHelper: "/usr/bin/false")
        let host = try await VaultHost(store: store, hosts: HostsStore(), paths: paths,
                                       approver: SecurityAutoApprove())
        if start { try host.start() }
        return Self(root: root, recordDir: recordDir, socketPath: configuredSocket,
                    store: store, host: host)
    }

    func cleanUp() async {
        host.stop()
        await store.close()
        try? FileManager.default.removeItem(at: root)
    }
}

private enum TestSocketError: Error {
    case posix(Int32)
    case eof
    case unencodable
}

private final class TransportFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var stored = false
    func set() { lock.withLock { stored = true } }
    func claim() -> Bool {
        lock.withLock {
            guard !stored else { return false }
            stored = true
            return true
        }
    }
    var value: Bool { lock.withLock { stored } }
}

private enum TestSocketClient {
    static func connect(_ path: String) throws -> Int32 {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw TestSocketError.posix(errno) }
        var noSigPipe: Int32 = 1
        guard setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe,
                         socklen_t(MemoryLayout<Int32>.size)) == 0 else {
            let code = errno
            Darwin.close(fd)
            throw TestSocketError.posix(code)
        }
        // Generous on purpose: the full suite runs many suites in parallel and a
        // busy host can take seconds to accept+reply; a short SO_RCVTIMEO turns
        // machine load into EAGAIN test flakes. 30s only ever matters when the
        // transport is genuinely broken.
        var timeout = timeval(tv_sec: 30, tv_usec: 0)
        _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                       socklen_t(MemoryLayout<timeval>.size))
        _ = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                       socklen_t(MemoryLayout<timeval>.size))

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        path.withCString { src in
            withUnsafeMutablePointer(to: &addr.sun_path) {
                $0.withMemoryRebound(to: CChar.self, capacity: 104) {
                    _ = strlcpy($0, src, 104)
                }
            }
        }
        let connected = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard connected == 0 else {
            let code = errno
            Darwin.close(fd)
            throw TestSocketError.posix(code)
        }
        return fd
    }

    static func connectEventually(_ path: String) throws -> Int32 {
        var lastError: Int32 = ECONNREFUSED
        for _ in 0..<200 {
            do {
                return try connect(path)
            } catch TestSocketError.posix(let code)
                where code == ECONNREFUSED || code == EAGAIN || code == ENOBUFS {
                lastError = code
                usleep(1_000)
            }
        }
        throw TestSocketError.posix(lastError)
    }

    @discardableResult
    static func writeAll(_ fd: Int32, _ data: Data) -> Bool {
        data.withUnsafeBytes { raw in
            var offset = 0
            while offset < raw.count {
                let n = Darwin.write(fd, raw.baseAddress!.advanced(by: offset), raw.count - offset)
                if n < 0 {
                    if errno == EINTR { continue }
                    return false
                }
                guard n > 0 else { return false }
                offset += n
            }
            return true
        }
    }

    static func sendLine(_ fd: Int32, _ data: Data) throws {
        var line = data
        line.append(0x0a)
        guard writeAll(fd, line) else { throw TestSocketError.posix(errno) }
    }

    static func sendJSON(_ fd: Int32, _ object: [String: Any]) throws {
        guard JSONSerialization.isValidJSONObject(object) else { throw TestSocketError.unencodable }
        try sendLine(fd, JSONSerialization.data(withJSONObject: object))
    }

    static func readLine(_ fd: Int32) throws -> Data {
        var accumulated = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let n = Darwin.read(fd, &buffer, buffer.count)
            if n < 0 {
                if errno == EINTR { continue }
                throw TestSocketError.posix(errno)
            }
            guard n > 0 else { throw TestSocketError.eof }
            accumulated.append(contentsOf: buffer[0..<n])
            if let newline = accumulated.firstIndex(of: 0x0a) {
                return Data(accumulated[..<newline])
            }
        }
    }

    static func readJSON(_ fd: Int32) throws -> [String: Any] {
        let data = try readLine(fd)
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw TestSocketError.unencodable
        }
        return object
    }

    static func request(_ path: String, _ object: [String: Any]) throws -> [String: Any] {
        let fd = try connect(path)
        defer { Darwin.close(fd) }
        try sendJSON(fd, object)
        return try readJSON(fd)
    }
}

@Suite("Recording reader — path, type, and memory boundary", .serialized)
struct RecordingReaderSecurityTests {
    @Test("only a bounded regular file directly inside recordDir can be decrypted")
    func containedRegularFileOnly() async throws {
        let fixture = try await SecurityHostFixture.make()
        defer { fixture.host.stop(); try? FileManager.default.removeItem(at: fixture.root) }

        let cast = Data("{\"version\":2}\n[0.1,\"o\",\"hello\"]\n".utf8)
        let filename = "ssh-valid.cast.sealed"
        let sealed = try await fixture.store.sealRecording(cast, filename: filename)
        let valid = fixture.recordDir.appendingPathComponent(filename)
        try sealed.write(to: valid)
        #expect(try await fixture.host.readRecording(path: valid.path) == cast)

        // The old implementation accepted this exact case: a valid sealed cast
        // copied anywhere on disk was read and decrypted because only its basename
        // was authenticated. Location is now part of the access-control boundary.
        let outside = fixture.root.appendingPathComponent("outside/\(filename)")
        try FileManager.default.createDirectory(at: outside.deletingLastPathComponent(),
                                                withIntermediateDirectories: true)
        try sealed.write(to: outside)
        await #expect(throws: VaultHost.RecordingError.invalidPath) {
            _ = try await fixture.host.readRecording(path: outside.path)
        }

        let nestedDir = fixture.recordDir.appendingPathComponent("nested", isDirectory: true)
        try FileManager.default.createDirectory(at: nestedDir, withIntermediateDirectories: true)
        let nested = nestedDir.appendingPathComponent(filename)
        try sealed.write(to: nested)
        await #expect(throws: VaultHost.RecordingError.invalidPath) {
            _ = try await fixture.host.readRecording(path: nested.path)
        }

        let wrongExtension = fixture.recordDir.appendingPathComponent("recording.bin")
        try sealed.write(to: wrongExtension)
        await #expect(throws: VaultHost.RecordingError.invalidPath) {
            _ = try await fixture.host.readRecording(path: wrongExtension.path)
        }

        let link = fixture.recordDir.appendingPathComponent("ssh-link.cast.sealed")
        try FileManager.default.createSymbolicLink(atPath: link.path,
                                                   withDestinationPath: valid.lastPathComponent)
        await #expect(throws: VaultHost.RecordingError.notRegularFile) {
            _ = try await fixture.host.readRecording(path: link.path)
        }

        let fifo = fixture.recordDir.appendingPathComponent("ssh-pipe.cast.sealed")
        guard mkfifo(fifo.path, 0o600) == 0 else { throw TestSocketError.posix(errno) }
        await #expect(throws: VaultHost.RecordingError.notRegularFile) {
            _ = try await fixture.host.readRecording(path: fifo.path)
        }

        let linkedName = "ssh-hardlink.cast.sealed"
        let linkedBlob = try await fixture.store.sealRecording(cast, filename: linkedName)
        let linkedSource = fixture.root.appendingPathComponent("outside/(linkedName)")
        try linkedBlob.write(to: linkedSource)
        let linkedInside = fixture.recordDir.appendingPathComponent(linkedName)
        guard Darwin.link(linkedSource.path, linkedInside.path) == 0 else {
            throw TestSocketError.posix(errno)
        }
        await #expect(throws: VaultHost.RecordingError.notRegularFile) {
            _ = try await fixture.host.readRecording(path: linkedInside.path)
        }

        // Sparse: proves rejection happens from fstat before allocating/reading.
        let huge = fixture.recordDir.appendingPathComponent("ssh-huge.cast.sealed")
        let hugeFD = Darwin.open(huge.path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
        guard hugeFD >= 0 else { throw TestSocketError.posix(errno) }
        let truncateResult = ftruncate(hugeFD, 64 * 1024 * 1024 + 1)
        let truncateError = errno
        Darwin.close(hugeFD)
        guard truncateResult == 0 else { throw TestSocketError.posix(truncateError) }
        await #expect(throws: VaultHost.RecordingError.tooLarge) {
            _ = try await fixture.host.readRecording(path: huge.path)
        }

        await fixture.store.close()
    }
}

@Suite("Control socket — hostile framing and lifecycle", .serialized)
struct ControlSocketSecurityTests {
    @Test("invalid UTF-8/JSON gets a structured error and cannot poison the connection")
    func malformedFramesStayContained() async throws {
        let fixture = try await SecurityHostFixture.make(start: true)
        defer { fixture.host.stop(); try? FileManager.default.removeItem(at: fixture.root) }
        let fd = try TestSocketClient.connect(fixture.socketPath)
        defer { Darwin.close(fd) }

        try TestSocketClient.sendLine(fd, Data([0xff, 0xfe, 0xfd]))
        let invalid = try TestSocketClient.readJSON(fd)
        #expect(invalid["type"] as? String == "error")
        #expect((invalid["error"] as? String)?.contains("bad frame") == true)

        try TestSocketClient.sendJSON(fd, ["type": "unknown", "id": "u1"])
        let unknown = try TestSocketClient.readJSON(fd)
        #expect(unknown["type"] as? String == "error")
        #expect(unknown["id"] as? String == "u1")

        try TestSocketClient.sendJSON(fd, ["type": "invoke", "id": "bad-invoke"])
        let invoke = try TestSocketClient.readJSON(fd)
        let result = invoke["result"] as? [String: Any]
        #expect(result?["error_code"] as? String == "SALLYPORT_BAD_REQUEST")

        // Same connection remains usable after all malformed inputs.
        try TestSocketClient.sendJSON(fd, ["type": "list_tools", "id": "good"])
        let good = try TestSocketClient.readJSON(fd)
        #expect(good["type"] as? String == "list_tools_result")
        #expect((good["tools"] as? [Any])?.count == 3)
        await fixture.store.close()
    }

    @Test("an unterminated frame dies with its peer; rapid disconnects do not kill the listener")
    func partialEOFAndDisconnectStorm() async throws {
        let fixture = try await SecurityHostFixture.make(start: true)
        defer { fixture.host.stop(); try? FileManager.default.removeItem(at: fixture.root) }

        for _ in 0..<256 {
            let fd = try TestSocketClient.connectEventually(fixture.socketPath)
            #expect(TestSocketClient.writeAll(fd, Data("{\"type\":\"list_tools\"".utf8)))
            Darwin.close(fd) // EOF with a pending, unterminated frame
        }

        let finalFD = try TestSocketClient.connectEventually(fixture.socketPath)
        defer { Darwin.close(finalFD) }
        try TestSocketClient.sendJSON(finalFD, ["type": "list_tools", "id": "after-storm"])
        let reply = try TestSocketClient.readJSON(finalFD)
        #expect(reply["type"] as? String == "list_tools_result")
        #expect(reply["id"] as? String == "after-storm")
        await fixture.store.close()
    }

    @Test("a frame above 8 MiB closes only that peer; the listener stays alive")
    func oversizedFrameIsolation() async throws {
        let fixture = try await SecurityHostFixture.make(start: true)
        defer { fixture.host.stop(); try? FileManager.default.removeItem(at: fixture.root) }
        let fd = try TestSocketClient.connect(fixture.socketPath)

        let cap = 8 * 1024 * 1024
        let chunk = Data(repeating: 0x61, count: 64 * 1024)
        var attempted = 0
        while attempted <= cap {
            guard TestSocketClient.writeAll(fd, chunk) else { break }
            attempted += chunk.count
        }
        #expect(attempted >= cap, "the peer must cross the LineFramer cap")
        _ = shutdown(fd, SHUT_WR)
        var byte: UInt8 = 0
        let n = Darwin.read(fd, &byte, 1)
        #expect(n <= 0, "an over-cap peer must be closed without a reply")
        Darwin.close(fd)

        let reply = try TestSocketClient.request(fixture.socketPath,
                                                 ["type": "list_tools", "id": "still-alive"])
        #expect(reply["type"] as? String == "list_tools_result")
        await fixture.store.close()
    }

    @Test("a connection flood is capped and rejected with a structured busy error")
    func connectionFloodIsBounded() async throws {
        let fixture = try await SecurityHostFixture.make(start: true)
        defer { fixture.host.stop(); try? FileManager.default.removeItem(at: fixture.root) }

        // A partial frame parks each admitted worker in read(), modeling both a
        // slowloris client and a connection waiting on human approval.
        var parked: [Int32] = []
        defer { for fd in parked { Darwin.close(fd) } }

        // The server reaps a silent connection after `idleReadTimeoutSeconds` (1s),
        // so a parked slot the peer already closed frees up. On a loaded CI host,
        // filling all 32 slots can outrun that 1s window and let an early slot
        // reap before the over-cap probe — so top the pool back up to the cap
        // (dropping peer-closed fds) right before each probe, and retry the probe
        // until it observes the busy rejection (the guarantee under test).
        func topUpToCap() {
            parked.removeAll { fd in
                var b: UInt8 = 0
                let n = recv(fd, &b, 1, MSG_PEEK | MSG_DONTWAIT)
                if n == 0 { Darwin.close(fd); return true }   // peer (server) closed → reaped
                return false
            }
            while parked.count < SocketServer.maxConnections {
                guard let fd = try? TestSocketClient.connectEventually(fixture.socketPath) else { break }
                _ = TestSocketClient.writeAll(fd, Data("{".utf8))
                parked.append(fd)
            }
        }

        var busy: [String: Any] = [:]
        for _ in 0..<20 {
            topUpToCap()
            guard let rejected = try? TestSocketClient.connectEventually(fixture.socketPath) else { continue }
            defer { Darwin.close(rejected) }
            if let reply = try? TestSocketClient.readJSON(rejected),
               reply["code"] as? String == "SALLYPORT_BUSY" {
                busy = reply
                break
            }
        }
        #expect(busy["type"] as? String == "error")
        #expect(busy["code"] as? String == "SALLYPORT_BUSY")

        for fd in parked { Darwin.close(fd) }
        parked.removeAll()

        // Worker teardown is asynchronous. Once slots drain, normal service
        // resumes without restarting the vault host.
        var recovered = false
        for _ in 0..<200 where !recovered {
            let fd = try TestSocketClient.connectEventually(fixture.socketPath)
            try TestSocketClient.sendJSON(fd, ["type": "list_tools", "id": "after-flood"])
            if let response = try? TestSocketClient.readJSON(fd) {
                recovered = response["type"] as? String == "list_tools_result"
            }
            Darwin.close(fd)
            if !recovered { usleep(1_000) }
        }
        #expect(recovered)
        await fixture.store.close()
    }

    @Test("idle and slowloris clients age out, release slots, and service recovers")
    func idleClientsExpire() async throws {
        let fixture = try await SecurityHostFixture.make(start: true)
        defer { fixture.host.stop(); try? FileManager.default.removeItem(at: fixture.root) }

        var parked: [Int32] = []
        for _ in 0..<SocketServer.maxConnections {
            let fd = try TestSocketClient.connectEventually(fixture.socketPath)
            parked.append(fd) // send nothing: worker is parked in read()
        }
        usleep(useconds_t((SocketServer.idleReadTimeoutSeconds + 1) * 1_000_000))

        // All idle workers must have torn down without a host restart.
        let recovered = try TestSocketClient.request(
            fixture.socketPath, ["type": "list_tools", "id": "after-idle"])
        #expect(recovered["type"] as? String == "list_tools_result")
        for fd in parked { Darwin.close(fd) }

        // Sending a byte before each SO_RCVTIMEO expiry must not reset the
        // absolute age of one unterminated frame forever.
        let trickle = try TestSocketClient.connectEventually(fixture.socketPath)
        var serverClosed = false
        for _ in 0..<8 {
            if !TestSocketClient.writeAll(trickle, Data("{".utf8)) {
                serverClosed = true
                break
            }
            usleep(400_000)
        }
        if !serverClosed {
            var byte: UInt8 = 0
            serverClosed = Darwin.read(trickle, &byte, 1) <= 0
        }
        Darwin.close(trickle)
        #expect(serverClosed, "a byte-at-a-time partial frame must have an absolute deadline")
        await fixture.store.close()
    }

    @Test("an async tool catalog is awaited and returned")
    func asyncToolCatalogCompletes() async throws {
        let root = URL(fileURLWithPath: "/tmp/sp-catalog-async-\(UUID().uuidString.prefix(8))",
                       isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        let path = root.appendingPathComponent("sallyport.sock").path
        // Completion path: a catalog that does 20ms of async work must return
        // under the cap. Cap is generous (1s, not 200ms) so a loaded CI host's
        // socket + scheduling overhead can't eat the margin — the catalog-timeout
        // FIRES direction is covered by "a wedged tool catalog is cancelled…".
        let server = SocketServer(
            path: path, invokeTimeout: 1, catalogTimeout: 1,
            tools: {
                try? await Task.sleep(for: .milliseconds(20))
                return [.object(["name": .string("async.tool")])]
            },
            invokeAction: { _, _, _ in .denied("UNUSED", "unused") })
        try server.start()
        defer {
            server.stop()
            try? FileManager.default.removeItem(at: root)
        }

        let reply = try TestSocketClient.request(path, ["type": "list_tools", "id": "async"])
        #expect(reply["type"] as? String == "list_tools_result")
        let tools = try #require(reply["tools"] as? [[String: Any]])
        #expect(tools.first?["name"] as? String == "async.tool")
    }

    @Test("a wedged tool catalog is cancelled at its own server deadline")
    func catalogHardDeadline() async throws {
        let root = URL(fileURLWithPath: "/tmp/sp-catalog-timeout-\(UUID().uuidString.prefix(8))",
                       isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        let path = root.appendingPathComponent("sallyport.sock").path
        let firstCall = TransportFlag()
        let cancelled = TransportFlag()
        let server = SocketServer(
            path: path, invokeTimeout: 1, catalogTimeout: 0.02,
            tools: {
                guard firstCall.claim() else {
                    return [.object(["name": .string("recovered.tool")])]
                }
                return await withTaskCancellationHandler {
                    try? await Task.sleep(for: .seconds(60))
                    return []
                } onCancel: {
                    cancelled.set()
                }
            },
            invokeAction: { _, _, _ in .denied("UNUSED", "unused") })
        try server.start()
        defer {
            server.stop()
            try? FileManager.default.removeItem(at: root)
        }

        let reply = try TestSocketClient.request(path, ["type": "list_tools", "id": "wedged"])
        #expect(reply["type"] as? String == "error")
        #expect(reply["code"] as? String == "SALLYPORT_TIMEOUT")
        for _ in 0..<100 where !cancelled.value {
            try await Task.sleep(for: .milliseconds(2))
        }
        #expect(cancelled.value, "catalog timeout must cancel its provider task")
        let recovered = try TestSocketClient.request(
            path, ["type": "list_tools", "id": "after-timeout"])
        #expect((recovered["tools"] as? [[String: Any]])?.first?["name"] as? String
                == "recovered.tool")
    }

    @Test("disconnecting a catalog peer cancels its provider task")
    func catalogPeerDisconnectCancels() async throws {
        let root = URL(fileURLWithPath: "/tmp/sp-catalog-disconnect-\(UUID().uuidString.prefix(8))",
                       isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        let path = root.appendingPathComponent("sallyport.sock").path
        let firstCall = TransportFlag()
        let started = TransportFlag()
        let cancelled = TransportFlag()
        let server = SocketServer(
            path: path, invokeTimeout: 1, catalogTimeout: 5,
            tools: {
                guard firstCall.claim() else {
                    return [.object(["name": .string("recovered.tool")])]
                }
                started.set()
                return await withTaskCancellationHandler {
                    try? await Task.sleep(for: .seconds(60))
                    return []
                } onCancel: {
                    cancelled.set()
                }
            },
            invokeAction: { _, _, _ in .denied("UNUSED", "unused") })
        try server.start()
        defer {
            server.stop()
            try? FileManager.default.removeItem(at: root)
        }

        let fd = try TestSocketClient.connectEventually(path)
        try TestSocketClient.sendJSON(fd, ["type": "list_tools", "id": "abandoned"])
        for _ in 0..<100 where !started.value {
            try await Task.sleep(for: .milliseconds(2))
        }
        #expect(started.value)
        _ = shutdown(fd, SHUT_RDWR)
        Darwin.close(fd)

        for _ in 0..<200 where !cancelled.value {
            try await Task.sleep(for: .milliseconds(5))
        }
        #expect(cancelled.value, "peer EOF must cancel catalog generation and release its slot")
        let recovered = try TestSocketClient.request(
            path, ["type": "list_tools", "id": "after-disconnect"])
        #expect((recovered["tools"] as? [[String: Any]])?.first?["name"] as? String
                == "recovered.tool")
    }

    @Test("a wedged invocation is cancelled at the server deadline and releases its slot")
    func invokeHardDeadline() async throws {
        #expect(SocketServer.invokeTimeoutSeconds > 15 * 60,
                "the transport deadline must preserve the credential UI's 15-minute budget")
        let root = URL(fileURLWithPath: "/tmp/sp-invoke-timeout-\(UUID().uuidString.prefix(8))",
                       isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        let path = root.appendingPathComponent("sallyport.sock").path
        let cancelled = TransportFlag()
        let server = SocketServer(path: path, invokeTimeout: 0.02, tools: { [] }) {
            _, _, _ in
            await withTaskCancellationHandler {
                try? await Task.sleep(nanoseconds: 60_000_000_000)
                return .denied("TOO_LATE", "the cancelled invocation returned")
            } onCancel: {
                cancelled.set()
            }
        }
        try server.start()
        defer {
            server.stop()
            try? FileManager.default.removeItem(at: root)
        }

        let started = DispatchTime.now().uptimeNanoseconds
        let reply = try TestSocketClient.request(path, [
            "type": "invoke", "id": "wedged",
            "action": ["tool": "test.wedge", "args": [:]],
        ])
        let elapsed = DispatchTime.now().uptimeNanoseconds - started
        let result = try #require(reply["result"] as? [String: Any])
        #expect(result["error_code"] as? String == "SALLYPORT_TIMEOUT")
        #expect(elapsed < 1_000_000_000, "the test seam must not inherit the production wait")
        for _ in 0..<100 where !cancelled.value {
            try await Task.sleep(nanoseconds: 1_000_000)
        }
        #expect(cancelled.value)

        // The timed-out worker is gone; normal requests do not require a host
        // restart and cannot be starved behind the abandoned engine task.
        let recovered = try TestSocketClient.request(
            path, ["type": "list_tools", "id": "after-timeout"])
        #expect(recovered["type"] as? String == "list_tools_result")
    }

    @Test("an invocation longer than the old client budget still completes below the hard cap")
    func validDelayedInvokeCompletes() async throws {
        let root = URL(fileURLWithPath: "/tmp/sp-invoke-valid-\(UUID().uuidString.prefix(8))",
                       isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        let path = root.appendingPathComponent("sallyport.sock").path
        // A legitimate slow-but-valid approval (40ms handler work) must complete
        // under the transport ceiling. The ceiling is deliberately generous (2s,
        // 50× the work) so this only asserts "a valid invocation below the cap is
        // NOT spuriously killed" — the timeout-fires direction is a separate test
        // ("a wedged invocation is cancelled at the server deadline"). A tight
        // ceiling here flaked on loaded CI hosts, where socket round-trip +
        // scheduling ate the small margin before the 40ms work returned.
        let server = SocketServer(path: path, invokeTimeout: 2.0, tools: { [] }) {
            _, _, _ in
            try? await Task.sleep(nanoseconds: 40_000_000)
            return InvokeResult(ok: true, output: ["status": .string("approved")])
        }
        try server.start()
        defer {
            server.stop()
            try? FileManager.default.removeItem(at: root)
        }

        let reply = try TestSocketClient.request(path, [
            "type": "invoke", "id": "delayed",
            "action": ["tool": "test.delayed", "args": [:]],
        ])
        let result = try #require(reply["result"] as? [String: Any])
        #expect(result["ok"] as? Bool == true)
        #expect((result["output"] as? [String: Any])?["status"] as? String == "approved")
    }

    @Test("disconnecting an invoking peer cancels its engine task and releases the slot")
    func invokePeerDisconnectCancels() async throws {
        let root = URL(fileURLWithPath: "/tmp/sp-invoke-disconnect-\(UUID().uuidString.prefix(8))",
                       isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        let path = root.appendingPathComponent("sallyport.sock").path
        let cancelled = TransportFlag()
        let server = SocketServer(path: path, invokeTimeout: 5, tools: { [] }) {
            _, _, _ in
            await withTaskCancellationHandler {
                try? await Task.sleep(nanoseconds: 60_000_000_000)
                return InvokeResult(ok: false)
            } onCancel: {
                cancelled.set()
            }
        }
        try server.start()
        defer {
            server.stop()
            try? FileManager.default.removeItem(at: root)
        }

        let fd = try TestSocketClient.connect(path)
        try TestSocketClient.sendJSON(fd, [
            "type": "invoke", "id": "abandoned",
            "action": ["tool": "test.wait", "args": [:]],
        ])
        _ = shutdown(fd, SHUT_RDWR)
        Darwin.close(fd)

        for _ in 0..<200 where !cancelled.value {
            try await Task.sleep(nanoseconds: 5_000_000)
        }
        #expect(cancelled.value, "peer EOF must not leave an approval task occupying a slot")
        let recovered = try TestSocketClient.request(
            path, ["type": "list_tools", "id": "after-disconnect"])
        #expect(recovered["type"] as? String == "list_tools_result")
    }

    @Test("deep action arguments fail closed before the engine is invoked")
    func boundedActionArguments() async throws {
        let root = URL(fileURLWithPath: "/tmp/sp-json-depth-\(UUID().uuidString.prefix(8))",
                       isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        let path = root.appendingPathComponent("sallyport.sock").path
        let invoked = TransportFlag()
        let server = SocketServer(path: path, invokeTimeout: 1, tools: { [] }) {
            _, _, _ in
            invoked.set()
            return InvokeResult(ok: true)
        }
        try server.start()
        defer {
            server.stop()
            try? FileManager.default.removeItem(at: root)
        }

        var nested: Any = "leaf"
        for _ in 0..<65 { nested = [nested] }
        let reply = try TestSocketClient.request(path, [
            "type": "invoke", "id": "too-deep",
            "action": ["tool": "test.depth", "args": ["nested": nested]],
        ])
        let result = try #require(reply["result"] as? [String: Any])
        #expect(result["error_code"] as? String == "SALLYPORT_BAD_REQUEST")
        #expect(!invoked.value)
    }

    @Test("accept errors retry unless the listener descriptor itself is invalid")
    func acceptFailureClassification() {
        #expect(SocketServer.acceptFailureAction(EINTR, running: true) == .retry)
        #expect(SocketServer.acceptFailureAction(ECONNABORTED, running: true) == .retry)
        #expect(SocketServer.acceptFailureAction(EAGAIN, running: true) == .retry)
        #expect(SocketServer.acceptFailureAction(EMFILE, running: true) == .backoff)
        #expect(SocketServer.acceptFailureAction(ENOBUFS, running: true) == .backoff)
        #expect(SocketServer.acceptFailureAction(EPROTO, running: true) == .backoff)
        #expect(SocketServer.acceptFailureAction(EBADF, running: true) == .stop)
        #expect(SocketServer.acceptFailureAction(EINVAL, running: true) == .stop)
        #expect(SocketServer.acceptFailureAction(EAGAIN, running: false) == .stop)
    }

    @Test("a second server cannot unlink or steal a live control endpoint")
    func liveSocketOwnership() async throws {
        let owner = try await SecurityHostFixture.make(start: true)
        defer { owner.host.stop(); try? FileManager.default.removeItem(at: owner.root) }
        let contender = try await SecurityHostFixture.make(socketPath: owner.socketPath)
        defer { contender.host.stop(); try? FileManager.default.removeItem(at: contender.root) }

        #expect(throws: SocketServer.SocketError.self) { try contender.host.start() }
        let reply = try TestSocketClient.request(
            owner.socketPath, ["type": "list_tools", "id": "owner-still-live"])
        #expect(reply["type"] as? String == "list_tools_result")
        #expect(FileManager.default.fileExists(atPath: owner.socketPath))
        await contender.store.close()
        await owner.store.close()
    }

    @Test("socket and containing directory are owner-only; stop removes the socket")
    func permissionsAndStopCleanup() async throws {
        let fixture = try await SecurityHostFixture.make(start: true)
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        var socketInfo = stat()
        var dirInfo = stat()
        #expect(lstat(fixture.socketPath, &socketInfo) == 0)
        #expect(lstat((fixture.socketPath as NSString).deletingLastPathComponent, &dirInfo) == 0)
        #expect(socketInfo.st_mode & 0o777 == 0o700)
        #expect(dirInfo.st_mode & 0o777 == 0o700)

        fixture.host.stop()
        #expect(lstat(fixture.socketPath, &socketInfo) != 0 && errno == ENOENT)
        await fixture.store.close()
    }

    @Test("startup rejects dangerous paths before side effects and preserves regular files")
    func pathValidationAndStaleFileSafety() async throws {
        // Existing non-socket content is never unlinked as "stale".
        let stale = try await SecurityHostFixture.make()
        let socketDir = URL(fileURLWithPath: stale.socketPath).deletingLastPathComponent()
        try FileManager.default.createDirectory(at: socketDir, withIntermediateDirectories: true)
        let marker = Data("do not delete".utf8)
        try marker.write(to: URL(fileURLWithPath: stale.socketPath))
        #expect(throws: SocketServer.SocketError.self) { try stale.host.start() }
        #expect(try Data(contentsOf: URL(fileURLWithPath: stale.socketPath)) == marker)
        await stale.cleanUp()

        let long = try await SecurityHostFixture.make()
        let overlongPath = long.root.appendingPathComponent(String(repeating: "x", count: 110)).path
        let longHost = try await SecurityHostFixture.make(socketPath: overlongPath)
        #expect(throws: SocketServer.SocketError.self) { try longHost.host.start() }
        #expect(!FileManager.default.fileExists(atPath: overlongPath))
        // No truncated socket artifact was left in the target directory.
        let sockets = (try? FileManager.default.contentsOfDirectory(atPath: longHost.root.path)) ?? []
        #expect(!sockets.contains { $0.hasPrefix(String(repeating: "x", count: 20)) })
        await long.cleanUp()
        await longHost.cleanUp()

        let relative = try await SecurityHostFixture.make(socketPath: "relative.sock")
        #expect(throws: SocketServer.SocketError.self) { try relative.host.start() }
        #expect(!FileManager.default.fileExists(atPath: "relative.sock"))
        await relative.cleanUp()

        let nul = try await SecurityHostFixture.make(socketPath: nulPath())
        #expect(throws: SocketServer.SocketError.self) { try nul.host.start() }
        await nul.cleanUp()

        // A socket directly in an existing shared/non-private directory must be
        // refused without chmodding that directory as a side effect.
        let sharedDir = URL(fileURLWithPath: "/tmp/sp-shared-\(UUID().uuidString.prefix(8))",
                            isDirectory: true)
        try FileManager.default.createDirectory(at: sharedDir, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o755])
        try FileManager.default.setAttributes([.posixPermissions: 0o755],
                                              ofItemAtPath: sharedDir.path)
        defer { try? FileManager.default.removeItem(at: sharedDir) }
        let shared = try await SecurityHostFixture.make(
            socketPath: sharedDir.appendingPathComponent("sallyport.sock").path)
        #expect(throws: SocketServer.SocketError.self) { try shared.host.start() }
        let attrs = try FileManager.default.attributesOfItem(atPath: sharedDir.path)
        #expect((attrs[.posixPermissions] as? NSNumber)?.intValue == 0o755)
        await shared.cleanUp()
    }

    private func nulPath() -> String {
        "/tmp/sp-invalid-" + String(UnicodeScalar(0)) + "suffix.sock"
    }
}
