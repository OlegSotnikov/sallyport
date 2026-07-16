import Darwin
import Foundation
import Network
import Testing
@testable import SallyportVault

private func launchPinnedHTTPFixture() throws
    -> (port: Int, process: Process, events: FileHandle) {
    let dir = FileManager.default.temporaryDirectory
        .appendingPathComponent("sp-pinned-http-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    let script = dir.appendingPathComponent("server.py")
    try #"""
    import time
    from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def log_message(self, *args): pass
        def do_GET(self):
            if self.path == "/stall":
                print("STALL", flush=True)
                time.sleep(10)
            auth = self.headers.get("Authorization", "")
            host = self.headers.get("Host", "")
            body = (host + "\n" + auth).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            if length:
                self.rfile.read(length)
            if self.path == "/mcp-stall":
                print("MCPSTALL " + self.headers.get("Authorization", ""), flush=True)
                time.sleep(10)
            body = b'{}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("0.0.0.0", 0), H)
    server.daemon_threads = True
    print(server.server_address[1], flush=True)
    server.serve_forever()
    """#.write(to: script, atomically: true, encoding: .utf8)

    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
    process.arguments = ["python3", script.path]
    let output = Pipe()
    process.standardOutput = output
    process.standardError = FileHandle.nullDevice
    try process.run()
    guard let line = output.fileHandleForReading.availableData.split(separator: 0x0a).first,
          let port = Int(String(decoding: line, as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)) else {
        process.terminate()
        throw PinnedTransportError.unavailable
    }
    return (port, process, output.fileHandleForReading)
}

private func firstNonLoopbackIPv4() -> String? {
    var head: UnsafeMutablePointer<ifaddrs>?
    guard getifaddrs(&head) == 0, let first = head else { return nil }
    defer { freeifaddrs(first) }
    var fallback: String?
    var node: UnsafeMutablePointer<ifaddrs>? = first
    while let current = node {
        defer { node = current.pointee.ifa_next }
        guard let address = current.pointee.ifa_addr,
              Int32(address.pointee.sa_family) == AF_INET,
              current.pointee.ifa_flags & UInt32(IFF_UP) != 0,
              current.pointee.ifa_flags & UInt32(IFF_LOOPBACK) == 0 else { continue }
        var copy = address.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
        var text = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        guard inet_ntop(AF_INET, &copy.sin_addr, &text, socklen_t(text.count)) != nil else {
            continue
        }
        let candidate = String(
            decoding: text.prefix { $0 != 0 }.map(UInt8.init(bitPattern:)), as: UTF8.self)
        if current.pointee.ifa_flags & UInt32(IFF_POINTOPOINT) == 0 { return candidate }
        fallback = fallback ?? candidate
    }
    return fallback
}

private func launchPinnedTLSFixture() throws -> (port: Int, process: Process) {
    let dir = FileManager.default.temporaryDirectory
        .appendingPathComponent("sp-pinned-tls-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    let cert = dir.appendingPathComponent("cert.pem")
    let key = dir.appendingPathComponent("key.pem")
    let openssl = Process()
    openssl.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
    openssl.arguments = ["req", "-x509", "-newkey", "rsa:2048", "-nodes",
                         "-keyout", key.path, "-out", cert.path,
                         "-subj", "/CN=sni.invalid", "-days", "1"]
    openssl.standardOutput = FileHandle.nullDevice
    openssl.standardError = FileHandle.nullDevice
    try openssl.run()
    openssl.waitUntilExit()
    guard openssl.terminationStatus == 0 else { throw PinnedTransportError.unavailable }

    let script = dir.appendingPathComponent("tls_server.py")
    try #"""
    import ssl, sys
    from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def log_message(self, *args): pass
        def do_GET(self):
            body = getattr(self.connection, "sallyport_sni", "").encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), H)
    server.daemon_threads = True
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(sys.argv[1], sys.argv[2])
    def capture(sock, name, context):
        sock.sallyport_sni = name or ""
    context.set_servername_callback(capture)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(server.server_address[1], flush=True)
    server.serve_forever()
    """#.write(to: script, atomically: true, encoding: .utf8)

    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
    process.arguments = ["python3", script.path, cert.path, key.path]
    let output = Pipe()
    process.standardOutput = output
    process.standardError = FileHandle.nullDevice
    try process.run()
    guard let line = output.fileHandleForReading.availableData.split(separator: 0x0a).first,
          let port = Int(String(decoding: line, as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)) else {
        process.terminate()
        throw PinnedTransportError.unavailable
    }
    return (port, process)
}

private func loadThroughPin(url: URL, destination: PinnedDestination,
                            authorization: String = "", allowInsecureTLS: Bool = false)
    async throws -> (Data, HTTPURLResponse) {
    var request = URLRequest(url: url)
    request.timeoutInterval = 3
    if !authorization.isEmpty {
        request.setValue(authorization, forHTTPHeaderField: "Authorization")
    }
    let policy = RedirectPolicy(origin: url.hostPort,
                                originScheme: url.scheme ?? "http",
                                hasCredential: !authorization.isEmpty,
                                allowInsecureTLS: allowInsecureTLS,
                                maxBody: 4096)
    return try await PinnedHTTPTransport().loadCapped(
        request: request, destination: destination, policy: policy, hardTimeout: 3)
}

private func rawSOCKSClient(port: UInt16) throws -> Int32 {
    let fd = socket(AF_INET, SOCK_STREAM, 0)
    guard fd >= 0 else { throw PinnedTransportError.unavailable }
    var timeout = timeval(tv_sec: 1, tv_usec: 0)
    _ = withUnsafePointer(to: &timeout) {
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, $0,
                   socklen_t(MemoryLayout<timeval>.size))
    }
    var address = sockaddr_in()
    address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    address.sin_family = sa_family_t(AF_INET)
    address.sin_port = port.bigEndian
    address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
    let result = withUnsafePointer(to: &address) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
        }
    }
    guard result == 0 else { Darwin.close(fd); throw PinnedTransportError.unavailable }
    return fd
}

private func writeBytes(_ bytes: [UInt8], to fd: Int32) throws {
    let sent = bytes.withUnsafeBytes { raw in
        Darwin.send(fd, raw.baseAddress, raw.count, 0)
    }
    guard sent == bytes.count else { throw PinnedTransportError.unavailable }
}

private func readBytes(_ count: Int, from fd: Int32) throws -> [UInt8] {
    var result: [UInt8] = []
    while result.count < count {
        var chunk = [UInt8](repeating: 0, count: count - result.count)
        let received = chunk.withUnsafeMutableBytes { raw in
            Darwin.recv(fd, raw.baseAddress, raw.count, 0)
        }
        guard received > 0 else { throw PinnedTransportError.unavailable }
        result.append(contentsOf: chunk.prefix(received))
    }
    return result
}

@Suite("Pinned HTTP transport — DNS rebinding", .serialized)
struct PinnedHTTPTransportTests {
    @Test("one logical load uses exactly one validated DNS snapshot")
    func oneSnapshotPerLoad() async throws {
        let fixture = try launchPinnedHTTPFixture()
        defer { fixture.process.terminate() }

        let lookups = Locked(0)
        var guardrail = NetGuard()
        guardrail.resolve = { host in
            #expect(host == "rebind.invalid")
            return lookups.withLock { count in
                count += 1
                return count == 1 ? [IPAddr("127.0.0.1")!] : [IPAddr("169.254.169.254")!]
            }
        }
        let url = URL(string: "http://rebind.invalid:\(fixture.port)/proof")!
        let destination = try guardrail.destination(for: url, bound: true)
        let (body, response) = try await loadThroughPin(
            url: url, destination: destination, authorization: "Bearer pinned-secret")

        #expect(response.statusCode == 200)
        #expect(String(decoding: body, as: UTF8.self)
            == "rebind.invalid:\(fixture.port)\nBearer pinned-secret")
        #expect(lookups.current == 1,
                "URLSession/proxy must not re-resolve after validation")

        // A new logical load performs a fresh lookup and rejects the changed,
        // hostile answer before any replay or connection attempt.
        #expect(throws: BlockedError.self) {
            _ = try guardrail.destination(for: url, bound: true)
        }
        #expect(lookups.current == 2)
    }

    @Test("full IPv4/IPv6 snapshot supports bounded failover")
    func multiAddressFailover() async throws {
        let fixture = try launchPinnedHTTPFixture()
        defer { fixture.process.terminate() }
        let url = URL(string: "http://multi.invalid:\(fixture.port)/")!
        let destination = try PinnedDestination(
            url: url, addresses: [IPAddr("::1")!, IPAddr("127.0.0.1")!])

        let (body, response) = try await loadThroughPin(url: url, destination: destination)
        #expect(response.statusCode == 200)
        #expect(String(decoding: body, as: UTF8.self).hasPrefix("multi.invalid:"))
    }

    @Test("TLS keeps the original hostname as SNI through the numeric pin")
    func originalTLSIdentityIsPreserved() async throws {
        let fixture = try launchPinnedTLSFixture()
        defer { fixture.process.terminate() }
        let url = URL(string: "https://sni.invalid:\(fixture.port)/")!
        let destination = try PinnedDestination(
            url: url, addresses: [IPAddr("127.0.0.1")!])
        let (body, response) = try await loadThroughPin(
            url: url, destination: destination, authorization: "Bearer proof",
            allowInsecureTLS: true)
        #expect(response.statusCode == 200)
        #expect(String(decoding: body, as: UTF8.self) == "sni.invalid")
    }

    @Test("snapshot normalization keeps order and removes mapped duplicates")
    func normalizedSnapshot() throws {
        let mapped = IPAddr(bytes: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff,
                                    192, 0, 2, 1])
        var guardrail = NetGuard()
        guardrail.resolve = { _ in [mapped, IPAddr("192.0.2.1")!, IPAddr("2001:db8::1")!] }
        let result = try guardrail.validatedAddresses(host: "cdn.invalid", bound: false)
        #expect(result == [IPAddr("192.0.2.1")!, IPAddr("2001:db8::1")!])
    }

    @Test("transport rejects a request whose host or effective port differs from its pin")
    func requestAuthorityMustMatchPin() async throws {
        let pinnedURL = URL(string: "https://api.invalid/resource")!
        let destination = try PinnedDestination(
            url: pinnedURL, addresses: [IPAddr("192.0.2.10")!])
        let transport = PinnedHTTPTransport()
        for mismatched in [
            URL(string: "https://other.invalid/resource")!,
            URL(string: "https://api.invalid:444/resource")!,
            URL(string: "http://api.invalid/resource")!,
        ] {
            let request = URLRequest(url: mismatched)
            let policy = RedirectPolicy(origin: mismatched.hostPort,
                                        originScheme: mismatched.scheme ?? "https",
                                        hasCredential: true, maxBody: 1024)
            do {
                _ = try await transport.loadCapped(
                    request: request, destination: destination, policy: policy,
                    hardTimeout: 1)
                Issue.record("mismatched request authority must fail before transport")
            } catch let error as PinnedTransportError {
                #expect(error == .destinationRefused)
            } catch {
                Issue.record("expected destinationRefused, got \(error)")
            }
        }
    }

    @Test("a dead pinned proxy never falls back directly to a reachable target")
    func noDirectFallback() async throws {
        let fixture = try launchPinnedHTTPFixture()
        defer { fixture.process.terminate() }
        guard let reachableHost = firstNonLoopbackIPv4() else {
            throw PinnedTransportError.unavailable
        }
        let url = URL(string: "http://\(reachableHost):\(fixture.port)/fallback-proof")!

        // Establish that the real target is reachable without Sallyport's proxy.
        let direct = URLSession(configuration: .ephemeral)
        defer { direct.invalidateAndCancel() }
        let (_, directResponse) = try await direct.data(from: url)
        #expect((directResponse as? HTTPURLResponse)?.statusCode == 200)

        let destination = try PinnedDestination(
            url: url, addresses: [IPAddr(reachableHost)!])
        let transport = PinnedHTTPTransport(proxyReadyHook: { proxy in
            // The URLSession is created only after this hook returns.
            proxy.stop()
        })
        let request = URLRequest(url: url)
        let policy = RedirectPolicy(origin: url.hostPort, originScheme: "http",
                                    hasCredential: false, maxBody: 1024)
        do {
            _ = try await transport.loadCapped(
                request: request, destination: destination, policy: policy,
                hardTimeout: 2)
            Issue.record("URLSession reached the target directly after its pinned proxy died")
        } catch {
            // Connection failure is required: allowFailover=false forbids direct access.
        }
    }

    @Test("Happy Eyeballs preserves family order and never schedules over two dials")
    func boundedHappyEyeballs() {
        let v6a = IPAddr("2001:db8::1")!
        let v6b = IPAddr("2001:db8::2")!
        let v4a = IPAddr("192.0.2.1")!
        let v4b = IPAddr("192.0.2.2")!
        var scheduler = PinnedDialScheduler(addresses: [v6a, v6b, v4a, v4b])
        let first = scheduler.takeNext()!
        let second = scheduler.takeNext()!
        #expect([first.address, second.address] == [v6a, v4a])
        #expect(scheduler.active.count == 2)
        #expect(scheduler.takeNext() == nil)
        scheduler.completed(ticket: first.ticket)
        let third = scheduler.takeNext()!
        #expect(third.address == v6b)
        #expect(scheduler.active.count == PinnedDialScheduler.maxConcurrent)
        #expect(scheduler.takeNext() == nil)
        // Two blackholed attempts eventually time out; completing both tickets
        // immediately exposes the remaining snapshot members without exceeding
        // the two-connection bound.
        scheduler.completed(ticket: second.ticket)
        scheduler.completed(ticket: third.ticket)
        let fourth = scheduler.takeNext()!
        #expect(fourth.address == v4b)
        #expect(scheduler.active.count == 1)
    }

    @Test("SOCKS requires its capability and binds host, port, and numeric snapshot")
    func socksCapabilityAndTargetBinding() async throws {
        let url = URL(string: "http://expected.invalid:8080/")!
        let v4 = IPAddr("192.0.2.8")!
        let v6 = IPAddr("2001:db8::8")!
        let destination = try PinnedDestination(url: url, addresses: [v4, v6])
        #expect(destination.allows(host: "EXPECTED.INVALID.", port: 8080))
        #expect(!destination.allows(host: "other.invalid", port: 8080))
        #expect(!destination.allows(host: "expected.invalid", port: 8081))
        #expect(destination.allows(address: v4, port: 8080))
        #expect(destination.allows(address: v6, port: 8080))
        #expect(!destination.allows(address: IPAddr("169.254.169.254")!, port: 8080))

        let proxy = try await PinnedSOCKSProxy.start(destination: destination)
        defer { proxy.stop() }

        // A client offering only unauthenticated SOCKS is rejected before it can
        // name or reach any destination.
        let unauthenticated = try rawSOCKSClient(port: proxy.port.rawValue)
        defer { Darwin.close(unauthenticated) }
        try writeBytes([0x05, 0x01, 0x00], to: unauthenticated)
        #expect(try readBytes(2, from: unauthenticated) == [0x05, 0xff])

        let wrongPassword = try rawSOCKSClient(port: proxy.port.rawValue)
        defer { Darwin.close(wrongPassword) }
        try writeBytes([0x05, 0x01, 0x02], to: wrongPassword)
        #expect(try readBytes(2, from: wrongPassword) == [0x05, 0x02])
        let capabilityUser = [UInt8](proxy.username.utf8)
        let incorrect = [UInt8]("incorrect".utf8)
        try writeBytes([0x01, UInt8(capabilityUser.count)] + capabilityUser
                       + [UInt8(incorrect.count)] + incorrect, to: wrongPassword)
        #expect(try readBytes(2, from: wrongPassword) == [0x01, 0x01])

        // Authenticate with the request-scoped capability, then prove a
        // different host is rejected without dialing it.
        let client = try rawSOCKSClient(port: proxy.port.rawValue)
        defer { Darwin.close(client) }
        try writeBytes([0x05, 0x01, 0x02], to: client)
        #expect(try readBytes(2, from: client) == [0x05, 0x02])
        let user = [UInt8](proxy.username.utf8)
        let pass = [UInt8](proxy.password.utf8)
        try writeBytes([0x01, UInt8(user.count)] + user + [UInt8(pass.count)] + pass,
                       to: client)
        #expect(try readBytes(2, from: client) == [0x01, 0x00])
        let hostile = [UInt8]("other.invalid".utf8)
        try writeBytes([0x05, 0x01, 0x00, 0x03, UInt8(hostile.count)] + hostile
                       + [0x1f, 0x90], to: client)
        #expect(throws: (any Error).self) {
            _ = try readBytes(10, from: client)
        }
        #expect(proxy.isStopped,
                "an authenticated destination mismatch must kill the owner proxy")
    }

    @Test("constant-time capability comparison includes length")
    func capabilityComparison() {
        #expect(SOCKSClient.constantTimeEqual(Data("abc".utf8), Data("abc".utf8)))
        #expect(!SOCKSClient.constantTimeEqual(Data("abc".utf8), Data("abd".utf8)))
        #expect(!SOCKSClient.constantTimeEqual(Data("abc".utf8), Data("abc\0".utf8)))
    }

    @Test("listener caps unauthenticated clients and stop cancels them synchronously")
    func clientCapAndCleanup() async throws {
        let destination = try PinnedDestination(
            url: URL(string: "http://expected.invalid:8080/")!,
            addresses: [IPAddr("192.0.2.8")!])
        let proxy = try await PinnedSOCKSProxy.start(destination: destination)
        var clients: [Int32] = []
        defer { for fd in clients { Darwin.close(fd) } }
        for _ in 0..<9 { clients.append(try rawSOCKSClient(port: proxy.port.rawValue)) }

        let deadline = ContinuousClock.now + .seconds(1)
        while proxy.activeClientCount < 8, ContinuousClock.now < deadline {
            try await Task.sleep(for: .milliseconds(5))
        }
        #expect(proxy.activeClientCount == 8)
        proxy.stop()
        #expect(proxy.isStopped)
        #expect(proxy.activeClientCount == 0)
    }

    @Test("transport shutdown cancels active loads and permanently closes the owner")
    func ownerShutdownClosesRace() async throws {
        let fixture = try launchPinnedHTTPFixture()
        defer { fixture.process.terminate() }
        let url = URL(string: "http://shutdown.invalid:\(fixture.port)/stall")!
        let destination = try PinnedDestination(
            url: url, addresses: [IPAddr("127.0.0.1")!])
        let transport = PinnedHTTPTransport()
        let task = Task {
            var request = URLRequest(url: url)
            request.timeoutInterval = 30
            request.setValue("Bearer must-stop", forHTTPHeaderField: "Authorization")
            let policy = RedirectPolicy(origin: url.hostPort, originScheme: "http",
                                        hasCredential: true, maxBody: 1024)
            _ = try await transport.loadCapped(request: request, destination: destination,
                                               policy: policy, hardTimeout: 30)
        }
        // Do not rely on task scheduling speed: the server signals only after
        // it has received the credential-bearing request and begun its 10 s stall.
        let marker = fixture.events.availableData
        #expect(String(decoding: marker, as: UTF8.self).contains("STALL"))
        let started = ContinuousClock.now
        transport.shutdown()
        do {
            _ = try await task.value
            Issue.record("shutdown must cancel the active load")
        } catch {
            // Cancellation/URLSession teardown is the required outcome.
        }
        #expect(ContinuousClock.now - started < .seconds(1))

        var request = URLRequest(url: url)
        request.timeoutInterval = 1
        request.setValue("Bearer must-stop", forHTTPHeaderField: "Authorization")
        let nextPolicy = RedirectPolicy(origin: url.hostPort, originScheme: "http",
                                        hasCredential: true, maxBody: 1024)
        do {
            _ = try await transport.loadCapped(request: request, destination: destination,
                                               policy: nextPolicy, hardTimeout: 1)
            Issue.record("a shut-down owner must reject future loads")
        } catch let error as PinnedTransportError {
            #expect(error.description == PinnedTransportError.unavailable.description)
        } catch {
            Issue.record("expected PinnedTransportError.unavailable, got \(error)")
        }
    }

    @Test("Remote MCP terminate cancels an in-flight credential-bearing RPC")
    func remoteMCPTerminateCancelsInflight() async throws {
        let fixture = try launchPinnedHTTPFixture()
        defer { fixture.process.terminate() }
        let endpoint = URL(string: "http://127.0.0.1:\(fixture.port)/mcp-stall")!
        let connection = RemoteMCPConnection(
            name: "stalling", endpoint: endpoint,
            bearer: { "remote-mcp-secret" })
        let task = Task { try await connection.start(timeout: 30) }

        let marker = fixture.events.availableData
        let markerText = String(decoding: marker, as: UTF8.self)
        #expect(markerText.contains("MCPSTALL Bearer remote-mcp-secret"))
        let started = ContinuousClock.now
        connection.terminate()
        do {
            try await task.value
            Issue.record("terminate must cancel the in-flight MCP request")
        } catch {
            // Owner shutdown is expected to surface as cancellation/transport failure.
        }
        #expect(!connection.isAlive)
        #expect(ContinuousClock.now - started < .seconds(1))
    }
}
