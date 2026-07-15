import Foundation

/// One-shot RFC 8252 OAuth callback listener on loopback. It closes after a
/// callback, timeout, or cancellation.
public final class LoopbackCallbackServer: @unchecked Sendable {

    struct Callback: Sendable {
        var code: String
        var state: String
    }

    public enum CallbackError: Error, CustomStringConvertible, Sendable {
        case bind(String)
        case timedOut
        /// Error returned by the authorization server.
        case denied(String)
        case badRequest

        public var description: String {
            switch self {
            case .bind(let m): return "Could not open the sign-in listener: \(m)"
            case .timedOut: return "Sign-in timed out."
            case .denied(let m): return m
            case .badRequest: return "The browser sent an unexpected callback."
            }
        }
    }

    /// The redirect URI to register and send to the authorization server.
    var redirectURI: String { "http://127.0.0.1:\(port)/callback" }

    private let fd: Int32
    let port: Int
    private let queue = DispatchQueue(label: "sallyport.oauth.callback")
    private var closed = false
    private var fdClosed = false
    private var activeConn: Int32 = -1
    private var closeWaiter: (@Sendable () -> Void)?
    private let lock = NSLock()

    /// Bind an ephemeral loopback port. `preferredPort` (from a previous
    /// registration) is tried first, since some authorization servers pin the
    /// exact redirect URI they registered; 0/unavailable falls back to any.
    init(preferredPort: Int = 0) throws {
        var sock = socket(AF_INET, SOCK_STREAM, 0)
        guard sock >= 0 else { throw CallbackError.bind(String(cString: strerror(errno))) }
        var yes: Int32 = 1
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))

        func bindPort(_ p: Int) -> Bool {
            guard let port = UInt16(exactly: p) else { return false }
            var addr = sockaddr_in()
            addr.sin_family = sa_family_t(AF_INET)
            addr.sin_port = in_port_t(port).bigEndian
            addr.sin_addr.s_addr = INADDR_LOOPBACK.bigEndian   // 127.0.0.1 only
            let ok = withUnsafePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.bind(sock, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
            return ok == 0
        }

        if preferredPort > 0, !bindPort(preferredPort) {
            // Fall back to an ephemeral port if the remembered port is in use.
            Darwin.close(sock)
            sock = socket(AF_INET, SOCK_STREAM, 0)
            guard sock >= 0 else { throw CallbackError.bind(String(cString: strerror(errno))) }
            setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))
            guard bindPort(0) else {
                Darwin.close(sock)
                throw CallbackError.bind(String(cString: strerror(errno)))
            }
        } else if preferredPort <= 0, !bindPort(0) {
            Darwin.close(sock)
            throw CallbackError.bind(String(cString: strerror(errno)))
        }

        guard listen(sock, 1) == 0 else {
            Darwin.close(sock)
            throw CallbackError.bind(String(cString: strerror(errno)))
        }
        var bound = sockaddr_in()
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        withUnsafeMutablePointer(to: &bound) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { _ = getsockname(sock, $0, &len) }
        }
        self.fd = sock
        self.port = Int(UInt16(bigEndian: bound.sin_port))
    }

    /// Wait for the browser's callback. Returns the code+state, or throws on
    /// timeout / an error redirect. Idempotently closes the socket.
    func wait(timeout: TimeInterval) async throws -> Callback {
        defer { close() }
        let timeoutDelay = timeout.isFinite && timeout > 0 ? timeout : 0
        return try await withTaskCancellationHandler {
            try Task.checkCancellation()
            return try await withCheckedThrowingContinuation { cont in
                let resumed = ResumeOnce(cont)
                let mayStart = lock.withLock { () -> Bool in
                    guard !closed else { return false }
                    closeWaiter = {
                        _ = resumed.resume(throwing: CallbackError.timedOut)
                    }
                    return true
                }
                guard mayStart else {
                    resumed.resume(throwing: CallbackError.timedOut)
                    return
                }
                queue.async { [fd] in
                // This queue owns the listener descriptor. Timeout/cancellation
                // may shutdown it to unblock accept, but must never close it from
                // another thread: the numeric fd can be reused before this loop
                // returns, turning a stale accept/close into corruption of an
                // unrelated socket or pipe.
                defer { self.finishListener() }
                // Browsers may hit the port with a favicon/preflight request
                // before or after the callback. Keep accepting until
                // one carries `code` or `error`.
                while true {
                    let conn = accept(fd, nil, nil)
                    if conn < 0 {
                        if errno == EINTR {
                            if self.lock.withLock({ self.closed }) {
                                resumed.resume(throwing: CallbackError.timedOut)
                                return
                            }
                            continue
                        }
                        resumed.resume(throwing: CallbackError.timedOut)  // socket closed
                        return
                    }
                    let mayServe = self.lock.withLock { () -> Bool in
                        guard !self.closed else { return false }
                        self.activeConn = conn
                        return true
                    }
                    guard mayServe else {
                        Darwin.close(conn)
                        resumed.resume(throwing: CallbackError.timedOut)
                        return
                    }
                    defer {
                        self.lock.withLock {
                            if self.activeConn == conn { self.activeConn = -1 }
                        }
                        Darwin.close(conn)
                    }
                    // Prevent SIGPIPE and bound idle client reads.
                    var one: Int32 = 1
                    setsockopt(conn, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
                    var rcv = timeval(tv_sec: 5, tv_usec: 0)
                    setsockopt(conn, SOL_SOCKET, SO_RCVTIMEO, &rcv, socklen_t(MemoryLayout<timeval>.size))
                    guard let requestLine = Self.readRequestLine(conn) else {
                        Self.respond(conn, status: "400 Bad Request", body: Self.errorPage("Bad request"))
                        continue
                    }
                    guard let query = Self.query(fromRequestLine: requestLine) else {
                        Self.respond(conn, status: "404 Not Found", body: Self.errorPage("Not found"))
                        continue
                    }
                    if let error = query["error"] {
                        let detail = query["error_description"] ?? error
                        Self.respond(conn, status: "200 OK", body: Self.errorPage(detail))
                        resumed.resume(throwing: CallbackError.denied(detail))
                        return
                    }
                    guard let code = query["code"], !code.isEmpty else {
                        Self.respond(conn, status: "400 Bad Request", body: Self.errorPage("No authorization code"))
                        continue
                    }
                    Self.respond(conn, status: "200 OK", body: Self.successPage())
                    resumed.resume(returning: Callback(code: code, state: query["state"] ?? ""))
                    return
                }
            }
            // Run the timeout on a separate queue because the listener queue can
            // block in accept or read. Closing the descriptor unblocks it.
                DispatchQueue.global().asyncAfter(deadline: .now() + timeoutDelay) { [weak self] in
                    guard let self else { return }
                    if resumed.resume(throwing: CallbackError.timedOut) { self.close() }
                }
            }
        } onCancel: { [weak self] in
            self?.close()
        }
    }

    func close() {
        lock.lock()
        guard !closed else {
            lock.unlock()
            return
        }
        closed = true
        if activeConn >= 0 { shutdown(activeConn, SHUT_RDWR) }
        if !fdClosed { shutdown(fd, SHUT_RDWR) }
        let waiter = closeWaiter
        closeWaiter = nil
        lock.unlock()
        // Resume outside the lock: returning from wait runs its defer { close() },
        // which would otherwise re-enter this lock synchronously.
        waiter?()
    }

    /// Called only by the accept queue when it has stopped using `fd`.
    private func finishListener() {
        lock.lock()
        defer { lock.unlock() }
        guard !fdClosed else { return }
        fdClosed = true
        closed = true
        closeWaiter = nil
        Darwin.close(fd)
    }

    // MARK: - HTTP parsing

    private static func readRequestLine(_ conn: Int32) -> String? {
        let cap = 8192
        var line = Data()
        line.reserveCapacity(512)
        var buf = [UInt8](repeating: 0, count: 1024)
        while line.count < cap {
            let n = read(conn, &buf, min(buf.count, cap - line.count))
            if n < 0 {
                if errno == EINTR { continue }
                return nil
            }
            // EOF without LF is an incomplete HTTP request, not a valid line.
            guard n > 0 else { return nil }
            line.append(contentsOf: buf[0..<n])
            if let lf = line.firstIndex(of: 0x0A) {
                var end = lf
                if end > line.startIndex, line[line.index(before: end)] == 0x0D {
                    end = line.index(before: end)
                }
                return String(decoding: line[..<end], as: UTF8.self)
            }
        }
        return nil
    }

    /// Parses callback query fields from an HTTP request line.
    static func query(fromRequestLine line: String) -> [String: String]? {
        let parts = line.split(separator: " ")
        guard parts.count >= 2, parts[0] == "GET" else { return nil }
        let target = String(parts[1])
        guard let comps = URLComponents(string: "http://127.0.0.1" + target),
              comps.path == "/callback" else { return nil }
        var out: [String: String] = [:]
        for item in comps.queryItems ?? [] {
            out[item.name] = item.value ?? ""
        }
        return out
    }

    private static func respond(_ conn: Int32, status: String, body: String) {
        let response = """
            HTTP/1.1 \(status)\r
            Content-Type: text/html; charset=utf-8\r
            Content-Length: \(body.utf8.count)\r
            Connection: close\r
            \r
            \(body)
            """
        let data = Array(response.utf8)
        data.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return }
            var sent = 0
            while sent < raw.count {
                let n = write(conn, base.advanced(by: sent), raw.count - sent)
                if n <= 0 { return }
                sent += n
            }
        }
    }

    private static func page(_ title: String, _ message: String, accent: String) -> String {
        """
        <!doctype html><meta charset="utf-8"><title>Sallyport</title>
        <style>
          body { font: 15px/1.5 -apple-system, system-ui, sans-serif; color: #1d1d1f;
                 display: grid; place-items: center; height: 100vh; margin: 0; background: #f5f5f7; }
          .card { background: #fff; padding: 32px 40px; border-radius: 14px; text-align: center;
                  box-shadow: 0 1px 3px rgba(0,0,0,.08); max-width: 420px; }
          h1 { font-size: 17px; margin: 0 0 6px; color: \(accent); }
          p { margin: 0; color: #6e6e73; }
          @media (prefers-color-scheme: dark) {
            body { background: #1c1c1e; color: #f5f5f7; }
            .card { background: #2c2c2e; box-shadow: none; }
            p { color: #98989d; }
          }
        </style>
        <div class="card"><h1>\(title)</h1><p>\(message)</p></div>
        """
    }

    private static func successPage() -> String {
        page("Sign-in complete", "You can close this tab.", accent: "#1d7d3f")
    }

    private static func errorPage(_ detail: String) -> String {
        let safe = detail
            .replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
        return page("Sign-in failed", safe, accent: "#c0392b")
    }
}

/// A continuation that can only be resumed once (the accept loop and the
/// timeout race each other).
private final class ResumeOnce: @unchecked Sendable {
    private var cont: CheckedContinuation<LoopbackCallbackServer.Callback, any Error>?
    private let lock = NSLock()

    init(_ cont: CheckedContinuation<LoopbackCallbackServer.Callback, any Error>) {
        self.cont = cont
    }

    @discardableResult
    func resume(returning value: LoopbackCallbackServer.Callback) -> Bool {
        guard let c = take() else { return false }
        c.resume(returning: value)
        return true
    }

    @discardableResult
    func resume(throwing error: any Error) -> Bool {
        guard let c = take() else { return false }
        c.resume(throwing: error)
        return true
    }

    private func take() -> CheckedContinuation<LoopbackCallbackServer.Callback, any Error>? {
        lock.lock()
        defer { lock.unlock() }
        let c = cont
        cont = nil
        return c
    }
}
