import Foundation
import SallyportKit

/// Agent control server on a 0700 Unix socket. It captures each connection's peer
/// PID with `LOCAL_PEERPID` for provenance checks and handles `invoke` and
/// `list_tools` frames.
public final class SocketServer: @unchecked Sendable {
    /// Maximum concurrent connections.
    static let maxConnections = 32
    /// The shipped CLI sends immediately. Idle sockets get one second; a peer
    /// trickling an unterminated frame gets two seconds total, not per byte.
    static let idleReadTimeoutSeconds: Int = 1
    static let partialFrameTimeoutNanoseconds: UInt64 = 2_000_000_000
    /// Credential UI timeout plus a one-minute cleanup margin.
    static let invokeTimeoutSeconds: TimeInterval = 16 * 60
    /// Catalog generation timeout.
    static let catalogTimeoutSeconds: TimeInterval = 10

    public let path: String
    private let invokeAction: @Sendable (String, Action, Provenance) async -> InvokeResult
    private let invokeTimeout: TimeInterval
    private let catalogTimeout: TimeInterval
    private let tools: @Sendable () async -> [JSONValue]
    private var listenFD: Int32 = -1
    private var ownershipFD: Int32 = -1
    private var socketIdentity: (dev: dev_t, ino: ino_t)?
    private let queue = DispatchQueue(label: "sallyport.socket.accept")
    private let stateLock = NSLock()
    private var running = false
    private var activeConnections: Set<Int32> = []

    public init(path: String, engine: Engine,
                tools: @escaping @Sendable () async -> [JSONValue]) {
        self.path = path
        self.invokeTimeout = Self.invokeTimeoutSeconds
        self.catalogTimeout = Self.catalogTimeoutSeconds
        self.invokeAction = { identity, action, provenance in
            await engine.invoke(identity: identity, action: action, provenance: provenance)
        }
        self.tools = tools
    }

    /// Timeout override for tests.
    init(path: String, invokeTimeout: TimeInterval,
         catalogTimeout: TimeInterval = SocketServer.catalogTimeoutSeconds,
         tools: @escaping @Sendable () async -> [JSONValue],
         invokeAction: @escaping @Sendable (String, Action, Provenance) async -> InvokeResult) {
        self.path = path
        self.invokeTimeout = invokeTimeout.isFinite
            ? min(max(0, invokeTimeout), Self.invokeTimeoutSeconds) : 0
        self.catalogTimeout = catalogTimeout.isFinite
            ? min(max(0, catalogTimeout), Self.catalogTimeoutSeconds) : 0
        self.invokeAction = invokeAction
        self.tools = tools
    }

    /// Bind the socket (0700 inside a 0700 dir) and start accepting.
    public func start() throws {
        stateLock.lock()
        defer { stateLock.unlock() }
        guard !running else { throw SocketError.alreadyRunning }
        guard path.hasPrefix("/"), !path.utf8.contains(0), path.utf8.count < 104 else {
            throw SocketError.invalidPath
        }
        let dir = (path as NSString).deletingLastPathComponent
        var priorDir = stat()
        let directoryExisted: Bool
        if lstat(dir, &priorDir) == 0 {
            directoryExisted = true
        } else if errno == ENOENT {
            directoryExisted = false
            try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o700])
        } else {
            throw SocketError.permissions(errno)
        }
        // Do not change permissions on an arbitrary existing parent directory.
        // merely because it was supplied as a socket path. Existing parents
        // must already be a private directory owned by this user. A new leaf is
        // pinned with O_NOFOLLOW and tightened through its descriptor.
        let dirFD = open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard dirFD >= 0 else { throw SocketError.permissions(errno) }
        defer { close(dirFD) }
        var dirInfo = stat()
        guard fstat(dirFD, &dirInfo) == 0,
              (dirInfo.st_mode & S_IFMT) == S_IFDIR,
              dirInfo.st_uid == geteuid() else {
            throw SocketError.permissions(EACCES)
        }
        if !directoryExisted, fchmod(dirFD, 0o700) != 0 {
            throw SocketError.permissions(errno)
        }
        guard dirInfo.st_mode & 0o777 == 0o700 || !directoryExisted else {
            throw SocketError.permissions(EACCES)
        }

        // A persistent advisory lock distinguishes "stale pathname" from
        // "another Sallyport owns this endpoint" and closes the two-starters
        // race around probe+unlink. Keep the file; only the lock is lifecycle
        // state, so a new owner can never have its lock pathname unlinked.
        let owner = open(path + ".lock", O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0o600)
        guard owner >= 0 else { throw SocketError.ownership(errno) }
        guard flock(owner, LOCK_EX | LOCK_NB) == 0 else {
            let code = errno
            close(owner)
            if code == EWOULDBLOCK { throw SocketError.alreadyRunning }
            throw SocketError.ownership(code)
        }
        var retainOwnership = false
        defer {
            if !retainOwnership {
                _ = flock(owner, LOCK_UN)
                close(owner)
            }
        }
        guard fchmod(owner, 0o600) == 0 else { throw SocketError.ownership(errno) }

        // Clear only a demonstrably stale socket. The ownership lock protects
        // modern Sallyport instances; the connect probe protects a live legacy
        // listener that predates the lock file.
        var existing = stat()
        if lstat(path, &existing) == 0 {
            guard (existing.st_mode & S_IFMT) == S_IFSOCK else {
                throw SocketError.bind(EEXIST)
            }
            switch Self.probeSocket(path) {
            case .live: throw SocketError.alreadyRunning
            case .indeterminate(let code): throw SocketError.bind(code)
            case .stale: break
            }
            guard unlink(path) == 0 else { throw SocketError.bind(errno) }
        } else if errno != ENOENT {
            throw SocketError.bind(errno)
        }

        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw SocketError.create(errno) }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        _ = path.withCString { src in
            withUnsafeMutablePointer(to: &addr.sun_path) {
                $0.withMemoryRebound(to: CChar.self, capacity: 104) { dst in strncpy(dst, src, 103) }
            }
        }
        let len = socklen_t(MemoryLayout<sockaddr_un>.size)
        let bound = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, len) }
        }
        guard bound == 0 else { close(fd); throw SocketError.bind(errno) }
        guard chmod(path, 0o700) == 0 else {
            let code = errno
            close(fd); unlink(path)
            throw SocketError.permissions(code)
        }
        guard listen(fd, Int32(Self.maxConnections)) == 0 else {
            let code = errno
            close(fd); unlink(path)
            throw SocketError.listen(code)
        }

        listenFD = fd
        ownershipFD = owner
        if lstat(path, &existing) == 0 {
            socketIdentity = (existing.st_dev, existing.st_ino)
        } else {
            socketIdentity = nil
        }
        running = true
        retainOwnership = true
        queue.async { [weak self] in self?.acceptLoop() }
    }

    public func stop() {
        let state = stateLock.withLock { () -> (Int32, Int32, (dev_t, ino_t)?) in
            running = false
            let fd = listenFD
            let owner = ownershipFD
            let identity = socketIdentity
            listenFD = -1
            ownershipFD = -1
            socketIdentity = nil
            // Unblock every worker parked in read(). Workers own close(); using
            // shutdown here avoids a close/reuse race on the descriptor number.
            for conn in activeConnections { _ = shutdown(conn, SHUT_RDWR) }
            return (fd, owner, identity)
        }
        if state.0 >= 0 { close(state.0) }
        var existing = stat()
        if let identity = state.2,
           lstat(path, &existing) == 0,
           (existing.st_mode & S_IFMT) == S_IFSOCK,
           existing.st_dev == identity.0, existing.st_ino == identity.1 {
            unlink(path)
        }
        if state.1 >= 0 {
            _ = flock(state.1, LOCK_UN)
            close(state.1)
        }
    }

    private func acceptLoop() {
        while true {
            let fd = stateLock.withLock { running ? listenFD : -1 }
            guard fd >= 0 else { return }
            let conn = accept(fd, nil, nil)
            if conn < 0 {
                let code = errno
                switch Self.acceptFailureAction(code, running: stateLock.withLock({ running })) {
                case .retry:
                    continue
                case .backoff:
                    // Persistent resource pressure or a platform-specific
                    // transient must not become a hot spin.
                    usleep(100_000)
                    continue
                case .stop:
                    return
                }
            }
            // A dead peer must fail the write with EPIPE, not SIGPIPE-kill the app
            // (the exact scenario: agent exits while its call awaits approval).
            var one: Int32 = 1
            guard setsockopt(conn, SOL_SOCKET, SO_NOSIGPIPE, &one,
                             socklen_t(MemoryLayout<Int32>.size)) == 0 else {
                close(conn)
                continue
            }
            var timeout = timeval(tv_sec: Self.idleReadTimeoutSeconds, tv_usec: 0)
            _ = setsockopt(conn, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                           socklen_t(MemoryLayout<timeval>.size))

            let admitted = stateLock.withLock { () -> Bool in
                guard running, activeConnections.count < Self.maxConnections else { return false }
                activeConnections.insert(conn)
                return true
            }
            guard admitted else {
                rejectBusy(conn)
                close(conn)
                continue
            }

            let peer = Provenance.peerPID(fromFD: conn)
            Thread.detachNewThread { [weak self] in
                guard let self else { close(conn); return }
                defer {
                    _ = self.stateLock.withLock { self.activeConnections.remove(conn) }
                    close(conn)
                }
                self.serve(conn: conn, peerPID: peer)
            }
        }
    }

    private func serve(conn: Int32, peerPID: Int) {
        var framer = LineFramer()
        var buf = [UInt8](repeating: 0, count: 64 * 1024)
        var partialFrameStartedAt: UInt64?
        while stateLock.withLock({ running }) {
            let n = read(conn, &buf, buf.count)
            if n < 0, errno == EINTR { continue }
            if n <= 0 { return }
            let lines: [Data]
            do { lines = try framer.push(Data(buf[0..<n])) } catch { return }
            let now = DispatchTime.now().uptimeNanoseconds
            if framer.pendingByteCount > 0 {
                if partialFrameStartedAt == nil { partialFrameStartedAt = now }
                if let started = partialFrameStartedAt,
                   now >= started,
                   now - started >= Self.partialFrameTimeoutNanoseconds { return }
            } else {
                partialFrameStartedAt = nil
            }
            for line in lines where !line.isEmpty {
                if let reply = handle(line, peerPID: peerPID, conn: conn) {
                    var out = reply
                    out.append(0x0A)
                    // A stream write may be partial, so continue until the frame is sent.
                    var sent = 0
                    let complete = out.withUnsafeBytes { raw -> Bool in
                        guard let base = raw.baseAddress else { return raw.isEmpty }
                        while sent < raw.count {
                            let n = write(conn, base.advanced(by: sent), raw.count - sent)
                            if n < 0, errno == EINTR { continue }
                            guard n > 0 else { return false }
                            sent += n
                        }
                        return true
                    }
                    if !complete { return }
                }
            }
        }
    }

    /// Reject over-cap clients without allocating another thread. The peer gets
    /// a valid protocol frame instead of an ambiguous EOF.
    private func rejectBusy(_ conn: Int32) {
        var reply = Data(#"{"type":"error","code":"SALLYPORT_BUSY","error":"server busy: too many active connections"}"#.utf8)
        reply.append(0x0A)
        reply.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return }
            var sent = 0
            while sent < raw.count {
                let n = write(conn, base.advanced(by: sent), raw.count - sent)
                if n < 0, errno == EINTR { continue }
                guard n > 0 else { return }
                sent += n
            }
        }
    }

    private enum SocketProbe {
        case live
        case stale
        case indeterminate(Int32)
    }

    private static func probeSocket(_ path: String) -> SocketProbe {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return .indeterminate(errno) }
        defer { close(fd) }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        path.withCString { src in
            withUnsafeMutablePointer(to: &addr.sun_path) {
                $0.withMemoryRebound(to: CChar.self, capacity: 104) { _ = strlcpy($0, src, 104) }
            }
        }
        let result = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        if result == 0 { return .live }
        switch errno {
        case ECONNREFUSED, ENOENT: return .stale
        default: return .indeterminate(errno)
        }
    }

    /// Dispatches one frame and replies unless the peer disconnects.
    private func handle(_ line: Data, peerPID: Int, conn: Int32) -> Data? {
        guard let obj = try? JSONSerialization.jsonObject(with: line) as? [String: Any],
              let type = obj["type"] as? String else {
            return encode(["type": "error", "error": "bad frame: expected one JSON object per line"])
        }
        let id = obj["id"] as? String ?? ""
        switch type {
        case "list_tools":
            let sem = DispatchSemaphore(value: 0)
            let box = CatalogBox()
            let task = Task { [tools] in
                box.store(await tools())
                sem.signal()
            }
            switch waitForAsyncResult(sem, conn: conn, timeout: catalogTimeout) {
            case .disconnected:
                task.cancel()
                return nil
            case .timedOut:
                task.cancel()
                return encode(["type": "error", "id": id, "code": "SALLYPORT_TIMEOUT",
                               "error": "tool catalog exceeded Sallyport's server deadline"])
            case .completed:
                break
            }
            guard let catalog = box.load(),
                  let encodedTools = try? JSONValue.array(catalog).boundedFoundation(),
                  let toolArray = encodedTools as? [Any] else {
                return encode(["type": "error", "id": id,
                               "error": "tool catalog exceeds JSON resource limits"])
            }
            return encode(["type": "list_tools_result", "id": id,
                           "tools": toolArray])
                ?? encode(["type": "error", "id": id, "error": "tool catalog unencodable"])
        case "invoke":
            let identity = obj["identity"] as? String ?? "agent://local"
            guard let actionObj = obj["action"] as? [String: Any],
                  let tool = actionObj["tool"] as? String else {
                return invokeReply(id: id, result: .denied("SALLYPORT_BAD_REQUEST",
                                                           "invoke needs action.tool"))
            }
            let args: [String: JSONValue]
            do {
                args = try (actionObj["args"] as? [String: Any])
                    .map(JSONValue.boundedObject(fromFoundation:)) ?? [:]
            } catch {
                return invokeReply(id: id, result: .denied(
                    "SALLYPORT_BAD_REQUEST", "action.args exceeds JSON resource limits"))
            }
            let action = Action(tool: tool, args: args)
            let prov = Provenance.chain(pid: peerPID)

            let sem = DispatchSemaphore(value: 0)
            let box = ResultBox()
            let task = Task { [invokeAction] in
                box.result = await invokeAction(identity, action, prov)
                sem.signal()
            }
            switch waitForAsyncResult(sem, conn: conn, timeout: invokeTimeout) {
            case .disconnected:
                task.cancel()
                return nil
            case .timedOut:
                task.cancel()
                let timeout = InvokeResult.denied(
                    "SALLYPORT_TIMEOUT",
                    "the invocation exceeded Sallyport's hard server deadline",
                    rule: "server.timeout")
                return invokeReply(id: id, result: timeout)
            case .completed:
                break
            }
            let r = box.result ?? InvokeResult.denied("SALLYPORT_UNAVAILABLE", "engine error")
            return invokeReply(id: id, result: r)
        default:
            return encode(["type": "error", "id": id, "error": "unknown frame type: \(type)"])
        }
    }

    /// JSONSerialization wrapper that never throws out of the reply path.
    private func encode(_ obj: [String: Any]) -> Data? {
        try? JSONSerialization.data(withJSONObject: obj)
    }

    private func invokeReply(id: String, result: InvokeResult) -> Data? {
        if let bounded = try? result.boundedFoundation(),
           let encoded = encode(["type": "invoke_result", "id": id, "result": bounded]) {
            return encoded
        }
        let fallback: [String: Any] = [
            "ok": false,
            "error_code": "SALLYPORT_UNAVAILABLE",
            "reason": "result exceeds JSON resource limits",
        ]
        return encode(["type": "invoke_result", "id": id, "result": fallback])
    }

    private final class ResultBox: @unchecked Sendable { var result: InvokeResult? }

    private final class CatalogBox: @unchecked Sendable {
        private let lock = NSLock()
        private var catalog: [JSONValue]?
        func store(_ value: [JSONValue]) { lock.withLock { catalog = value } }
        func load() -> [JSONValue]? { lock.withLock { catalog } }
    }

    private enum AsyncWait { case completed, timedOut, disconnected }

    /// Releases the connection slot if the caller disconnects while work is pending.
    private func waitForAsyncResult(_ semaphore: DispatchSemaphore, conn: Int32,
                                    timeout: TimeInterval) -> AsyncWait {
        let now = DispatchTime.now().uptimeNanoseconds
        let nanos = UInt64((timeout * 1_000_000_000).rounded(.up))
        let deadline = nanos <= UInt64.max - now ? now + nanos : UInt64.max
        let pollSlice: UInt64 = 100_000_000
        while true {
            let current = DispatchTime.now().uptimeNanoseconds
            if current >= deadline { return .timedOut }
            let next = min(deadline, current <= UInt64.max - pollSlice
                           ? current + pollSlice : UInt64.max)
            if semaphore.wait(timeout: DispatchTime(uptimeNanoseconds: next)) == .success {
                return .completed
            }
            if Self.peerDisconnected(conn) { return .disconnected }
        }
    }

    private static func peerDisconnected(_ fd: Int32) -> Bool {
        var byte: UInt8 = 0
        let count = recv(fd, &byte, 1, MSG_PEEK | MSG_DONTWAIT)
        if count == 0 { return true }
        if count > 0 { return false }
        return errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR
    }

    enum AcceptFailureAction: Equatable { case retry, backoff, stop }

    /// `accept(2)` may report transient queue/resource failures even while the
    /// listener is healthy. Only descriptor/configuration failures are terminal;
    /// unknown errors back off so a new OS errno cannot silently kill service.
    static func acceptFailureAction(_ code: Int32, running: Bool) -> AcceptFailureAction {
        guard running else { return .stop }
        switch code {
        case EINTR, ECONNABORTED, EAGAIN:
            return .retry
        case EBADF, EINVAL, ENOTSOCK, EFAULT:
            return .stop
        default:
            return .backoff
        }
    }

    public enum SocketError: Error, Sendable {
        case invalidPath
        case alreadyRunning
        case ownership(Int32)
        case create(Int32)
        case bind(Int32)
        case listen(Int32)
        case permissions(Int32)
    }
}
