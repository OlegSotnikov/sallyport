import Darwin
import Foundation
import SallyportKit
import Security

protocol SocketRequesting: AnyObject {
    func request(_ object: [String: Any]) -> [String: Any]?
}

/// Synchronous, one-request client for the app's line-delimited control socket.
/// Every externally controlled allocation and blocking operation is bounded.
final class SocketClient: SocketRequesting {
    static let defaultMaxFrameBytes = 8 * 1024 * 1024
    /// Approval may take two minutes and credential provisioning may take
    /// fifteen. Keep the client slightly beyond the server's 16-minute hard cap
    /// so the server, not a premature socket timeout, returns the final verdict.
    static let defaultTimeout: TimeInterval = 16 * 60 + 10

    private let fd: Int32
    private let maxFrameBytes: Int

    convenience init?() {
        self.init(path: Self.defaultPath)
    }

    init?(
        path: String,
        timeout: TimeInterval = SocketClient.defaultTimeout,
        maxFrameBytes: Int = SocketClient.defaultMaxFrameBytes,
        peerAuthenticator: (Int32) -> Bool = ServerPeerAuthenticator.isTrusted(fd:)
    ) {
        guard Self.isValidSocketPath(path), maxFrameBytes > 0 else { return nil }
        let socketFD = socket(AF_UNIX, SOCK_STREAM, 0)
        guard socketFD >= 0 else { return nil }
        guard Self.configure(socketFD, timeout: timeout) else {
            close(socketFD)
            return nil
        }

        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let capacity = MemoryLayout.size(ofValue: address.sun_path)
        path.withCString { source in
            withUnsafeMutablePointer(to: &address.sun_path) {
                $0.withMemoryRebound(to: CChar.self, capacity: capacity) {
                    _ = strncpy($0, source, capacity - 1)
                }
            }
        }
        let connected = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(socketFD, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard connected == 0 else {
            close(socketFD)
            return nil
        }
        guard peerAuthenticator(socketFD) else {
            close(socketFD)
            return nil
        }
        fd = socketFD
        self.maxFrameBytes = maxFrameBytes
    }

    /// Test seam for exercising framing and timeout behavior over `socketpair`.
    init?(
        connectedFileDescriptor: Int32,
        timeout: TimeInterval = SocketClient.defaultTimeout,
        maxFrameBytes: Int = SocketClient.defaultMaxFrameBytes,
        peerAuthenticator: (Int32) -> Bool = { _ in true }
    ) {
        guard connectedFileDescriptor >= 0, maxFrameBytes > 0,
              Self.configure(connectedFileDescriptor, timeout: timeout) else { return nil }
        guard peerAuthenticator(connectedFileDescriptor) else {
            close(connectedFileDescriptor)
            return nil
        }
        fd = connectedFileDescriptor
        self.maxFrameBytes = maxFrameBytes
    }

    static var defaultPath: String {
        if let path = ProcessInfo.processInfo.environment["SALLYPORT_SOCKET"], !path.isEmpty {
            return path
        }
        let home = ProcessInfo.processInfo.environment["SALLYPORT_HOME"]
            ?? (NSHomeDirectory() + "/.sallyport")
        return home + "/sallyport.sock"
    }

    static func isValidSocketPath(_ path: String) -> Bool {
        // sockaddr_un.sun_path is 104 bytes on macOS, including the NUL terminator.
        path.first == "/" && !path.utf8.contains(0) && path.utf8.count < 104
    }

    /// Send one JSON object plus newline and read exactly one bounded JSON reply.
    func request(_ object: [String: Any]) -> [String: Any]? {
        guard var request = try? JSONSerialization.data(withJSONObject: object),
              request.count <= maxFrameBytes else { return nil }
        request.append(0x0A)
        guard Self.writeAll(fd, request) else { return nil }

        var framer = LineFramer(maxLineBytes: maxFrameBytes)
        var bytes = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let count = bytes.withUnsafeMutableBytes {
                Darwin.read(fd, $0.baseAddress, $0.count)
            }
            if count < 0, errno == EINTR { continue }
            guard count > 0 else { return nil }
            do {
                let frames = try framer.push(Data(bytes.prefix(count)))
                guard let frame = frames.first else { continue }
                guard let value = try? JSONSerialization.jsonObject(with: frame) else { return nil }
                return value as? [String: Any]
            } catch {
                return nil
            }
        }
    }

    deinit { close(fd) }

    private static func configure(_ fd: Int32, timeout: TimeInterval) -> Bool {
        guard timeout.isFinite, timeout > 0 else { return false }
        // The authenticated connection must not be inheritable by any child
        // process — an inherited descriptor writes frames attributed to the
        // shim's parent chain.
        let flags = fcntl(fd, F_GETFD)
        guard flags >= 0, fcntl(fd, F_SETFD, flags | FD_CLOEXEC) != -1 else { return false }
        var noSigPipe: Int32 = 1
        guard setsockopt(
            fd, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe,
            socklen_t(MemoryLayout<Int32>.size)
        ) == 0 else { return false }

        // Bound conversion to `timeval` and one-shot socket use.
        let boundedTimeout = min(timeout, 3_600)
        let wholeSeconds = floor(boundedTimeout)
        var value = timeval(
            tv_sec: Int(wholeSeconds),
            tv_usec: Int32(min(999_999, max(0, (boundedTimeout - wholeSeconds) * 1_000_000)))
        )
        let size = socklen_t(MemoryLayout<timeval>.size)
        return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &value, size) == 0
            && setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &value, size) == 0
    }

    private static func writeAll(_ fd: Int32, _ data: Data) -> Bool {
        data.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return false }
            var sent = 0
            while sent < raw.count {
                let count = Darwin.write(fd, base.advanced(by: sent), raw.count - sent)
                if count < 0, errno == EINTR { continue }
                guard count > 0 else { return false }
                sent += count
            }
            return true
        }
    }
}

/// Authenticates the process on the other end of the Unix socket. Directory
/// permissions do not authenticate against another process running as the same
/// user; without this check such a process could bind the well-known path while
/// Sallyport is down and forge tool results to the agent.
enum ServerPeerAuthenticator {
    private static let solLocal: Int32 = 0
    private static let localPeerPID: Int32 = 0x002
    private static let localPeerToken: Int32 = 0x006
    private static let expectedBundleID = "dev.sallyport.mac"

    static func peerPID(fd: Int32) -> pid_t? {
        guard fd >= 0 else { return nil }
        var pid: pid_t = 0
        var length = socklen_t(MemoryLayout<pid_t>.size)
        guard getsockopt(fd, solLocal, localPeerPID, &pid, &length) == 0,
              length == socklen_t(MemoryLayout<pid_t>.size), pid > 0 else { return nil }
        return pid
    }

    /// The peer's connect-time audit token, immune to PID reuse in the
    /// window between connect and code-signing verification.
    static func peerAuditToken(fd: Int32) -> Data? {
        guard fd >= 0 else { return nil }
        var token = audit_token_t()
        var length = socklen_t(MemoryLayout<audit_token_t>.size)
        guard getsockopt(fd, solLocal, localPeerToken, &token, &length) == 0,
              length == socklen_t(MemoryLayout<audit_token_t>.size) else { return nil }
        return withUnsafeBytes(of: token) { Data($0) }
    }

    static func isTrusted(fd: Int32) -> Bool {
        guard let peer = liveCode(fd: fd),
              let ownTeam = ownTeamIdentifier(),
              satisfiesAppleAnchor(peer),
              let info = signingInfo(peer),
              info[kSecCodeInfoTeamIdentifier as String] as? String == ownTeam,
              info[kSecCodeInfoIdentifier as String] as? String == expectedBundleID else {
            return false
        }
        return true
    }

    private static func ownTeamIdentifier() -> String? {
        var ownCode: SecCode?
        guard SecCodeCopySelf([], &ownCode) == errSecSuccess, let ownCode,
              let info = signingInfo(ownCode),
              let team = info[kSecCodeInfoTeamIdentifier as String] as? String,
              !team.isEmpty else { return nil }
        return team
    }

    private static func liveCode(fd: Int32) -> SecCode? {
        // Prefer the audit token: it names one process instance, while a PID
        // is a reusable number. Fall back to the PID only when the platform
        // call is unavailable.
        let attributes: CFDictionary
        if let token = peerAuditToken(fd: fd) {
            attributes = [kSecGuestAttributeAudit as String: token] as CFDictionary
        } else if let pid = peerPID(fd: fd) {
            attributes = [kSecGuestAttributePid as String: NSNumber(value: pid)] as CFDictionary
        } else {
            return nil
        }
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess else {
            return nil
        }
        return code
    }

    private static func satisfiesAppleAnchor(_ code: SecCode) -> Bool {
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(
            "anchor apple generic" as CFString, [], &requirement
        ) == errSecSuccess, let requirement else { return false }
        return SecCodeCheckValidity(
            code, SecCSFlags(rawValue: kSecCSStrictValidate), requirement
        ) == errSecSuccess
    }

    private static func signingInfo(_ code: SecCode) -> [String: Any]? {
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else {
            return nil
        }
        var information: CFDictionary?
        guard SecCodeCopySigningInformation(
            staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information
        ) == errSecSuccess else { return nil }
        return information as? [String: Any]
    }
}

// MARK: - MCP stdio shim

public final class MCPShim {
    private let identity = "agent://mac.mcp"
    private let maxFrameBytes: Int
    private let clientFactory: () -> (any SocketRequesting)?

    public convenience init() {
        self.init(maxFrameBytes: SocketClient.defaultMaxFrameBytes) { SocketClient() }
    }

    init(
        maxFrameBytes: Int,
        clientFactory: @escaping () -> (any SocketRequesting)?
    ) {
        self.maxFrameBytes = max(1, maxFrameBytes)
        self.clientFactory = clientFactory
    }

    public func run() {
        run(input: .standardInput, output: .standardOutput)
    }

    func run(input: FileHandle, output: FileHandle) {
        var framer = LineFramer(maxLineBytes: maxFrameBytes)
        do {
            while true {
                // availableData blocks until at least one byte arrives (or EOF).
                // read(upToCount:) blocks until the FULL count or EOF, so a live
                // MCP host — which writes one small request and then waits for
                // the reply on an open pipe — would deadlock against a 64 KiB
                // read and time out without ever seeing the initialize response.
                let chunk = input.availableData
                if chunk.isEmpty { break }   // EOF
                for line in try framer.push(chunk) {
                    handle(line, output: output)
                }
            }
        } catch {
            reply(output, id: nil, error: ["code": -32700, "message": "invalid or oversized JSON-RPC frame"])
        }
    }

    private func handle(_ line: Data, output: FileHandle) {
        guard let value = try? JSONSerialization.jsonObject(with: line),
              let message = value as? [String: Any],
              let method = message["method"] as? String else {
            reply(output, id: nil, error: ["code": -32700, "message": "invalid JSON-RPC request"])
            return
        }
        let id = message["id"]
        switch method {
        case "initialize":
            reply(output, id: id, result: [
                "protocolVersion": "2024-11-05",
                "capabilities": ["tools": [:]],
                "serverInfo": ["name": "sallyport", "version": "1.0"],
            ])
        case "notifications/initialized":
            break
        case "tools/list":
            let tools = (clientFactory()?.request(["type": "list_tools", "id": "l"])?["tools"] as? [Any]) ?? []
            reply(output, id: id, result: ["tools": tools])
        case "tools/call":
            reply(output, id: id, result: callTool(message["params"] as? [String: Any] ?? [:]))
        default:
            if id != nil {
                reply(output, id: id, error: ["code": -32601, "message": "method not found: \(method)"])
            }
        }
    }

    private func callTool(_ parameters: [String: Any]) -> [String: Any] {
        let name = parameters["name"] as? String ?? ""
        let arguments = parameters["arguments"] as? [String: Any] ?? [:]
        guard let client = clientFactory() else {
            return errorContent("Sallyport isn't running (no control socket). Open the Sallyport app.")
        }
        let response = client.request([
            "type": "invoke", "id": "c",
            "identity": identity,
            "action": ["tool": name, "args": arguments],
        ])
        guard let result = response?["result"] as? [String: Any] else {
            return errorContent("no response from Sallyport")
        }
        let text = (try? JSONSerialization.data(withJSONObject: result, options: [.sortedKeys]))
            .map { String(decoding: $0, as: UTF8.self) } ?? "{}"
        return [
            "content": [["type": "text", "text": text]],
            "isError": (result["ok"] as? Bool) == false,
        ]
    }

    private func errorContent(_ message: String) -> [String: Any] {
        ["content": [["type": "text", "text": message]], "isError": true]
    }

    private func reply(_ output: FileHandle, id: Any?, result: [String: Any]) {
        emit(output, ["jsonrpc": "2.0", "id": id ?? NSNull(), "result": result])
    }

    private func reply(_ output: FileHandle, id: Any?, error: [String: Any]) {
        emit(output, ["jsonrpc": "2.0", "id": id ?? NSNull(), "error": error])
    }

    private func emit(_ output: FileHandle, _ object: [String: Any]) {
        guard var data = try? JSONSerialization.data(withJSONObject: object) else { return }
        data.append(0x0A)
        try? output.write(contentsOf: data)
    }
}
