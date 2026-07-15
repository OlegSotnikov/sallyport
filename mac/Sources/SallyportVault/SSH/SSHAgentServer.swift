import Foundation

/// Single-key SSH agent for an `sp-ssh` child over a private inherited socket.
/// It supports listing identities and signing. The key set is fixed for one exec.
public final class SSHAgentServer: @unchecked Sendable {

    // PROTOCOL.agent message numbers.
    private enum Msg {
        static let failure: UInt8 = 5
        static let requestIdentities: UInt8 = 11
        static let identitiesAnswer: UInt8 = 12
        static let signRequest: UInt8 = 13
        static let signResponse: UInt8 = 14
    }

    private let key: SSHPrivateKey
    private let comment: String
    /// Maximum signatures served during one execution.
    private let maxSignatures: Int
    private let lock = NSLock()
    private var signCount = 0
    private var revoked = false

    public init(key: SSHPrivateKey, comment: String = "sallyport", maxSignatures: Int = 32) {
        self.key = key
        self.comment = comment
        self.maxSignatures = maxSignatures
    }

    /// Refuses further signatures after teardown begins.
    public func revoke() { lock.withLock { revoked = true } }

    /// Processes one request payload without the outer length field.
    public func handle(_ message: Data) -> Data {
        guard let type = message.first else { return Self.failure }
        var r = SSHWire.Reader(message.dropFirst())
        switch type {
        case Msg.requestIdentities:
            var w = SSHWire.Writer()
            w.byte(Msg.identitiesAnswer)
            w.uint32(1)                       // exactly one identity
            w.string(key.publicKeyBlob)
            w.string(comment)
            return w.data

        case Msg.signRequest:
            guard let blob = try? r.string(),
                  let data = try? r.string(),
                  let flags = try? r.uint32(),
                  blob == key.publicKeyBlob else { return Self.failure }
            // Reject signing after revocation or budget exhaustion.
            let allowed = lock.withLock { () -> Bool in
                if revoked || signCount >= maxSignatures { return false }
                signCount += 1
                return true
            }
            guard allowed else { return Self.failure }
            guard let sig = try? key.sign(data, flags: .init(rawValue: flags)) else { return Self.failure }
            var w = SSHWire.Writer()
            w.byte(Msg.signResponse)
            w.string(sig)
            return w.data

        default:
            return Self.failure
        }
    }

    private static var failure: Data { Data([Msg.failure]) }

    /// Blocking serve loop over a connected socket fd (a socketpair end inherited
    /// by the child). Reads length-prefixed requests, writes length-prefixed
    /// responses, returns on EOF or error. Runs on a background queue.
    public func serve(fd: Int32) {
        // revoke()/child teardown can close the peer between read and reply.
        // That is an ordinary end-of-session condition, never a process signal.
        var one: Int32 = 1
        _ = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one,
                       socklen_t(MemoryLayout<Int32>.size))
        while true {
            guard let lenBytes = Self.readN(fd, 4), lenBytes.count == 4 else { break }
            let len = (UInt32(lenBytes[0]) << 24) | (UInt32(lenBytes[1]) << 16)
                    | (UInt32(lenBytes[2]) << 8) | UInt32(lenBytes[3])
            // Reject agent requests larger than 256 KiB.
            guard len > 0, len <= 256 * 1024, let body = Self.readN(fd, Int(len)), body.count == Int(len) else { break }
            let resp = handle(Data(body))
            let n = UInt32(resp.count)
            var out = Data([UInt8((n >> 24) & 0xff), UInt8((n >> 16) & 0xff),
                            UInt8((n >> 8) & 0xff), UInt8(n & 0xff)])
            out.append(resp)
            guard Self.writeAll(fd, out) else { break }
        }
    }

    /// Read exactly `n` bytes (looping over short reads); nil on EOF/error.
    private static func readN(_ fd: Int32, _ n: Int) -> [UInt8]? {
        var buf = [UInt8](repeating: 0, count: n)
        var got = 0
        while got < n {
            let r = buf.withUnsafeMutableBytes { p in
                guard let base = p.baseAddress else { return -1 }
                return read(fd, base.advanced(by: got), n - got)
            }
            if r == 0 { return nil }                              // EOF
            if r < 0 { if errno == EINTR { continue }; return nil }
            got += r
        }
        return buf
    }

    private static func writeAll(_ fd: Int32, _ data: Data) -> Bool {
        data.withUnsafeBytes { raw -> Bool in
            guard !raw.isEmpty else { return true }
            guard let base = raw.baseAddress else { return false }
            var off = 0
            while off < raw.count {
                let w = write(fd, base.advanced(by: off), raw.count - off)
                if w < 0 { if errno == EINTR { continue }; return false }
                off += w
            }
            return true
        }
    }
}
