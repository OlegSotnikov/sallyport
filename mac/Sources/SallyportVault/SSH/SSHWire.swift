import Foundation

/// The SSH binary wire encoding (RFC 4251 §5), used by the private-key format,
/// the public-key blobs, the signature blobs and the ssh-agent protocol. Only
/// the pieces Sallyport needs: uint32, `string` (length-prefixed bytes) and
/// `mpint` (a signed big-endian integer, always non-negative here).
enum SSHWire {

    /// Bounds-checked forward reader for an SSH packet.
    struct Reader {
        private let bytes: [UInt8]
        private var offset = 0
        init(_ data: Data) { bytes = [UInt8](data) }

        var isAtEnd: Bool { offset >= bytes.count }
        var remaining: Data { Data(bytes[offset...]) }

        mutating func byte() throws -> UInt8 {
            guard offset < bytes.count else { throw SSHError.truncated }
            defer { offset += 1 }
            return bytes[offset]
        }

        mutating func uint32() throws -> UInt32 {
            guard offset + 4 <= bytes.count else { throw SSHError.truncated }
            defer { offset += 4 }
            return (UInt32(bytes[offset]) << 24) | (UInt32(bytes[offset + 1]) << 16)
                 | (UInt32(bytes[offset + 2]) << 8) | UInt32(bytes[offset + 3])
        }

        /// A length-prefixed `string` (may hold arbitrary bytes, not just UTF-8).
        mutating func string() throws -> Data {
            let n = Int(try uint32())
            guard n >= 0, offset + n <= bytes.count else { throw SSHError.truncated }
            defer { offset += n }
            return Data(bytes[offset..<offset + n])
        }

        mutating func stringUTF8() throws -> String {
            let bytes = try string()
            guard let value = String(data: bytes, encoding: .utf8) else {
                throw SSHError.malformed("invalid UTF-8 string")
            }
            return value
        }

        /// A big-endian two's-complement `mpint`. Values here are
        /// non-negative, so we drop a single leading 0x00 sign byte and return the
        /// magnitude bytes.
        mutating func mpint() throws -> Data {
            let value = try string()
            guard let firstNonzero = value.firstIndex(where: { $0 != 0 }) else { return Data() }
            return Data(value[firstNonzero...])
        }

        /// Bytes consumed so far.
        var consumed: Int { offset }
    }

    /// Builds an SSH packet. All integers big-endian; `string`/`mpint` are
    /// length-prefixed exactly as the readers expect.
    struct Writer {
        private(set) var data = Data()

        mutating func byte(_ b: UInt8) { data.append(b) }

        mutating func uint32(_ v: UInt32) {
            data.append(UInt8((v >> 24) & 0xff))
            data.append(UInt8((v >> 16) & 0xff))
            data.append(UInt8((v >> 8) & 0xff))
            data.append(UInt8(v & 0xff))
        }

        mutating func string(_ s: Data) {
            uint32(UInt32(s.count))
            data.append(s)
        }

        mutating func string(_ s: String) { string(Data(s.utf8)) }

        /// Encode a non-negative magnitude as an `mpint`: strip leading zeros, then
        /// prepend one 0x00 if the top bit is set (so it stays positive). Zero is
        /// the empty string.
        mutating func mpint(_ magnitude: Data) {
            let firstNonzero = magnitude.firstIndex(where: { $0 != 0 })
            var m = firstNonzero.map { Data(magnitude[$0...]) } ?? Data()
            if m.isEmpty { uint32(0); return }
            if m[m.startIndex] & 0x80 != 0 { m = Data([0x00]) + m }
            string(m)
        }
    }
}

/// Errors from SSH key parsing / signing.
public enum SSHError: Error, CustomStringConvertible, Sendable, Equatable {
    case truncated
    case badMagic
    case encryptedKey            // A KDF other than "none" must be normalized first.
    case unsupportedKeyType(String)
    case malformed(String)
    case signFailed(String)

    public var description: String {
        switch self {
        case .truncated: return "ssh: truncated data"
        case .badMagic: return "ssh: not an openssh-key-v1 private key"
        case .encryptedKey: return "ssh: the private key is still encrypted (normalize it first)"
        case .unsupportedKeyType(let t): return "ssh: unsupported key type '\(t)'"
        case .malformed(let m): return "ssh: malformed key: \(m)"
        case .signFailed(let m): return "ssh: signing failed: \(m)"
        }
    }
}
