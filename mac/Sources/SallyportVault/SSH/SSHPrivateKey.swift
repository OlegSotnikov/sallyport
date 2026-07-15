import Foundation
import CryptoKit
import Security

/// An `openssh-key-v1` private key that emits its public-key blob and signs SSH
/// challenges. The helper receives signatures, not private-key material.
///
/// Supports Ed25519, ECDSA P-256/P-384/P-521, RSA SHA-256/SHA-512, and requested
/// legacy RSA SHA-1 signatures.
public struct SSHPrivateKey {

    /// Maximum imported private-key size.
    static let maxInputBytes = 1 * 1024 * 1024

    /// SSH agent signature-request flags.
    public struct SignFlags: OptionSet, Sendable {
        public let rawValue: UInt32
        public init(rawValue: UInt32) { self.rawValue = rawValue }
        public static let rsaSha256 = SignFlags(rawValue: 0x02)
        public static let rsaSha512 = SignFlags(rawValue: 0x04)
    }

    enum ECDSACurve: String {
        case p256 = "nistp256", p384 = "nistp384", p521 = "nistp521"
        var keyName: String { "ecdsa-sha2-\(rawValue)" }
        var scalarBytes: Int { self == .p256 ? 32 : (self == .p384 ? 48 : 66) }
    }

    private enum Material {
        case ed25519(seed: Data, pub: Data)
        case ecdsa(curve: ECDSACurve, d: Data, q: Data)
        case rsa(key: SecKey, n: Data, e: Data)
    }

    private let material: Material

    /// The SSH public-key blob (the bytes in an `authorized_keys` line / the agent
    /// identities answer). Uniquely identifies this key on the wire.
    public let publicKeyBlob: Data

    /// The default key-type / signature name (`ssh-ed25519`, `ecdsa-sha2-nistp256`,
    /// `ssh-rsa`). RSA upgrades to rsa-sha2-256/512 per the request flags.
    public let keyType: String

    // MARK: - Parse

    /// Parse an unencrypted `openssh-key-v1` private key (PEM or raw base64 body).
    public init(opensshPEM pem: Data) throws {
        guard pem.count <= Self.maxInputBytes else {
            throw SSHError.malformed("private key exceeds \(Self.maxInputBytes)-byte limit")
        }
        let base64 = Self.stripPEM(pem)
        guard let raw = Data(base64Encoded: base64) else { throw SSHError.malformed("bad base64") }
        try self.init(opensshRaw: raw)
    }

    init(opensshRaw raw: Data) throws {
        guard raw.count <= Self.maxInputBytes else {
            throw SSHError.malformed("private key exceeds \(Self.maxInputBytes)-byte limit")
        }
        let magic = Data("openssh-key-v1\u{0}".utf8)
        guard raw.starts(with: magic) else { throw SSHError.badMagic }
        var r = SSHWire.Reader(raw.dropFirst(magic.count))
        let cipher = try r.stringUTF8()
        let kdf = try r.stringUTF8()
        let kdfOptions = try r.string()
        guard cipher == "none", kdf == "none" else { throw SSHError.encryptedKey }
        guard kdfOptions.isEmpty else { throw SSHError.malformed("unexpected KDF options") }
        let count = try r.uint32()
        guard count == 1 else { throw SSHError.malformed("expected exactly one key") }
        let declaredPublicKey = try r.string()
        var priv = SSHWire.Reader(try r.string())
        guard r.isAtEnd else { throw SSHError.malformed("trailing outer data") }
        let check1 = try priv.uint32(), check2 = try priv.uint32()
        guard check1 == check2 else { throw SSHError.malformed("private-key checkint mismatch") }

        let type = try priv.stringUTF8()
        switch type {
        case "ssh-ed25519":
            let pub = try priv.string()          // 32
            let sk = try priv.string()           // 64 = seed || pub
            guard pub.count == 32, sk.count == 64 else { throw SSHError.malformed("ed25519 sizes") }
            let seed = sk.prefix(32)
            guard Data(sk.suffix(32)) == pub else {
                throw SSHError.malformed("ed25519 public/private mismatch")
            }
            let derivedPublic = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
                .publicKey.rawRepresentation
            guard derivedPublic == pub else {
                throw SSHError.malformed("ed25519 public/private mismatch")
            }
            material = .ed25519(seed: Data(seed), pub: pub)
            keyType = "ssh-ed25519"
            var w = SSHWire.Writer(); w.string("ssh-ed25519"); w.string(pub)
            publicKeyBlob = w.data

        case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
            let curveName = try priv.stringUTF8()
            guard let curve = ECDSACurve(rawValue: curveName) else { throw SSHError.unsupportedKeyType(type) }
            guard type == curve.keyName else { throw SSHError.malformed("ECDSA type/curve mismatch") }
            let q = try priv.string()            // uncompressed point 0x04||X||Y
            let d = try priv.mpint()             // private scalar
            guard !d.isEmpty, d.count <= curve.scalarBytes else {
                throw SSHError.malformed("invalid ECDSA private scalar")
            }
            guard try Self.ecdsaPublic(curve: curve, d: d) == q else {
                throw SSHError.malformed("ECDSA public/private mismatch")
            }
            material = .ecdsa(curve: curve, d: d, q: q)
            keyType = curve.keyName
            var w = SSHWire.Writer(); w.string(curve.keyName); w.string(curve.rawValue); w.string(q)
            publicKeyBlob = w.data

        case "ssh-rsa":
            let n = try priv.mpint(), e = try priv.mpint(), d = try priv.mpint()
            let iqmp = try priv.mpint(), p = try priv.mpint(), q = try priv.mpint()
            let key = try Self.importRSA(n: n, e: e, d: d, p: p, q: q, iqmp: iqmp)
            material = .rsa(key: key, n: n, e: e)
            keyType = "ssh-rsa"
            var w = SSHWire.Writer(); w.string("ssh-rsa"); w.mpint(e); w.mpint(n)
            publicKeyBlob = w.data

        default:
            throw SSHError.unsupportedKeyType(type)
        }

        guard declaredPublicKey == publicKeyBlob else {
            throw SSHError.malformed("declared public key mismatch")
        }
        _ = try priv.string()                     // opaque comment
        let padding = priv.remaining
        // cipher "none" has an 8-byte block size. OpenSSH emits zero through
        // seven bytes (an already-aligned payload has no padding).
        guard padding.count <= 7,
              padding.enumerated().allSatisfy({ $0.element == UInt8($0.offset + 1) }) else {
            throw SSHError.malformed("invalid private-key padding")
        }
    }

    // MARK: - Sign

    /// Sign `data` (the SSH auth challenge the server chose) and return the SSH
    /// signature blob: `string algo || string signature`, algorithm-encoded.
    public func sign(_ data: Data, flags: SignFlags = []) throws -> Data {
        switch material {
        case .ed25519(let seed, _):
            let sk = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
            let sig = try sk.signature(for: data)          // Ed25519 hashes internally
            var w = SSHWire.Writer(); w.string("ssh-ed25519"); w.string(sig)
            return w.data

        case .ecdsa(let curve, let d, _):
            let (r, s) = try Self.ecdsaSign(curve: curve, d: d, data: data)
            var inner = SSHWire.Writer(); inner.mpint(r); inner.mpint(s)
            var w = SSHWire.Writer(); w.string(curve.keyName); w.string(inner.data)
            return w.data

        case .rsa(let key, _, _):
            let (algo, secAlgo) = Self.rsaAlgorithm(flags: flags)
            var err: Unmanaged<CFError>?
            guard let sig = SecKeyCreateSignature(key, secAlgo, data as CFData, &err) as Data? else {
                throw SSHError.signFailed(err.map { "\($0.takeRetainedValue())" } ?? "SecKeyCreateSignature")
            }
            var w = SSHWire.Writer(); w.string(algo); w.string(sig)
            return w.data
        }
    }

    private static func rsaAlgorithm(flags: SignFlags) -> (name: String, algo: SecKeyAlgorithm) {
        if flags.contains(.rsaSha512) { return ("rsa-sha2-512", .rsaSignatureMessagePKCS1v15SHA512) }
        if flags.contains(.rsaSha256) { return ("rsa-sha2-256", .rsaSignatureMessagePKCS1v15SHA256) }
        return ("ssh-rsa", .rsaSignatureMessagePKCS1v15SHA1)     // legacy default
    }

    private static func ecdsaSign(curve: ECDSACurve, d: Data, data: Data) throws -> (r: Data, s: Data) {
        let scalar = leftPad(d, to: curve.scalarBytes)
        let raw: Data
        switch curve {
        case .p256:
            raw = try P256.Signing.PrivateKey(rawRepresentation: scalar).signature(for: data).rawRepresentation
        case .p384:
            raw = try P384.Signing.PrivateKey(rawRepresentation: scalar).signature(for: data).rawRepresentation
        case .p521:
            raw = try P521.Signing.PrivateKey(rawRepresentation: scalar).signature(for: data).rawRepresentation
        }
        let half = raw.count / 2
        return (Data(raw.prefix(half)), Data(raw.suffix(half)))
    }

    private static func ecdsaPublic(curve: ECDSACurve, d: Data) throws -> Data {
        let scalar = leftPad(d, to: curve.scalarBytes)
        do {
            switch curve {
            case .p256:
                return try P256.Signing.PrivateKey(rawRepresentation: scalar).publicKey.x963Representation
            case .p384:
                return try P384.Signing.PrivateKey(rawRepresentation: scalar).publicKey.x963Representation
            case .p521:
                return try P521.Signing.PrivateKey(rawRepresentation: scalar).publicKey.x963Representation
            }
        } catch {
            throw SSHError.malformed("invalid ECDSA private scalar")
        }
    }

    // MARK: - RSA import (derive CRT exponents, build PKCS#1, hand to Security)

    private static func importRSA(n: Data, e: Data, d: Data, p: Data, q: Data, iqmp: Data) throws -> SecKey {
        // Reject primes below 2 before CRT arithmetic to avoid trapping on
        // malformed RSA keys.
        let pBig = BigUIntLite(bigEndian: p), qBig = BigUIntLite(bigEndian: q)
        let pMinus1 = pBig.minusOneOrZero(), qMinus1 = qBig.minusOneOrZero()
        guard !pMinus1.isZero, !qMinus1.isZero else {
            throw SSHError.malformed("RSA primes out of range")
        }
        let dp = BigUIntLite(bigEndian: d).mod(pMinus1).bigEndianBytes()
        let dq = BigUIntLite(bigEndian: d).mod(qMinus1).bigEndianBytes()
        // PKCS#1 RSAPrivateKey: SEQUENCE { version(0), n, e, d, p, q, dp, dq, iqmp }.
        let der = DER.sequence([
            DER.integer(Data([0x00])), DER.integer(n), DER.integer(e), DER.integer(d),
            DER.integer(p), DER.integer(q), DER.integer(dp), DER.integer(dq), DER.integer(iqmp),
        ])
        let attrs: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
        ]
        var err: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(der as CFData, attrs as CFDictionary, &err) else {
            throw SSHError.malformed("RSA import: \(err.map { "\($0.takeRetainedValue())" } ?? "SecKeyCreateWithData")")
        }
        return key
    }

    // MARK: - Helpers

    private static func leftPad(_ d: Data, to size: Int) -> Data {
        if d.count >= size { return Data(d.suffix(size)) }
        return Data(repeating: 0, count: size - d.count) + d
    }

    private static func stripPEM(_ pem: Data) -> String {
        let text = String(decoding: pem, as: UTF8.self)
        if !text.contains("BEGIN") { return text.filter { !$0.isWhitespace } }
        return text.split(separator: "\n")
            .filter { !$0.hasPrefix("-----") }
            .joined()
    }
}

/// DER encoder for a PKCS#1 RSA private key.
private enum DER {
    static func integer(_ magnitude: Data) -> Data {
        let firstNonzero = magnitude.firstIndex(where: { $0 != 0 })
        var m = firstNonzero.map { Data(magnitude[$0...]) } ?? Data()
        if m.isEmpty { m = Data([0x00]) }
        if m[m.startIndex] & 0x80 != 0 { m = Data([0x00]) + m }   // keep positive
        return tlv(0x02, m)
    }

    static func sequence(_ parts: [Data]) -> Data {
        tlv(0x30, parts.reduce(Data(), +))
    }

    private static func tlv(_ tag: UInt8, _ content: Data) -> Data {
        Data([tag]) + length(content.count) + content
    }

    private static func length(_ n: Int) -> Data {
        if n < 0x80 { return Data([UInt8(n)]) }
        var bytes = [UInt8]()
        var v = n
        while v > 0 { bytes.insert(UInt8(v & 0xff), at: 0); v >>= 8 }
        return Data([0x80 | UInt8(bytes.count)] + bytes)
    }
}
