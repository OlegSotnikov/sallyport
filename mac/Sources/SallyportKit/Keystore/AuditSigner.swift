import Foundation
import CryptoKit
import Security

/// Signs each audit row's chain head. A hash chain alone can be rewritten by
/// anyone with file access; verification also requires this signing key.
///
/// The verifying key is sealed under the vault DEK instead of trusted from the
/// audit log or anchor.
public protocol AuditSigner: Sendable {
    /// "se" (Secure Enclave) or "software" (tests / unsigned dev builds).
    var backend: String { get }
    /// X9.63 representation of the P-256 verifying key.
    var publicKeyX963: Data { get }
    /// DER-encoded ECDSA P-256 signature over `message`.
    func sign(_ message: Data) throws -> Data
}

public enum AuditSignerError: Error, CustomStringConvertible {
    case unavailable(String)
    public var description: String {
        switch self {
        case .unavailable(let m): return "audit signer: \(m)"
        }
    }
}

/// Verify a signature produced by any `AuditSigner` (P-256 ECDSA, DER).
public enum AuditSignatureVerifier {
    public static func isValid(signatureDER: Data, message: Data, publicKeyX963: Data) -> Bool {
        guard let key = try? P256.Signing.PublicKey(x963Representation: publicKeyX963),
              let sig = try? P256.Signing.ECDSASignature(derRepresentation: signatureDER) else {
            return false
        }
        return key.isValidSignature(sig, for: message)
    }
}

/// A Secure Enclave P-256 signing key without a biometric requirement. It stays
/// available after first unlock so the app can record denials and session ends
/// while the screen is locked.
///
/// The persistent object is a code-bound `SecKey` in the data-protection
/// keychain. No exported `dataRepresentation` or private-key file exists.
public final class SecureEnclaveAuditSigner: AuditSigner, @unchecked Sendable {
    public let backend = "se"
    public let publicKeyX963: Data
    /// Secure Enclave key reference stored in the data-protection keychain.
    private let key: SecKey
    private let lock = NSLock()

    /// Keychain application tag (per-namespace so diagnostics don't collide).
    static let tagPrefix = "dev.sallyport.audit.signer."

    private init(key: SecKey, publicKeyX963: Data) {
        self.key = key
        self.publicKeyX963 = publicKeyX963
    }

    /// Loads or creates the signing key. Returns nil when the Secure Enclave or
    /// required keychain access is unavailable.
    public static func makeAvailable(namespace: String = "") -> SecureEnclaveAuditSigner? {
        guard SecureEnclave.isAvailable else { return nil }
        let tag = Data((tagPrefix + namespace).utf8)

        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecUseDataProtectionKeychain as String: true,
            kSecReturnRef as String: true,
        ]
        var out: CFTypeRef?
        if SecItemCopyMatching(query as CFDictionary, &out) == errSecSuccess, let ref = out {
            guard CFGetTypeID(ref) == SecKeyGetTypeID() else { return nil }
            let key = unsafeDowncast(ref, to: SecKey.self)
            if let pub = publicKeyX963(of: key) {
                return SecureEnclaveAuditSigner(key: key, publicKeyX963: pub)
            }
        }
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            [.privateKeyUsage], nil) else { return nil }
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecUseDataProtectionKeychain as String: true,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrAccessControl as String: access,
            ],
        ]
        var err: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &err),
              let pub = publicKeyX963(of: key) else { return nil }
        return SecureEnclaveAuditSigner(key: key, publicKeyX963: pub)
    }

    /// The X9.63 (04‖X‖Y) public key of an EC `SecKey`.
    private static func publicKeyX963(of key: SecKey) -> Data? {
        guard let pub = SecKeyCopyPublicKey(key),
              let ext = SecKeyCopyExternalRepresentation(pub, nil) as Data? else { return nil }
        return ext
    }

    public func sign(_ message: Data) throws -> Data {
        lock.lock()
        defer { lock.unlock() }
        var err: Unmanaged<CFError>?
        // SHA-256 with ECDSA P-256, returned as DER for the CryptoKit verifier.
        guard let sig = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256,
                                              message as CFData, &err) as Data? else {
            throw AuditSignerError.unavailable("SE signing failed: \(err.map { "\($0.takeRetainedValue())" } ?? "unknown")")
        }
        return sig
    }
}

/// Software P-256 fallback for tests and development builds. Anyone who can read
/// its persisted private key can forge audit entries.
public final class SoftwareAuditSigner: AuditSigner, @unchecked Sendable {
    public let backend = "software"
    private let key: P256.Signing.PrivateKey
    public var publicKeyX963: Data { key.publicKey.x963Representation }

    static let blobAccount = "auditsign.software"

    /// An ephemeral in-memory signer (tests).
    public init() { self.key = P256.Signing.PrivateKey() }

    private init(key: P256.Signing.PrivateKey) { self.key = key }

    /// The persistent dev-build signer: same key across launches, stored 0600.
    /// Corrupt or unwritable trust state is fatal: silently minting an ephemeral
    /// replacement would make an existing signed audit chain unverifiable.
    public static func persistent(namespace: String = "") throws -> SoftwareAuditSigner {
        let account = namespace + blobAccount
        return try persistent(existing: Keychain.get(account: account)) { raw in
            Keychain.set(raw, account: account) == errSecSuccess &&
            Keychain.get(account: account) == raw
        }
    }

    /// Initializes a signer from existing bytes or commits a new key.
    static func persistent(existing: Data?, commit: (Data) -> Bool) throws -> SoftwareAuditSigner {
        if let raw = existing {
            guard let key = try? P256.Signing.PrivateKey(rawRepresentation: raw) else {
                throw AuditSignerError.unavailable("persistent software signing key is malformed")
            }
            return SoftwareAuditSigner(key: key)
        }
        let key = P256.Signing.PrivateKey()
        guard commit(key.rawRepresentation) else {
            throw AuditSignerError.unavailable("persistent software signing key could not be committed")
        }
        return SoftwareAuditSigner(key: key)
    }

    public func sign(_ message: Data) throws -> Data {
        try key.signature(for: message).derRepresentation
    }
}
