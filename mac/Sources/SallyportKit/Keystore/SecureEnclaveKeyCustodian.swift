import Foundation
import CryptoKit
import LocalAuthentication
import Security
import os

/// How the Secure-Enclave key is gated.
public enum SEKeyPolicy: String, Sendable, Hashable {
    /// Requires Touch ID for private-key use. Uses `.biometryAny` so changing
    /// enrolled fingerprints does not invalidate the key.
    case biometric
    /// Development mode without a biometric requirement.
    case deviceUnlocked

    /// Keychain accessibility class.
    var accessibility: CFString {
        switch self {
        case .biometric: return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        case .deviceUnlocked: return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        }
    }

    var accessFlags: SecAccessControlCreateFlags {
        switch self {
        case .biometric: return [.privateKeyUsage, .biometryAny]
        case .deviceUnlocked: return [.privateKeyUsage]
        }
    }

    /// Keychain account suffix, so the two policies persist independent keys.
    var accountSuffix: String { rawValue }
}

/// Holds the vault wrapping key in the Secure Enclave. The private key is not
/// exported. The biometric mode requires Touch ID for unsealing.
///
/// `@unchecked Sendable`: the only non-`Sendable` member is the optional
/// `LAContext`, set once via `authenticated(with:)` and read on the main actor.
public final class SecureEnclaveKeyCustodian: KeyCustodian, @unchecked Sendable {
    public let backend = KeystoreBackend.secureEnclave
    public let policy: SEKeyPolicy
    /// Whether the key was loaded instead of created during this launch.
    public let reused: Bool
    public let wrapPublicKeySPKI: String

    /// Data Protection Keychain tag for the wrapping key.
    private let tag: Data
    private let context: LAContext?

    private init(policy: SEKeyPolicy, reused: Bool, tag: Data,
                 wrapPublicKeySPKI: String, context: LAContext?) {
        self.policy = policy
        self.reused = reused
        self.tag = tag
        self.wrapPublicKeySPKI = wrapPublicKeySPKI
        self.context = context
    }

    // MARK: Creation / persistence

    /// Loads or creates the wrapping key. Returns nil when unavailable.
    ///
    /// - Parameter namespace: Account prefix. Diagnostics must use a non-empty value.
    /// - Parameter createIfMissing: Whether to create a missing key.
    public static func makeAvailable(policy: SEKeyPolicy = .biometric,
                                     persistent: Bool = true,
                                     namespace: String = "",
                                     createIfMissing: Bool = true) -> SecureEnclaveKeyCustodian? {
        guard SecureEnclave.isAvailable else { return nil }
        let tag = Data(("dev.sallyport.kwrap." + namespace + policy.accountSuffix).utf8)

        // Loading the key reference does not use the private key or prompt.
        if persistent, let key = fetchKey(tag: tag, context: nil),
           let spki = spki(of: key) {
            diagnostics.withLock { $0.persist = "kwrap SecKey reused (tag \(tag.count)B)" }
            return SecureEnclaveKeyCustodian(policy: policy, reused: true, tag: tag,
                                             wrapPublicKeySPKI: spki, context: nil)
        }

        guard createIfMissing else { return nil }
        guard let access = makeAccessControl(policy: policy) else { return nil }
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecUseDataProtectionKeychain as String: true,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: persistent,
                kSecAttrApplicationTag as String: tag,
                kSecAttrAccessControl as String: access,
            ],
        ]
        var err: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &err), let spki = spki(of: key) else {
            let message = err.map { "\($0.takeRetainedValue())" } ?? "SecKeyCreateRandomKey returned nil"
            diagnostics.withLock { $0.createError = message }
            return nil
        }
        diagnostics.withLock { $0.persist = "kwrap SecKey created (persistent=\(persistent))" }
        return SecureEnclaveKeyCustodian(policy: policy, reused: false, tag: tag,
                                         wrapPublicKeySPKI: spki, context: nil)
    }

    /// Fetch the K-wrap `SecKey` from the data-protection keychain by tag. When
    /// `context` is set it is bound so a biometric use reuses that authentication.
    private static func fetchKey(tag: Data, context: LAContext?) -> SecKey? {
        var q: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecUseDataProtectionKeychain as String: true,
            kSecReturnRef as String: true,
        ]
        if let context { q[kSecUseAuthenticationContext as String] = context }
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let ref = out else { return nil }
        guard CFGetTypeID(ref) == SecKeyGetTypeID() else { return nil }
        return unsafeDowncast(ref, to: SecKey.self)
    }

    /// Base64 DER SPKI for the wrapping key's public half.
    private static func spki(of key: SecKey) -> String? {
        guard let pub = SecKeyCopyPublicKey(key),
              let x963 = SecKeyCopyExternalRepresentation(pub, nil) as Data?,
              let ck = try? P256.KeyAgreement.PublicKey(x963Representation: x963) else { return nil }
        return ck.derRepresentation.base64EncodedString()
    }

    /// Diagnostic state from the last key operation.
    private struct DiagnosticState: Sendable {
        var createError = ""
        var persist = ""
    }
    private static let diagnostics = OSAllocatedUnfairLock(initialState: DiagnosticState())
    public static var lastCreateError: String { diagnostics.withLock { $0.createError } }
    public static var lastPersistDebug: String { diagnostics.withLock { $0.persist } }

    /// Whether this process can create and use a Secure Enclave key.
    public static var isSupported: Bool {
        guard SecureEnclave.isAvailable else { return false }
        guard let access = makeAccessControl(policy: .deviceUnlocked) else { return false }
        do {
            let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
            // Verify key agreement without a biometric prompt.
            _ = try key.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PrivateKey().publicKey)
            return true
        } catch {
            diagnostics.withLock { $0.createError = "\(error)" }
            return false
        }
    }

    /// Creates and reloads a key in a diagnostic namespace.
    public static func persistenceReport(policy: SEKeyPolicy,
                                         namespace: String = "selftest.") -> String {
        reset(policy: policy, namespace: namespace)
        _ = makeAvailable(policy: policy, persistent: true, namespace: namespace)
        return lastPersistDebug
    }

    /// Deletes the persisted key in the supplied namespace.
    public static func reset(policy: SEKeyPolicy, namespace: String) {
        let tag = Data(("dev.sallyport.kwrap." + namespace + policy.accountSuffix).utf8)
        let q: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecUseDataProtectionKeychain as String: true,
        ]
        SecItemDelete(q as CFDictionary)
    }

    // MARK: Seal / unseal

    /// Reuses an authenticated `LAContext` for unsealing.
    public func authenticated(with context: LAContext) -> SecureEnclaveKeyCustodian {
        SecureEnclaveKeyCustodian(policy: policy, reused: reused, tag: tag,
                                  wrapPublicKeySPKI: wrapPublicKeySPKI, context: context)
    }

    /// Opens a blob using the Secure Enclave wrapping key.
    public func unsealSecret(_ blob: Data) throws -> Data {
        guard let key = Self.fetchKey(tag: tag, context: context) else {
            throw KeyCustodianError.wrapKeyUnavailable("the SE K-wrap key is not in the keychain (or access was refused)")
        }
        do {
            return try ECIES.openRaw(blob) { ephemeralPub in
                try Self.ecdhRaw(privateKey: key, ephemeralPub: ephemeralPub)
            }
        } catch let e as KeyCustodianError {
            throw e
        } catch {
            throw KeyCustodianError.wrapKeyUnavailable("K-wrap ECDH failed: \(error)")
        }
    }

    /// Raw ECDH shared secret between the wrapping key and an ephemeral public key.
    /// The biometric policy may prompt for Touch ID here.
    private static func ecdhRaw(privateKey: SecKey, ephemeralPub: P256.KeyAgreement.PublicKey) throws -> Data {
        var err: Unmanaged<CFError>?
        guard let ephSec = SecKeyCreateWithData(ephemeralPub.x963Representation as CFData, [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
        ] as CFDictionary, &err) else {
            throw KeyCustodianError.wrapKeyUnavailable("bad ephemeral public key")
        }
        guard let raw = SecKeyCopyKeyExchangeResult(privateKey, .ecdhKeyExchangeStandard,
                                                    ephSec, [:] as CFDictionary, &err) as Data? else {
            throw KeyCustodianError.wrapKeyUnavailable("SE key exchange refused: \(err.map { "\($0.takeRetainedValue())" } ?? "?")")
        }
        return raw
    }

    private static func makeAccessControl(policy: SEKeyPolicy) -> SecAccessControl? {
        var error: Unmanaged<CFError>?
        return SecAccessControlCreateWithFlags(
            kCFAllocatorDefault, policy.accessibility, policy.accessFlags, &error)
    }
}

/// Software wrapping key for tests and development builds.
public struct SoftwareKeyCustodian: KeyCustodian {
    public let backend = KeystoreBackend.software
    private let wrapKey: P256.KeyAgreement.PrivateKey
    public var wrapPublicKeySPKI: String { wrapKey.publicKey.derRepresentation.base64EncodedString() }

    public init() { self.wrapKey = P256.KeyAgreement.PrivateKey() }

    public func unsealSecret(_ blob: Data) throws -> Data {
        try ECIES.open(blob) { ephemeralPub in
            try wrapKey.sharedSecretFromKeyAgreement(with: ephemeralPub)
        }
    }
}

/// Selects the Secure Enclave when available, otherwise software.
public enum KeystoreFactory {
    public static func make(policy: SEKeyPolicy = .biometric,
                            preferSecureEnclave: Bool = true) -> any KeyCustodian {
        if preferSecureEnclave,
           let se = SecureEnclaveKeyCustodian.makeAvailable(policy: policy) {
            return se
        }
        return SoftwareKeyCustodian()
    }

    public static func makeDefault(preferSecureEnclave: Bool = true) -> any KeyCustodian {
        make(policy: .biometric, preferSecureEnclave: preferSecureEnclave)
    }
}
