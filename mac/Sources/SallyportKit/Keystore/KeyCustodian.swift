import Foundation
import CryptoKit

/// Backend holding the vault wrapping key.
public enum KeystoreBackend: String, Sendable, Hashable {
    case secureEnclave = "secure-enclave"
    case software = "software"

    public var displayName: String {
        switch self {
        case .secureEnclave: return "Secure Enclave"
        case .software: return "Software (dev)"
        }
    }
}

/// Wrapping-key errors.
public enum KeyCustodianError: Error, Equatable {
    /// The K-wrap key material couldn't be materialized (bad/absent SPKI, or the
    /// Secure Enclave blob is missing / can't be reconstructed in this process).
    case wrapKeyUnavailable(String)
}

/// Seals the vault identity to a wrapping public key and opens it with the
/// matching private key.
public protocol KeyCustodian: Sendable {
    var backend: KeystoreBackend { get }
    /// Base64 SPKI of the wrapping public key.
    var wrapPublicKeySPKI: String { get }

    /// Seals data to this custodian's wrapping public key.
    func sealSecret(_ plaintext: Data) throws -> Data

    /// Opens a blob using the wrapping private key.
    func unsealSecret(_ blob: Data) throws -> Data
}

public extension KeyCustodian {
    /// Default ECIES seal implementation shared by all backends.
    func sealSecret(_ plaintext: Data) throws -> Data {
        guard let spki = Data(base64Encoded: wrapPublicKeySPKI),
              let recipientPub = try? P256.KeyAgreement.PublicKey(derRepresentation: spki) else {
            throw KeyCustodianError.wrapKeyUnavailable("K-wrap SPKI is not a valid P-256 DER public key")
        }
        return try ECIES.seal(plaintext, to: recipientPub)
    }
}
