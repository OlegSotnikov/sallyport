import Foundation
import CryptoKit
import SallyportKit

/// Wraps and unwraps the vault data-encryption key.
public protocol Keystore: Sendable {
    /// Encrypt the DEK to the root key; the returned blob is safe at rest.
    func wrap(_ dek: Data) throws -> Data
    /// Recover the DEK from a wrapped blob.
    func unwrap(_ blob: Data) throws -> Data
}

/// Optional interface for a keystore that requires an identity on each unlock.
public protocol Sealer: AnyObject, Sendable {
    /// Install the app-recovered identity, unsealing the keystore. Rejects an
    /// identity whose public half does not match the stored recipient.
    func deliver(identity: String) throws
    /// Clears the delivered identity.
    func seal()
    /// True when no identity is currently delivered.
    var isSealed: Bool { get }
}

public enum KeystoreError: Error, Equatable, Sendable {
    /// The data-encryption key was requested before an identity was delivered.
    case sealed
    /// The delivered identity string is not base64 / not a P-256 private key.
    case malformedIdentity
    /// The delivered identity's public half does not match the recipient, so a
    /// wrong/hostile identity cannot unlock a vault it doesn't own.
    case identityMismatch
    /// A keystore file or key blob has the wrong shape.
    case malformed(String)
    /// The keystore file names a backend this build does not know.
    case unknownBackend(String)
    /// Filesystem-level failure reading/writing the keystore file.
    case io(String)
}

// MARK: - On-disk format

/// Persisted `keystore.json` shape.
private struct PersistedKeystore: Codable {
    var backend: String
    /// file-age: base64 of the raw 32-byte ChaChaPoly wrap key.
    var wrapKey: String?
    /// se-delegated: base64 of the recipient P-256 public key (X9.63).
    var recipient: String?

    enum CodingKeys: String, CodingKey {
        case backend
        case wrapKey = "wrap_key"
        case recipient
    }
}

/// Writes the keystore with a 0700 directory and 0600 file.
private func writeKeystoreFile(_ persisted: PersistedKeystore, to url: URL) throws {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    let data: Data
    do {
        data = try encoder.encode(persisted)
    } catch {
        throw KeystoreError.io("encode keystore: \(error)")
    }
    do {
        try SecureTrustFile.write(data, to: url, maxBytes: 1 * 1024 * 1024)
    } catch {
        throw KeystoreError.io("write \(url.path): \(error)")
    }
}

/// Loads the backend recorded in `keystore.json`.
public enum KeystoreLoader {
    public static func load(from url: URL) throws -> any Keystore {
        let data: Data
        do {
            data = try SecureTrustFile.read(url, maxBytes: 1 * 1024 * 1024)
        } catch {
            throw KeystoreError.io("read \(url.path): \(error)")
        }
        let persisted: PersistedKeystore
        do {
            persisted = try JSONDecoder().decode(PersistedKeystore.self, from: data)
        } catch {
            throw KeystoreError.malformed("keystore file is not valid JSON: \(error)")
        }
        switch persisted.backend {
        case FileAgeKeystore.backendID:
            guard let b64 = persisted.wrapKey, let raw = Data(base64Encoded: b64) else {
                throw KeystoreError.malformed("file-age keystore missing wrap_key")
            }
            return try FileAgeKeystore(rawWrapKey: [UInt8](raw))
        case SEDelegatedKeystore.backendID:
            guard let recipient = persisted.recipient else {
                throw KeystoreError.malformed("se-delegated keystore missing recipient")
            }
            return try SEDelegatedKeystore(recipientBase64: recipient)
        default:
            throw KeystoreError.unknownBackend(persisted.backend)
        }
    }
}

// MARK: - Software backend ("file-age")

/// Software backend that wraps the DEK with a 32-byte ChaChaPoly key stored in a
/// 0600 JSON file outside `vault.db`. Anyone who reads that file can unwrap it.
public struct FileAgeKeystore: Keystore {
    public static let backendID = "file-age"

    /// The raw 32-byte wrap key. Held as bytes (not `SymmetricKey`) so the value
    /// is unconditionally `Sendable`; it is persisted in cleartext in the 0600
    /// keystore file anyway, so in-memory zeroization buys nothing here.
    private let wrapKey: [UInt8]

    /// Generates a keystore in memory.
    public init() {
        self.wrapKey = SymmetricKey(size: .bits256).withUnsafeBytes { [UInt8]($0) }
    }

    /// Rebuild from a raw 32-byte key (the loader's path).
    init(rawWrapKey: [UInt8]) throws {
        guard rawWrapKey.count == 32 else {
            throw KeystoreError.malformed("file-age wrap key must be 32 bytes, got \(rawWrapKey.count)")
        }
        self.wrapKey = rawWrapKey
    }

    /// Wraps the DEK as a combined ChaChaPoly nonce, ciphertext, and tag.
    public func wrap(_ dek: Data) throws -> Data {
        try ChaChaPoly.seal(dek, using: SymmetricKey(data: wrapKey)).combined
    }

    /// Unwraps the DEK and verifies the AEAD tag.
    public func unwrap(_ blob: Data) throws -> Data {
        let box = try ChaChaPoly.SealedBox(combined: blob)
        return try ChaChaPoly.open(box, using: SymmetricKey(data: wrapKey))
    }

    /// Persists the keystore to a 0600 JSON file.
    public func save(to url: URL) throws {
        try writeKeystoreFile(
            PersistedKeystore(backend: Self.backendID,
                              wrapKey: Data(wrapKey).base64EncodedString(),
                              recipient: nil),
            to: url)
    }
}

// MARK: - Hardware-gated backend ("se-delegated")

/// Hardware-gated backend using P-256 and ChaChaPoly. The persisted keystore has
/// only the recipient public key. The app seals the private identity with its
/// Secure Enclave wrapping key and delivers it after authentication. `seal()`
/// clears the delivered identity from memory.
public final class SEDelegatedKeystore: Keystore, Sealer, @unchecked Sendable {
    public static let backendID = "se-delegated"

    /// Recipient P-256 public key, X9.63 (65 bytes). Immutable.
    private let recipientX963: Data

    /// Guards `identityRaw`. `@unchecked Sendable` is sound because every access
    /// to the sole mutable field goes through this lock.
    private let stateLock = NSLock()
    /// Raw 32-byte P-256 private scalar; nil = sealed.
    private var identityRaw: [UInt8]?

    /// Builds a sealed keystore from a recipient public key.
    public init(recipientX963: Data) throws {
        do {
            _ = try P256.KeyAgreement.PublicKey(x963Representation: recipientX963)
        } catch {
            throw KeystoreError.malformed("se-delegated recipient is not a P-256 public key")
        }
        self.recipientX963 = recipientX963
    }

    /// Builds a sealed keystore from a base64 recipient.
    public convenience init(recipientBase64: String) throws {
        guard let raw = Data(base64Encoded: recipientBase64) else {
            throw KeystoreError.malformed("se-delegated recipient is not base64")
        }
        try self.init(recipientX963: raw)
    }

    /// Creates a sealed keystore and its private identity. The app must seal and
    /// discard the returned identity immediately. Losing the Secure Enclave key
    /// permanently loses access to the vault; there is no recovery path.
    public static func generate() throws -> (keystore: SEDelegatedKeystore, identity: String) {
        let identity = P256.KeyAgreement.PrivateKey()
        let keystore = try SEDelegatedKeystore(recipientX963: identity.publicKey.x963Representation)
        return (keystore, identity.rawRepresentation.base64EncodedString())
    }

    /// Persisted base64 X9.63 recipient.
    public var recipient: String { recipientX963.base64EncodedString() }

    /// Encrypts the DEK to the recipient, including while sealed.
    public func wrap(_ dek: Data) throws -> Data {
        let recipientPub = try P256.KeyAgreement.PublicKey(x963Representation: recipientX963)
        return try ECIES.seal(dek, to: recipientPub)
    }

    /// Recovers the DEK while an identity is delivered.
    public func unwrap(_ blob: Data) throws -> Data {
        let raw = stateLock.withLock { identityRaw }
        guard let raw else { throw KeystoreError.sealed }
        let identity = try P256.KeyAgreement.PrivateKey(rawRepresentation: raw)
        return try ECIES.open(blob) { ephemeralPub in
            try identity.sharedSecretFromKeyAgreement(with: ephemeralPub)
        }
    }

    /// Delivers an identity whose public key must match the stored recipient.
    public func deliver(identity: String) throws {
        let trimmed = identity.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let raw = Data(base64Encoded: trimmed),
              let key = try? P256.KeyAgreement.PrivateKey(rawRepresentation: raw) else {
            throw KeystoreError.malformedIdentity
        }
        guard key.publicKey.x963Representation == recipientX963 else {
            throw KeystoreError.identityMismatch
        }
        stateLock.withLock { identityRaw = [UInt8](raw) }
    }

    /// Zeroizes the delivered identity on lock, sleep, or timeout.
    public func seal() {
        stateLock.withLock {
            if var raw = identityRaw {
                // Drop the stored reference before mutating the remaining
                // buffer, avoiding both a force unwrap and an avoidable COW
                // copy that would leave the old allocation uncleared.
                identityRaw = nil
                for i in raw.indices { raw[i] = 0 }
            }
            identityRaw = nil
        }
    }

    /// True when no identity is delivered.
    public var isSealed: Bool {
        stateLock.withLock { identityRaw == nil }
    }

    /// Persists only the recipient; the private identity is not written here.
    public func save(to url: URL) throws {
        try writeKeystoreFile(
            PersistedKeystore(backend: Self.backendID,
                              wrapKey: nil,
                              recipient: recipient),
            to: url)
    }

    deinit {
        seal()
    }
}
