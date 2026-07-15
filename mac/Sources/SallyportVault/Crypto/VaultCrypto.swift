import Foundation
import CryptoKit

/// Derives ChaChaPoly keys from the DEK with HKDF-SHA256.
/// AAD binds records to sid/version/domain, blobs to key, and recordings to filename.
public enum VaultCrypto {

    public static let metaDomain = "meta"
    public static let valueDomain = "value"
    static let blobDomain = "blob"

    /// Derive the 32-byte per-record subkey. Deterministic in (dek, sid, version, domain).
    static func recordKey(dek: SymmetricKey, sid: String, version: Int, domain: String) -> SymmetricKey {
        let info = Data("sallyport-record:v2:\(domain):\(sid):\(version)".utf8)
        return HKDF<SHA256>.deriveKey(inputKeyMaterial: dek, info: info, outputByteCount: 32)
    }

    /// The additional authenticated data binding a ciphertext to its slot, so a
    /// sealed blob can't be silently moved to another record or domain.
    static func aad(sid: String, version: Int, domain: String) -> Data {
        Data("\(sid)\u{0}\(version)\u{0}\(domain)".utf8)
    }

    /// Seal `plaintext` for (sid, version, domain). Returns the combined
    /// nonce‖ciphertext‖tag blob to store. The caller zeroizes `plaintext`.
    public static func seal(_ plaintext: Data, dek: SymmetricKey,
                            sid: String, version: Int, domain: String) throws -> Data {
        let key = recordKey(dek: dek, sid: sid, version: version, domain: domain)
        let box = try ChaChaPoly.seal(plaintext, using: key,
                                      authenticating: aad(sid: sid, version: version, domain: domain))
        return box.combined
    }

    /// Opens a stored blob and rejects a wrong key, moved record, or invalid tag.
    public static func open(_ blob: Data, dek: SymmetricKey,
                            sid: String, version: Int, domain: String) throws -> Data {
        let key = recordKey(dek: dek, sid: sid, version: version, domain: domain)
        let box = try ChaChaPoly.SealedBox(combined: blob)
        return try ChaChaPoly.open(box, using: key,
                                   authenticating: aad(sid: sid, version: version, domain: domain))
    }

    /// Seal a singleton vault document (hosts inventory, settings, audit identity).
    public static func sealBlob(_ plaintext: Data, dek: SymmetricKey, key: String) throws -> Data {
        try seal(plaintext, dek: dek, sid: key, version: 0, domain: blobDomain)
    }

    /// Open a singleton vault document.
    public static func openBlob(_ blob: Data, dek: SymmetricKey, key: String) throws -> Data {
        try open(blob, dek: dek, sid: key, version: 0, domain: blobDomain)
    }

    /// Derives the recording key in a separate HKDF domain.
    static func recordingKey(dek: SymmetricKey) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: dek, info: Data("sallyport-recording:v2".utf8),
                               outputByteCount: 32)
    }

    /// Seal one session recording. `filename` (the basename the sealed file will
    /// be stored under) is authenticated, so sealed casts can't be swapped.
    public static func sealRecording(_ cast: Data, dek: SymmetricKey, filename: String) throws -> Data {
        try ChaChaPoly.seal(cast, using: recordingKey(dek: dek),
                            authenticating: Data(filename.utf8)).combined
    }

    /// Open one sealed session recording.
    public static func openRecording(_ blob: Data, dek: SymmetricKey, filename: String) throws -> Data {
        let box = try ChaChaPoly.SealedBox(combined: blob)
        return try ChaChaPoly.open(box, using: recordingKey(dek: dek),
                                   authenticating: Data(filename.utf8))
    }
}
