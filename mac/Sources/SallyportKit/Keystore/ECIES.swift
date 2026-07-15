import Foundation
import CryptoKit

/// P-256 ECDH, HKDF-SHA256, and ChaChaPoly.
/// Blob layout: ephemeral-key length, X9.63 ephemeral key, then the combined box.
public enum ECIES {

    public enum ECIESError: Error, Equatable {
        /// The blob is too short, has a bad length prefix, or an unparseable pub.
        case malformedBlob
    }

    /// Changing this string makes existing blobs unreadable.
    private static let sharedInfo = Data("sallyport-identity-v1".utf8)

    /// Derives the 32-byte ChaChaPoly key.
    private static func symmetricKey(from shared: SharedSecret,
                                     ephemeralPub: P256.KeyAgreement.PublicKey) -> SymmetricKey {
        shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: ephemeralPub.rawRepresentation,
            sharedInfo: sharedInfo,
            outputByteCount: 32)
    }

    /// Seals plaintext with a fresh ephemeral key.
    public static func seal(_ plaintext: Data,
                            to recipientPub: P256.KeyAgreement.PublicKey) throws -> Data {
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: recipientPub)
        let symKey = symmetricKey(from: shared, ephemeralPub: ephemeral.publicKey)
        let box = try ChaChaPoly.seal(plaintext, using: symKey)

        let pub = ephemeral.publicKey.x963Representation   // 65 bytes for P-256
        // Return an error if the public-key length cannot be encoded.
        guard let pubLength = UInt16(exactly: pub.count) else {
            throw ECIESError.malformedBlob
        }
        var blob = Data(capacity: 2 + pub.count + box.combined.count)
        blob.append(UInt8(pubLength >> 8))
        blob.append(UInt8(pubLength & 0xff))
        blob.append(pub)
        blob.append(box.combined)
        return blob
    }

    /// Opens a blob using a backend-provided ECDH operation.
    public static func open(_ blob: Data,
                            sharedSecretFor: (P256.KeyAgreement.PublicKey) throws -> SharedSecret) throws -> Data {
        let (ephemeralPub, sealedBox) = try parse(blob)
        let shared = try sharedSecretFor(ephemeralPub)
        let symKey = symmetricKey(from: shared, ephemeralPub: ephemeralPub)
        return try ChaChaPoly.open(sealedBox, using: symKey)
    }

    /// Opens a blob from raw ECDH shared-secret bytes returned by `SecKey`.
    public static func openRaw(_ blob: Data,
                               rawSharedSecretFor: (P256.KeyAgreement.PublicKey) throws -> Data) throws -> Data {
        let (ephemeralPub, sealedBox) = try parse(blob)
        let raw = try rawSharedSecretFor(ephemeralPub)
        let symKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: raw),
            salt: ephemeralPub.rawRepresentation,
            info: sharedInfo,
            outputByteCount: 32)
        return try ChaChaPoly.open(sealedBox, using: symKey)
    }

    /// Parse the framed blob into the ephemeral public key + sealed box.
    private static func parse(_ blob: Data) throws -> (P256.KeyAgreement.PublicKey, ChaChaPoly.SealedBox) {
        // Normalize to a zero-based byte array so slice index math is unambiguous
        // even when `blob` is a Data slice with a non-zero startIndex.
        let bytes = [UInt8](blob)
        guard bytes.count >= 2 else { throw ECIESError.malformedBlob }
        let len = (Int(bytes[0]) << 8) | Int(bytes[1])
        let pubEnd = 2 + len
        guard len > 0, pubEnd <= bytes.count else { throw ECIESError.malformedBlob }
        let ephemeralPub: P256.KeyAgreement.PublicKey
        do {
            ephemeralPub = try P256.KeyAgreement.PublicKey(x963Representation: Data(bytes[2..<pubEnd]))
        } catch { throw ECIESError.malformedBlob }
        let sealedBox: ChaChaPoly.SealedBox
        do {
            sealedBox = try ChaChaPoly.SealedBox(combined: Data(bytes[pubEnd...]))
        } catch { throw ECIESError.malformedBlob }
        return (ephemeralPub, sealedBox)
    }
}
