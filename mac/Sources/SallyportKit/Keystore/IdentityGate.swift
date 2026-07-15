import Foundation

/// Stores the vault identity sealed to the app's Secure Enclave wrapping key.
public struct IdentityGate: Sendable {

    private static let maxBlobBytes = 1 * 1024 * 1024

    public enum GateError: Error, Equatable {
        /// No sealed blob on disk (nothing to unseal).
        case notSealed
        /// The identity handed to `seal` was empty/whitespace.
        case emptyIdentity
        /// The blob couldn't be written (disk error, no store dir).
        case writeFailed(String)
    }

    /// Absolute path of the sealed-identity blob file.
    public let blobURL: URL

    /// Point the gate at an explicit blob file. Tests pass a temp path; the live
    /// app uses `live()`.
    public init(blobURL: URL) { self.blobURL = blobURL }

    /// The live gate: `~/Library/Application Support/dev.sallyport.mac/identity.sealed`.
    /// Nil only if the App Support directory can't be created.
    public static func live() -> IdentityGate? {
        guard let dir = Keychain.storeDirectory() else { return nil }
        return IdentityGate(blobURL: dir.appendingPathComponent("identity.sealed", isDirectory: false))
    }

    /// True when a sealed blob exists on disk.
    public var isSealed: Bool {
        SecureTrustFile.exists(blobURL, maxBytes: Self.maxBlobBytes)
    }

    /// Seals a non-empty identity and writes it with mode 0600.
    public func seal(identity: String, using custodian: any KeyCustodian) throws {
        let trimmed = identity.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw GateError.emptyIdentity }
        let blob = try custodian.sealSecret(Data(trimmed.utf8))
        do {
            try SecureTrustFile.write(blob, to: blobURL, maxBytes: Self.maxBlobBytes)
        } catch {
            throw GateError.writeFailed("\(error)")
        }
    }

    /// Opens the stored identity with the wrapping private key.
    public func unseal(using custodian: any KeyCustodian) throws -> String {
        guard let blob = try? SecureTrustFile.read(blobURL, maxBytes: Self.maxBlobBytes),
              !blob.isEmpty else {
            throw GateError.notSealed
        }
        let plaintext = try custodian.unsealSecret(blob)
        return String(decoding: plaintext, as: UTF8.self)
    }

    /// Removes the sealed blob if present.
    public func clear() {
        try? SecureTrustFile.remove(blobURL, maxBytes: Self.maxBlobBytes)
    }
}

/// Detects a hardware-gated keystore from its backend field.
public enum HardwareGate {
    /// Reads only the backend field from keystore metadata.
    private struct BackendProbe: Decodable { let backend: String }

    /// The backend string a hardware-gated keystore reports.
    public static let gatedBackend = "se-delegated"

    /// Returns false for missing or malformed metadata.
    public static func isGatedKeystore(at keystorePath: String) -> Bool {
        guard let data = try? SecureTrustFile.read(
                  URL(fileURLWithPath: keystorePath), maxBytes: 1 * 1024 * 1024),
              let probe = try? JSONDecoder().decode(BackendProbe.self, from: data)
        else { return false }
        return probe.backend == gatedBackend
    }

    /// Whether the configured home uses the hardware-gated keystore.
    public static func isGatedHome(_ paths: OnboardingPaths) -> Bool {
        isGatedKeystore(at: paths.keystore)
    }
}
