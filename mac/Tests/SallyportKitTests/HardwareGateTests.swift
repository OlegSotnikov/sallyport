import Foundation
import Testing
import CryptoKit
@testable import SallyportKit

@Suite("ECIES seal/unseal (K-wrap)")
struct ECIESTests {

    @Test("KeyCustodian.sealSecret → unsealSecret round-trips the exact bytes")
    func signerRoundTrip() throws {
        let signer = SoftwareKeyCustodian()
        let secret = Data("AGE-SECRET-KEY-1QQPQ8W9F7X2ZK3M4N5P6R7S8T9V0".utf8)
        let blob = try signer.sealSecret(secret)
        #expect(blob != secret)                     // it's actually sealed, not stored plain
        let opened = try signer.unsealSecret(blob)
        #expect(opened == secret)
    }

    @Test("a tampered blob fails to open (AEAD tag rejects it)")
    func tamperFails() throws {
        let signer = SoftwareKeyCustodian()
        var blob = try signer.sealSecret(Data("secret".utf8))
        // Flip the final byte (inside the ChaChaPoly tag) — parses fine, auth fails.
        blob[blob.index(before: blob.endIndex)] ^= 0xFF
        #expect(throws: (any Error).self) { _ = try signer.unsealSecret(blob) }
    }

    @Test("a different signer's K-wrap key cannot open the blob")
    func wrongKeyFails() throws {
        let alice = SoftwareKeyCustodian()
        let bob = SoftwareKeyCustodian()
        let blob = try alice.sealSecret(Data("only-for-alice".utf8))
        #expect(throws: (any Error).self) { _ = try bob.unsealSecret(blob) }
        // …and Alice still opens her own.
        #expect(try alice.unsealSecret(blob) == Data("only-for-alice".utf8))
    }

    @Test("a truncated / garbage blob throws malformedBlob, not a crash")
    func malformedBlob() {
        let signer = SoftwareKeyCustodian()
        #expect(throws: ECIES.ECIESError.malformedBlob) { _ = try signer.unsealSecret(Data()) }
        #expect(throws: ECIES.ECIESError.malformedBlob) {
            _ = try signer.unsealSecret(Data([0xFF, 0xFF, 0x01, 0x02]))   // claims 65535-byte pub
        }
    }

    @Test("ECIES primitive round-trips over raw P-256 KeyAgreement keys")
    func primitiveRoundTrip() throws {
        let recipient = P256.KeyAgreement.PrivateKey()
        let plaintext = Data("payload".utf8)
        let blob = try ECIES.seal(plaintext, to: recipient.publicKey)
        let opened = try ECIES.open(blob) { ephemeralPub in
            try recipient.sharedSecretFromKeyAgreement(with: ephemeralPub)
        }
        #expect(opened == plaintext)
    }

    @Test("ECIES.openRaw derives the SAME key as seal — the Data-Protection-Keychain SE unseal bridge (#1)")
    func openRawInterop() throws {
        // openRaw is what the migrated K-wrap custodian uses: the SE key yields
        // the RAW ECDH shared secret (SecKeyCopyKeyExchangeResult), not a CryptoKit
        // SharedSecret. This proves openRaw(rawX) opens what seal(CryptoKit) wrote —
        // the exact interop the vault-unlock path depends on, without needing an SE.
        let recipient = P256.KeyAgreement.PrivateKey()
        let plaintext = Data("vault-identity-secret".utf8)
        let blob = try ECIES.seal(plaintext, to: recipient.publicKey)
        let opened = try ECIES.openRaw(blob) { ephemeralPub in
            let shared = try recipient.sharedSecretFromKeyAgreement(with: ephemeralPub)
            return shared.withUnsafeBytes { Data($0) }   // the raw X, == SecKey ECDH result
        }
        #expect(opened == plaintext)
        // A wrong raw secret must fail the AEAD tag, never silently mis-open.
        #expect(throws: (any Error).self) {
            _ = try ECIES.openRaw(blob) { _ in Data(repeating: 0, count: 32) }
        }
    }
}

@Suite("IdentityGate (sealed age identity on disk)")
struct IdentityGateTests {

    private func tempGate() -> (IdentityGate, URL) {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("sallyport-gate-\(UUID().uuidString)", isDirectory: true)
        let url = dir.appendingPathComponent("identity.sealed", isDirectory: false)
        return (IdentityGate(blobURL: url), dir)
    }

    @Test("seal → unseal returns the identity; isSealed toggles; clear removes it")
    func roundTrip() throws {
        let (gate, dir) = tempGate()
        defer { try? FileManager.default.removeItem(at: dir) }
        let signer = SoftwareKeyCustodian()
        let identity = "AGE-SECRET-KEY-1QQPQ8W9F7X2ZK3M4N5P6R7S8T9V0W1X2Y3Z4A5B6C7D8E9F0GHJ2K3L4"

        #expect(gate.isSealed == false)
        try gate.seal(identity: identity, using: signer)
        #expect(gate.isSealed == true)
        #expect(try gate.unseal(using: signer) == identity)

        gate.clear()
        #expect(gate.isSealed == false)
        #expect(throws: IdentityGate.GateError.notSealed) { _ = try gate.unseal(using: signer) }
    }

    @Test("seal trims surrounding whitespace and rejects an empty identity")
    func trimmingAndEmpty() throws {
        let (gate, dir) = tempGate()
        defer { try? FileManager.default.removeItem(at: dir) }
        let signer = SoftwareKeyCustodian()

        try gate.seal(identity: "  AGE-SECRET-KEY-1TRIMMED\n", using: signer)
        #expect(try gate.unseal(using: signer) == "AGE-SECRET-KEY-1TRIMMED")

        #expect(throws: IdentityGate.GateError.emptyIdentity) {
            try gate.seal(identity: "   \n ", using: signer)
        }
    }

    @Test("a blob sealed by one signer can't be unsealed by another")
    func wrongSignerCantUnseal() throws {
        let (gate, dir) = tempGate()
        defer { try? FileManager.default.removeItem(at: dir) }
        try gate.seal(identity: "AGE-SECRET-KEY-1SECRET", using: SoftwareKeyCustodian())
        #expect(throws: (any Error).self) { _ = try gate.unseal(using: SoftwareKeyCustodian()) }
    }

    @Test("a symlink blob cannot redirect seal, unseal, isSealed, or clear")
    func symlinkBlobFailsClosed() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("sallyport-gate-link-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: root) }
        try SecureTrustFile.prepareDirectory(root)
        let victim = root.appendingPathComponent("victim")
        let blob = root.appendingPathComponent("identity.sealed")
        try SecureTrustFile.write(Data("victim".utf8), to: victim, maxBytes: 1_048_576)
        try FileManager.default.createSymbolicLink(atPath: blob.path,
                                                   withDestinationPath: victim.path)
        let gate = IdentityGate(blobURL: blob)

        #expect(!gate.isSealed)
        #expect(throws: (any Error).self) {
            try gate.seal(identity: "AGE-SECRET-KEY-1SECRET", using: SoftwareKeyCustodian())
        }
        #expect(throws: IdentityGate.GateError.notSealed) {
            _ = try gate.unseal(using: SoftwareKeyCustodian())
        }
        gate.clear()
        #expect(FileManager.default.fileExists(atPath: blob.path))
        #expect(try SecureTrustFile.read(victim, maxBytes: 1_048_576) == Data("victim".utf8))
    }
}

@Suite("HardwareGate keystore detection")
struct HardwareGateTests {

    private func writeKeystore(_ json: String) -> OnboardingPaths {
        let home = FileManager.default.temporaryDirectory
            .appendingPathComponent("sallyport-home-\(UUID().uuidString)", isDirectory: true)
        let paths = OnboardingPaths(home: home.path)
        try? FileManager.default.createDirectory(
            atPath: paths.sallyportHome, withIntermediateDirectories: true)
        try? SecureTrustFile.write(Data(json.utf8),
                                   to: URL(fileURLWithPath: paths.keystore),
                                   maxBytes: 1_048_576)
        return paths
    }

    @Test("a se-delegated keystore is detected as gated")
    func gated() {
        let paths = writeKeystore(#"{"backend":"se-delegated"}"#)
        defer { try? FileManager.default.removeItem(atPath: paths.home) }
        #expect(HardwareGate.isGatedHome(paths) == true)
        #expect(HardwareGate.isGatedKeystore(at: paths.keystore) == true)
    }

    @Test("a file-age keystore is NOT gated (the common case)")
    func fileAge() {
        let paths = writeKeystore(#"{"backend":"file-age","age_identity":"AGE-SECRET-KEY-1X"}"#)
        defer { try? FileManager.default.removeItem(atPath: paths.home) }
        #expect(HardwareGate.isGatedHome(paths) == false)
    }

    @Test("a missing or malformed keystore defaults to not-gated (never disturbs file-age)")
    func missingOrMalformed() {
        #expect(HardwareGate.isGatedKeystore(at: "/nope/does/not/exist/keystore.json") == false)
        let paths = writeKeystore("not json at all")
        defer { try? FileManager.default.removeItem(atPath: paths.home) }
        #expect(HardwareGate.isGatedHome(paths) == false)
    }
}
