import Testing
import Foundation
import CryptoKit
import Darwin
@testable import SallyportVault
import SallyportKit   // SoftwareKeyCustodian + IdentityGate for the hardware-gate handoff shape

/// A unique per-test file path under a fresh temp directory.
private func tempFile(_ name: String) throws -> URL {
    let dir = FileManager.default.temporaryDirectory
        .appendingPathComponent("sallyport-keystore-tests", isDirectory: true)
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    return dir.appendingPathComponent(name, isDirectory: false)
}

@Suite("Keystore — DEK wrapping backends")
struct KeystoreTests {

    // MARK: file-age (software backend)

    @Test("file-age: wrap → unwrap round-trips; the blob never contains the DEK")
    func fileWrapUnwrapRoundTrip() throws {
        let ks = FileAgeKeystore()
        let dek = Data(SymmetricKey(size: .bits256).withUnsafeBytes { [UInt8]($0) })
        let blob = try ks.wrap(dek)
        #expect(blob.range(of: dek) == nil)
        let got = try ks.unwrap(blob)
        #expect(got == dek)
    }

    @Test("file-age: a wrong keystore cannot unwrap")
    func fileWrongKeyFails() throws {
        let k1 = FileAgeKeystore()
        let k2 = FileAgeKeystore()
        let dek = Data(repeating: 0xAB, count: 32)
        let blob = try k1.wrap(dek)
        #expect(throws: (any Error).self) {
            _ = try k2.unwrap(blob)
        }
    }

    @Test("file-age: a tampered blob fails to unwrap (AEAD tag)")
    func fileTamperFails() throws {
        let ks = FileAgeKeystore()
        let blob = try ks.wrap(Data(repeating: 0x11, count: 32))
        var bad = blob
        bad[bad.count - 1] ^= 0xFF
        #expect(throws: (any Error).self) {
            _ = try ks.unwrap(bad)
        }
    }

    @Test("file-age: save → load round-trips through the 0600 JSON file")
    func fileSaveLoad() throws {
        let url = try tempFile("keystore.json")
        let original = FileAgeKeystore()
        try original.save(to: url)

        let perms = (try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? NSNumber)?.intValue
        #expect(perms == 0o600)

        let loaded = try KeystoreLoader.load(from: url)
        #expect(loaded is FileAgeKeystore)

        // A DEK wrapped by the original must unwrap after reload, and vice versa.
        let dek = Data(repeating: 0x11, count: 32)
        let byOriginal = try original.wrap(dek)
        let unwrapped = try loaded.unwrap(byOriginal)
        #expect(unwrapped == dek)
        let byLoaded = try loaded.wrap(dek)
        let back = try original.unwrap(byLoaded)
        #expect(back == dek)
    }

    // MARK: se-delegated (hardware gate)

    @Test("se-delegated: boots SEALED — wrap works, unwrap fails until deliver, seal re-seals")
    func delegatedSealedUntilDelivered() throws {
        let url = try tempFile("keystore.json")
        let (provisioned, identity) = try SEDelegatedKeystore.generate()
        try provisioned.save(to: url)
        let dek = Data(repeating: 0x42, count: 32)

        // The persisted file carries ONLY the recipient — a reload is sealed.
        let loaded = try KeystoreLoader.load(from: url)
        let gated = try #require(loaded as? SEDelegatedKeystore)
        #expect(gated.isSealed)
        #expect(gated.recipient == provisioned.recipient)

        // Wrap still works (public recipient); unwrap fails sealed.
        let wrapped = try gated.wrap(dek)
        #expect(throws: KeystoreError.sealed) {
            _ = try gated.unwrap(wrapped)
        }

        // A wrong identity is rejected (recipient mismatch) and it stays sealed.
        let (_, wrongIdentity) = try SEDelegatedKeystore.generate()
        #expect(throws: KeystoreError.identityMismatch) {
            try gated.deliver(identity: wrongIdentity)
        }
        #expect(gated.isSealed)

        // The real identity unseals it and recovers the exact DEK.
        try gated.deliver(identity: identity)
        #expect(!gated.isSealed)
        let got = try gated.unwrap(wrapped)
        #expect(got == dek)

        // seal() zeroizes: sealed again, unwrap refuses.
        gated.seal()
        #expect(gated.isSealed)
        #expect(throws: KeystoreError.sealed) {
            _ = try gated.unwrap(wrapped)
        }
    }

    @Test("se-delegated: malformed identity strings are rejected and it stays sealed")
    func delegatedMalformedIdentity() throws {
        let (ks, _) = try SEDelegatedKeystore.generate()
        #expect(throws: KeystoreError.malformedIdentity) {
            try ks.deliver(identity: "not-base64!!")
        }
        #expect(throws: KeystoreError.malformedIdentity) {
            try ks.deliver(identity: Data("short".utf8).base64EncodedString())
        }
        #expect(ks.isSealed)
    }

    @Test("se-delegated: a sealed keystore blocks VaultStore.unlock until delivery")
    func delegatedVaultUnlockFlow() async throws {
        let vaultURL = try tempFile("vault.db")
        let (keystore, identity) = try SEDelegatedKeystore.generate()

        // Creating a vault only needs wrap (public op) — works while SEALED.
        let store = try VaultStore(creatingAt: vaultURL, keystore: keystore)
        try await store.set(SecretMeta(name: "s", kind: "bearer"), value: Data("v".utf8))
        await store.lock()

        // Sealed → the keystore refuses the DEK → unlock fails, vault stays shut.
        await #expect(throws: KeystoreError.sealed) {
            try await store.unlock()
        }

        // Deliver (the app's Touch-ID step) → unlock succeeds → value readable.
        try keystore.deliver(identity: identity)
        try await store.unlock()
        let v = try await store.secretValue(name: "s")
        #expect(v == Data("v".utf8))

        // Lock + seal (what the host does on lock/sleep/TTL) → shut again.
        await store.lock()
        keystore.seal()
        await #expect(throws: KeystoreError.sealed) {
            try await store.unlock()
        }
        await store.close()
    }

    @Test("se-delegated: the Sealer cast distinguishes the gated backend, like Go's type assert")
    func sealerCast() throws {
        let (gated, _) = try SEDelegatedKeystore.generate()
        #expect((gated as any Keystore) is Sealer)
        #expect(!((FileAgeKeystore() as any Keystore) is Sealer))
    }

    @Test("se-delegated: IdentityGate seals/unseals the identity (the Touch-ID handoff shape)")
    func identityGateHandoff() throws {
        let (keystore, identity) = try SEDelegatedKeystore.generate()

        // The app-side gate, with the software signer standing in for the
        // Secure Enclave (same KeyCustodian surface; SE needs a signed .app).
        let signer = SoftwareKeyCustodian()
        let gate = IdentityGate(blobURL: try tempFile("identity.sealed"))
        try gate.seal(identity: identity, using: signer)

        // The sealed blob never contains the identity in the clear.
        let blob = try Data(contentsOf: gate.blobURL)
        #expect(blob.range(of: Data(identity.utf8)) == nil)

        // Unseal (Touch ID in the live app) → deliver → the gate opens.
        let recovered = try gate.unseal(using: signer)
        try keystore.deliver(identity: recovered)
        #expect(!keystore.isSealed)

        let dek = Data(repeating: 0x07, count: 32)
        let wrapped = try keystore.wrap(dek)
        let got = try keystore.unwrap(wrapped)
        #expect(got == dek)
    }

    // MARK: loader

    @Test("loader refuses an unknown backend")
    func unknownBackend() throws {
        let url = try tempFile("keystore.json")
        try SecureTrustFile.write(Data(#"{"backend":"martian"}"#.utf8),
                                  to: url, maxBytes: 1_048_576)
        #expect(throws: KeystoreError.unknownBackend("martian")) {
            _ = try KeystoreLoader.load(from: url)
        }
    }

    @Test("loader refuses a file-age keystore with a bad wrap key")
    func malformedWrapKey() throws {
        let url = try tempFile("keystore.json")
        let short = Data(repeating: 1, count: 16).base64EncodedString()
        try SecureTrustFile.write(
            Data(#"{"backend":"file-age","wrap_key":"\#(short)"}"#.utf8),
            to: url, maxBytes: 1_048_576)
        #expect(throws: (any Error).self) {
            _ = try KeystoreLoader.load(from: url)
        }
    }

    @Test("save and load reject a final symlink without touching its victim")
    func keystoreSymlinkRejected() throws {
        let url = try tempFile("keystore.json")
        let victim = url.deletingLastPathComponent().appendingPathComponent("victim")
        try SecureTrustFile.write(Data("victim".utf8), to: victim, maxBytes: 1_048_576)
        try FileManager.default.createSymbolicLink(atPath: url.path,
                                                   withDestinationPath: victim.path)

        #expect(throws: (any Error).self) { try FileAgeKeystore().save(to: url) }
        #expect(throws: (any Error).self) { _ = try KeystoreLoader.load(from: url) }
        #expect(try SecureTrustFile.read(victim, maxBytes: 1_048_576) == Data("victim".utf8))
    }

    @Test("save and load reject a hardlinked keystore")
    func keystoreHardlinkRejected() throws {
        let url = try tempFile("keystore.json")
        try FileAgeKeystore().save(to: url)
        try FileManager.default.linkItem(
            at: url,
            to: url.deletingLastPathComponent().appendingPathComponent("alias"))

        #expect(throws: (any Error).self) { _ = try KeystoreLoader.load(from: url) }
        #expect(throws: (any Error).self) { try FileAgeKeystore().save(to: url) }
    }

    @Test("save and load reject FIFO/device-style path entries without blocking")
    func keystoreFIFORejected() throws {
        let url = try tempFile("keystore.json")
        #expect(Darwin.mkfifo(url.path, mode_t(0o600)) == 0)
        #expect(throws: (any Error).self) { _ = try KeystoreLoader.load(from: url) }
        #expect(throws: (any Error).self) { try FileAgeKeystore().save(to: url) }
    }

    @Test("loader refuses a world-readable keystore")
    func exposedKeystoreRejected() throws {
        let url = try tempFile("keystore.json")
        try FileAgeKeystore().save(to: url)
        #expect(Darwin.chmod(url.path, mode_t(0o644)) == 0)
        #expect(throws: (any Error).self) { _ = try KeystoreLoader.load(from: url) }
    }

    @Test("save rejects an immediate symlink parent")
    func keystoreParentSymlinkRejected() throws {
        let root = try tempFile("unused").deletingLastPathComponent()
        let real = root.appendingPathComponent("real", isDirectory: true)
        let linked = root.appendingPathComponent("linked", isDirectory: true)
        try SecureTrustFile.prepareDirectory(real)
        try FileManager.default.createSymbolicLink(atPath: linked.path,
                                                   withDestinationPath: real.path)
        #expect(throws: (any Error).self) {
            try FileAgeKeystore().save(to: linked.appendingPathComponent("keystore.json"))
        }
        #expect(!FileManager.default.fileExists(
            atPath: real.appendingPathComponent("keystore.json").path))
    }
}
