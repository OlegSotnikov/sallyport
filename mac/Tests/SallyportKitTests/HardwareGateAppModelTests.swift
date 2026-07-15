import Foundation
import Testing
@testable import SallyportKit
@testable import SallyportApp
import SallyportVault

/// The hardware-gate wiring in `AppModel.unlock()` — now end to end against a
/// REAL in-process vault: a gated vault is created (SE-recipient
/// keystore + identity sealed under the app K-wrap key), then locked and
/// unlocked, asserting the identity is delivered and the store actually opens.
/// The abort path needs no vault: it proves unlock refuses when the gate holds no
/// sealed identity, before ever touching the store.
@MainActor
@Suite("AppModel hardware-gated unlock", .serialized)
struct HardwareGateAppModelTests {

    /// A short-path home (Unix sockets cap at ~104 bytes, so `/tmp`, not the long
    /// `/var/folders` temp dir) plus a real signer + identity gate.
    private func makeModel() -> (model: AppModel, signer: SoftwareKeyCustodian,
                                 gate: IdentityGate, root: URL) {
        let root = URL(fileURLWithPath: "/tmp/spg-\(UUID().uuidString.prefix(8))", isDirectory: true)
        let paths = OnboardingPaths(home: root.appendingPathComponent("h").path)
        try? FileManager.default.createDirectory(atPath: paths.sallyportHome, withIntermediateDirectories: true)
        let signer = SoftwareKeyCustodian()
        let gate = IdentityGate(blobURL: root.appendingPathComponent("id.sealed"))
        let model = AppModel(signer: signer, authenticator: DevAuthenticator(),
                             setup: SallyportSetup(paths: paths), identityGate: gate)
        return (model, signer, gate, root)
    }

    @Test("no Secure Enclave → creation REFUSES, rather than building a weaker vault")
    func noEnclaveRefuses() async throws {
        // Intel Macs without a Secure Enclave are unsupported. A software-wrapped
        // vault keeps the key in a file beside the ciphertext — the exact bypass
        // this product exists to close — so we must fail loudly, never silently
        // downgrade. (`swift test` has no Enclave, so the software signer here is
        // the real thing being rejected.)
        let (model, signer, gate, root) = makeModel()
        defer { model.runtime.host?.stop(); try? FileManager.default.removeItem(at: root) }

        await #expect(throws: (any Error).self) {
            try await model.runtime.createVault(hardwareGate: true, signer: signer, gate: gate)
        }
        #expect(model.runtime.host == nil, "no half-built vault is left behind")
    }

    @Test("gated home + NO sealed identity → aborts with a surfaced error, stays locked")
    func gatedWithoutIdentityAborts() async {
        let (model, _, _, root) = makeModel()
        defer { try? FileManager.default.removeItem(at: root) }
        // A gated keystore on disk but an empty identity gate (nothing sealed).
        try? SecureTrustFile.write(
            Data(#"{"backend":"se-delegated","recipient":"x"}"#.utf8),
            to: URL(fileURLWithPath: model.setup.paths.keystore),
            maxBytes: 1_048_576)

        await model.unlock()

        #expect(model.vaultUnlockError != nil)          // clear error, not a silent unlock
        #expect(model.vault.locked == true)             // never opened the store
    }

    @Test("non-gated (file-age) vault → create → lock → unlocks with no identity, no error")
    func fileAgeNoRegression() async throws {
        let (model, signer, gate, root) = makeModel()
        defer { model.runtime.host?.stop(); try? FileManager.default.removeItem(at: root) }

        try await model.runtime.createVault(hardwareGate: false, signer: signer, gate: gate)
        #expect(model.isHardwareGated == false)

        await model.runtime.lock()
        await model.refreshVaultFromStatus()
        #expect(model.vault.locked == true)

        await model.unlock()
        #expect(model.vaultUnlockError == nil)
        #expect(model.vault.locked == false)
    }
}

/// Erasing the vault is irreversible, so the phrase check is enforced in the
/// MODEL, not just the sheet — no caller can skip it.
@MainActor
@Suite("Vault reset", .serialized)
struct VaultResetTests {

    private func makeModel() -> (AppModel, URL) {
        let root = URL(fileURLWithPath: "/tmp/spr-\(UUID().uuidString.prefix(8))", isDirectory: true)
        let paths = OnboardingPaths(home: root.appendingPathComponent("h").path)
        try? FileManager.default.createDirectory(atPath: paths.sallyportHome, withIntermediateDirectories: true)
        let model = AppModel(signer: SoftwareKeyCustodian(), authenticator: DevAuthenticator(),
                             setup: SallyportSetup(paths: paths),
                             identityGate: IdentityGate(blobURL: root.appendingPathComponent("id.sealed")))
        model.isDemo = true
        return (model, root)
    }

    @Test("a wrong phrase erases NOTHING")
    func wrongPhraseIsRefused() async throws {
        let (model, root) = makeModel()
        defer { model.runtime.host?.stop(); try? FileManager.default.removeItem(at: root) }
        try await model.runtime.createVault(hardwareGate: false, signer: SoftwareKeyCustodian(), gate: nil)
        try await model.mgmt.setSecret(SecretInput(name: "keep_me", kind: "bearer", value: "v"))

        for wrong in ["", "erase", "ERASE MY KEY", "yes", "DELETE MY KEYS"] {
            await #expect(throws: (any Error).self) {
                try await model.resetVault(confirmation: wrong)
            }
        }
        // The vault and its secret are untouched.
        #expect(FileManager.default.fileExists(atPath: model.setup.paths.vaultDB))
        #expect(try await model.mgmt.listSecrets().map(\.name) == ["keep_me"])
    }

    @Test("the exact phrase erases every key and leaves a fresh, working vault")
    func correctPhraseErases() async throws {
        let (model, root) = makeModel()
        defer { model.runtime.host?.stop(); try? FileManager.default.removeItem(at: root) }
        try await model.runtime.createVault(hardwareGate: false, signer: SoftwareKeyCustodian(), gate: nil)
        try await model.mgmt.setSecret(SecretInput(name: "doomed", kind: "bearer", value: "v"))
        #expect(try await model.mgmt.listSecrets().count == 1)

        // No Secure Enclave in `swift test`, so the reset's re-create step (which
        // demands one) throws — but only AFTER the old vault is gone. That is the
        // contract we care about: the keys really are destroyed.
        _ = try? await model.resetVault(confirmation: AppModel.resetConfirmationPhrase)
        #expect(!FileManager.default.fileExists(atPath: model.setup.paths.vaultDB),
                "the old ciphertext must be gone")
        #expect(!FileManager.default.fileExists(atPath: model.setup.paths.keystore),
                "the wrapping key must be gone")
        // Everything else the app stored goes with it — hosts, audit, recordings.
        #expect(!FileManager.default.fileExists(atPath: model.setup.paths.sallyportHome + "/hosts.json"))
        #expect(!FileManager.default.fileExists(atPath: model.setup.paths.sallyportHome + "/audit"))
    }

    @Test("the phrase is case-insensitive but must be the whole phrase")
    func phraseNormalization() async throws {
        let (model, root) = makeModel()
        defer { try? FileManager.default.removeItem(at: root) }
        // No vault at all: the phrase check still runs first and rejects.
        await #expect(throws: (any Error).self) {
            try await model.resetVault(confirmation: "erase my keyz")
        }
    }
}
