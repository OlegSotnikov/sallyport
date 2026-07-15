import Foundation
import SallyportKit
import SallyportVault

/// Creates a hardware-gated vault for `Sallyport --init`.
/// Existing readable vaults are unchanged. Incompatible files are archived.
enum VaultInitCLI {
    static func run() -> Never {
        print("Sallyport vault initialization")
        let paths = OnboardingPaths.live
        let vaultURL = URL(fileURLWithPath: paths.vaultDB)
        let keystoreURL = URL(fileURLWithPath: paths.keystore)
        let fm = FileManager.default

        // Leave an existing readable vault unchanged.
        if fm.fileExists(atPath: paths.vaultDB), fm.fileExists(atPath: paths.keystore),
           (try? KeystoreLoader.load(from: keystoreURL)) != nil {
            print("OK: vault already exists at \(paths.vaultDB)")
            exit(0)
        }

        // Archive an unreadable legacy home aside (never delete ciphertext).
        let stamp = UUID().uuidString.lowercased()
        for path in [paths.vaultDB, paths.keystore] where fm.fileExists(atPath: path) {
            let dest = path + ".pre-swift-\(stamp)"
            try? fm.moveItem(atPath: path, toPath: dest)
            print("archived: \(path) -> \(dest)")
        }

        do {
            // Release builds require the Secure Enclave.
            guard SecureEnclaveKeyCustodian.isSupported else {
                print("FAIL: Sallyport hardware protection requires Apple Silicon.")
                exit(1)
            }
            guard let gate = IdentityGate.live() else {
                print("FAIL: no App Support store for the sealed identity.")
                exit(1)
            }
            let signer = KeystoreFactory.make(policy: .biometric)
            guard signer.backend == .secureEnclave else {
                print("FAIL: Secure Enclave keys are unavailable. Run the signed app build.")
                exit(1)
            }
            let (delegated, identity) = try SEDelegatedKeystore.generate()
            try gate.seal(identity: identity, using: signer)
            try delegated.save(to: keystoreURL)
            print("keystore: Secure Enclave; unlocks require Touch ID; no recovery")
            _ = try VaultStore(creatingAt: vaultURL, keystore: delegated)
            print("OK: vault created at \(paths.vaultDB)")
            print("Open Sallyport and unlock with Touch ID to start adding keys.")
            exit(0)
        } catch {
            print("FAIL: \(error)")
            exit(1)
        }
    }

    #if DEBUG
    /// Opens the development vault and reports whether it unlocks.
    static func verifyUnlock() -> Never {
        let paths = OnboardingPaths.live
        let box = ResultBox()
        let sem = DispatchSemaphore(value: 0)
        Task.detached {
            do {
                let ks = try KeystoreLoader.load(from: URL(fileURLWithPath: paths.keystore))
                let store = try VaultStore(openingAt: URL(fileURLWithPath: paths.vaultDB), keystore: ks)
                let before = await store.locked()
                try await store.unlock()
                let after = await store.locked()
                box.message = after ? "FAIL: still locked after unlock" :
                    "PASS: vault unlocks (locked before=\(before), after=false, keystore=\(ks is FileAgeKeystore ? "file-age" : "gated"))"
            } catch { box.message = "FAIL: \(error)" }
            sem.signal()
        }
        sem.wait()
        print(box.message ?? "FAIL: no result")
        exit(box.message?.hasPrefix("PASS") == true ? 0 : 1)
    }
    private final class ResultBox: @unchecked Sendable { var message: String? }
    #endif
}
