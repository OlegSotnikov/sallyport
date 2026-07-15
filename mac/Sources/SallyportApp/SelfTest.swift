import Foundation
import SallyportKit

/// Verifies Secure Enclave key creation, sealing, foreign-ciphertext rejection,
/// persistence, and biometric-key availability in an isolated namespace.
enum SelfTest {
    @MainActor
    static func run() -> Never {
        let ns = "selftest."
        var ok = true
        func check(_ label: String, _ pass: Bool, _ detail: String = "") {
            print("  [\(pass ? " OK " : "FAIL")] \(label)\(detail.isEmpty ? "" : ": \(detail)")")
            if !pass { ok = false }
        }

        print("Sallyport.app Secure Enclave self-test")
        print(String(repeating: "-", count: 58))
        print("  Secure Enclave usable here     : \(SecureEnclaveKeyCustodian.isSupported)")
        print("  Touch ID available (LAContext) : \(BiometricAuthenticator.isAvailable())")
        print(String(repeating: "-", count: 58))

        // Create a wrapping key in the self-test namespace.
        SecureEnclaveKeyCustodian.reset(policy: .deviceUnlocked, namespace: ns)
        guard let custodian = SecureEnclaveKeyCustodian.makeAvailable(
                policy: .deviceUnlocked, namespace: ns) else {
            check("create a Secure-Enclave K-wrap key", false,
                  "makeAvailable returned nil: \(SecureEnclaveKeyCustodian.lastCreateError). Check the app signature.")
            finish(false)
        }
        check("create Secure-Enclave K-wrap key (fresh)", !custodian.reused,
              "backend=\(custodian.backend.rawValue) policy=\(custodian.policy.rawValue)")

        // Verify sealing to the public key and unsealing with the Secure Enclave key.
        let identity = "SELFTEST-IDENTITY-\(UUID().uuidString)"
        do {
            let sealed = try custodian.sealSecret(Data(identity.utf8))
            check("seal the vault identity to the K-wrap public key", !sealed.isEmpty,
                  "\(sealed.count)-byte ECIES blob")
            let opened = try custodian.unsealSecret(sealed)
            check("unseal it again inside the Enclave",
                  String(decoding: opened, as: UTF8.self) == identity)
        } catch {
            check("seal / unseal round-trip", false, "\(error)")
        }

        // A blob sealed to a different key must not open.
        do {
            let foreign = try SoftwareKeyCustodian().sealSecret(Data("not yours".utf8))
            _ = try custodian.unsealSecret(foreign)
            check("a blob sealed to another key is refused", false, "the blob opened")
        } catch {
            check("a blob sealed to another key is refused", true)
        }

        // Verify that the same key is loaded after relaunch. A replacement key
        // would orphan the sealed identity.
        print("  persistence: \(SecureEnclaveKeyCustodian.lastPersistDebug)")
        guard let reloaded = SecureEnclaveKeyCustodian.makeAvailable(
                policy: .deviceUnlocked, namespace: ns) else {
            check("reload the persisted K-wrap key", false, "makeAvailable returned nil")
            finish(false)
        }
        check("persisted K-wrap key is reused across launches", reloaded.reused,
              "a fresh key here would orphan every sealed vault")
        check("the reloaded key has the same public half",
              reloaded.wrapPublicKeySPKI == custodian.wrapPublicKeySPKI)

        // Verify that the biometric policy can be created without using it.
        SecureEnclaveKeyCustodian.reset(policy: .biometric, namespace: ns)
        if let bio = SecureEnclaveKeyCustodian.makeAvailable(policy: .biometric, namespace: ns) {
            check("create the biometric (.biometryAny) K-wrap key", true,
                  "wrap SPKI=\(bio.wrapPublicKeySPKI.prefix(24))…")
        } else {
            let err = SecureEnclaveKeyCustodian.lastCreateError
            if err.contains("-25293") || err.lowercased().contains("interaction") {
                print("  [SKIP] biometric K-wrap key requires an unlocked screen: \(err)")
            } else {
                check("create the biometric (.biometryAny) K-wrap key", false, "nil (\(err))")
            }
        }

        finish(ok)
    }

    private static func finish(_ ok: Bool) -> Never {
        print(String(repeating: "-", count: 58))
        print(ok ? "SELFTEST: PASS" : "SELFTEST: FAIL")
        exit(ok ? 0 : 1)
    }
}
