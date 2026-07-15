import Foundation
import Darwin
import Testing
@testable import SallyportKit
@testable import SallyportApp

/// The `KeysViewModel.save` decision path — the testable half of the SSH-key
/// import flow. The view (NSOpenPanel + the reveal/focus of the passphrase field)
/// isn't unit-testable, so the branch that decides *how* to react to a save
/// result lives in the view model and is proven here against the mock daemon.
@MainActor
@Suite("KeysViewModel save outcomes")
struct KeysViewModelTests {

    private func model(seeded: Bool = false) -> KeysViewModel {
        KeysViewModel(mgmt: MgmtClient.mock(daemon: MockMgmtDaemon(seeded: seeded)))
    }

    @Test("an encrypted key with no passphrase → .needsPassphrase (prompt, not toast)")
    func encryptedKeyNeedsPassphrase() async {
        let vm = model()
        let input = SecretInput(name: "id_ed25519", kind: "ssh-ed25519",
                                value: "-----BEGIN OPENSSH PRIVATE KEY-----\nENCRYPTED…")
        let outcome = await vm.save(input, isNew: true)
        guard case .needsPassphrase = outcome else {
            Issue.record("expected .needsPassphrase, got \(outcome)"); return
        }
    }

    @Test("supplying the passphrase → .saved and the key is listed")
    func passphraseImportsSaves() async {
        let vm = model()
        var input = SecretInput(name: "id_ed25519", kind: "ssh-ed25519",
                                value: "-----BEGIN OPENSSH PRIVATE KEY-----\nENCRYPTED…")
        input.passphrase = "hunter2"
        #expect(await vm.save(input, isNew: true) == .saved)
        #expect(vm.secrets.contains { $0.name == "id_ed25519" })
    }

    @Test("an unencrypted key imports straight away")
    func plainKeyImports() async {
        let vm = model()
        let input = SecretInput(name: "plain", kind: "ssh-ed25519",
                                value: "-----BEGIN OPENSSH PRIVATE KEY-----\n(plain)")
        #expect(await vm.save(input, isNew: true) == .saved)
    }

    @Test("key-file import is bounded and rejects unsafe filesystem objects")
    func importedKeyFileSecurity() throws {
        let root = URL(fileURLWithPath: "/tmp/sallyport-key-import-\(UUID().uuidString)",
                       isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }

        let regular = root.appendingPathComponent("id_ed25519")
        let expected = "-----BEGIN OPENSSH PRIVATE KEY-----\nkey\n"
        try Data(expected.utf8).write(to: regular)
        #expect(try SecretEditor.readImportedKey(at: regular) == expected)

        let oversized = root.appendingPathComponent("oversized")
        try Data(repeating: 0x41, count: SecretEditor.maxImportedKeyBytes + 1).write(to: oversized)
        #expect(throws: SecretEditor.ImportedKeyFileError.tooLarge) {
            _ = try SecretEditor.readImportedKey(at: oversized)
        }

        let symlink = root.appendingPathComponent("symlink")
        try FileManager.default.createSymbolicLink(at: symlink, withDestinationURL: regular)
        #expect(throws: SecretEditor.ImportedKeyFileError.unsafeFile) {
            _ = try SecretEditor.readImportedKey(at: symlink)
        }

        let hardlink = root.appendingPathComponent("hardlink")
        #expect(Darwin.link(regular.path, hardlink.path) == 0)
        #expect(throws: SecretEditor.ImportedKeyFileError.unsafeFile) {
            _ = try SecretEditor.readImportedKey(at: regular)
        }

        let fifo = root.appendingPathComponent("fifo")
        #expect(mkfifo(fifo.path, 0o600) == 0)
        #expect(throws: SecretEditor.ImportedKeyFileError.unsafeFile) {
            _ = try SecretEditor.readImportedKey(at: fifo)
        }

        let invalidUTF8 = root.appendingPathComponent("invalid-utf8")
        try Data([0xff, 0xfe]).write(to: invalidUTF8)
        #expect(throws: SecretEditor.ImportedKeyFileError.invalidUTF8) {
            _ = try SecretEditor.readImportedKey(at: invalidUTF8)
        }
    }

    @Test("agent-supplied documentation links cannot launch local or custom schemes")
    func credentialDocsURLSecurity() {
        let accepted = CredentialRequestSheet.safeDocsURL(
            "https://dashboard.example.com/token/new?scope=read"
        )
        #expect(accepted?.host() == "dashboard.example.com")
        #expect(CredentialRequestSheet.safeDocsURL("https://dashboard.example.com:443/token") != nil)

        let refused = [
            "http://dashboard.example.com/token",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "https://user:pass@dashboard.example.com/token",
            "https://dashboard.example.com:8443/token",
            "https://localhost/token",
            "https://service.local/token",
            "https://intranet/token",
            "https://127.0.0.1/token",
            "https://[::1]/token",
            "https://.example.com/token",
            "https://example..com/token",
            "https://-dashboard.example.com/token",
            "https://dashboard_.example.com/token",
            "https://dashboard.example.com./token",
            "https://dashboard.example.com/\nnext",
            "https://аррӏе.com/token",
        ]
        for raw in refused {
            #expect(CredentialRequestSheet.safeDocsURL(raw) == nil, "unexpectedly accepted \(raw)")
        }
    }
}
