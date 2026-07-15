import Darwin
import Foundation
import Security
import CryptoKit
import Testing
@testable import SallyportKit

private enum InjectedWriteFailure: Error { case stop }
private enum ConcurrentSnapshotError: Error { case tornWrite }

private func trustRoot() throws -> URL {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("sallyport-trust-file-\(UUID().uuidString)", isDirectory: true)
    try SecureTrustFile.prepareDirectory(root)
    return root
}

@Suite("Secure trust-file persistence")
struct SecureTrustFileTests {
    private let limit = 1 * 1024 * 1024

    @Test("atomic replacement is 0600 in a 0700 directory and round-trips")
    func atomicRoundTripAndPermissions() throws {
        let root = try trustRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("root.bin")

        try SecureTrustFile.write(Data("old".utf8), to: file, maxBytes: limit)
        try SecureTrustFile.write(Data("new".utf8), to: file, maxBytes: limit)

        #expect(try SecureTrustFile.read(file, maxBytes: limit) == Data("new".utf8))
        let fileMode = try #require(
            FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions] as? NSNumber)
        let directoryMode = try #require(
            FileManager.default.attributesOfItem(atPath: root.path)[.posixPermissions] as? NSNumber)
        #expect(fileMode.intValue == 0o600)
        #expect(directoryMode.intValue == 0o700)
        #expect(try FileManager.default.contentsOfDirectory(atPath: root.path) == ["root.bin"])
    }

    @Test("a final symlink cannot redirect a trust-root write")
    func finalSymlinkRejected() throws {
        let root = try trustRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let victim = root.appendingPathComponent("victim")
        let redirected = root.appendingPathComponent("redirected")
        try SecureTrustFile.write(Data("victim".utf8), to: victim, maxBytes: limit)
        try FileManager.default.createSymbolicLink(atPath: redirected.path,
                                                   withDestinationPath: victim.path)

        #expect(throws: SecureTrustFile.FileError.unsafeFile) {
            try SecureTrustFile.write(Data("secret".utf8), to: redirected, maxBytes: limit)
        }
        #expect(throws: SecureTrustFile.FileError.unsafeFile) {
            _ = try SecureTrustFile.read(redirected, maxBytes: limit)
        }
        #expect(try SecureTrustFile.read(victim, maxBytes: limit) == Data("victim".utf8))
    }

    @Test("a symlink parent cannot redirect trust state")
    func parentSymlinkRejected() throws {
        let root = try trustRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let real = root.appendingPathComponent("real", isDirectory: true)
        let linked = root.appendingPathComponent("linked", isDirectory: true)
        try SecureTrustFile.prepareDirectory(real)
        try FileManager.default.createSymbolicLink(atPath: linked.path,
                                                   withDestinationPath: real.path)
        let file = linked.appendingPathComponent("secret")

        #expect(throws: SecureTrustFile.FileError.unsafeParent) {
            try SecureTrustFile.write(Data("secret".utf8), to: file, maxBytes: limit)
        }
        #expect(!FileManager.default.fileExists(
            atPath: real.appendingPathComponent("secret").path))
    }

    @Test("dot components and non-file URLs are not accepted as trust paths")
    func ambiguousPathsRejected() throws {
        let root = try trustRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let dotted = URL(fileURLWithPath: root.path + "/child/../secret")
        #expect(throws: SecureTrustFile.FileError.invalidPath) {
            try SecureTrustFile.write(Data("secret".utf8), to: dotted, maxBytes: limit)
        }
        #expect(throws: SecureTrustFile.FileError.invalidPath) {
            try SecureTrustFile.write(Data(), to: URL(string: "https://example.com/root")!,
                                      maxBytes: limit)
        }
    }

    @Test("hardlinks are rejected for reads, writes, existence, and removal")
    func hardlinkRejected() throws {
        let root = try trustRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("root")
        let alias = root.appendingPathComponent("alias")
        try SecureTrustFile.write(Data("secret".utf8), to: file, maxBytes: limit)
        try FileManager.default.linkItem(at: file, to: alias)

        #expect(throws: SecureTrustFile.FileError.unsafeFile) {
            _ = try SecureTrustFile.read(file, maxBytes: limit)
        }
        #expect(throws: SecureTrustFile.FileError.unsafeFile) {
            try SecureTrustFile.write(Data("replacement".utf8), to: file, maxBytes: limit)
        }
        #expect(!SecureTrustFile.exists(file, maxBytes: limit))
        #expect(throws: SecureTrustFile.FileError.unsafeFile) {
            try SecureTrustFile.remove(file, maxBytes: limit)
        }
    }

    @Test("FIFO and world-readable files fail closed without blocking")
    func specialAndUnsafeModeRejected() throws {
        let root = try trustRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let fifo = root.appendingPathComponent("fifo")
        #expect(Darwin.mkfifo(fifo.path, mode_t(0o600)) == 0)
        #expect(throws: SecureTrustFile.FileError.unsafeFile) {
            _ = try SecureTrustFile.read(fifo, maxBytes: limit)
        }
        #expect(throws: SecureTrustFile.FileError.unsafeFile) {
            try SecureTrustFile.write(Data("secret".utf8), to: fifo, maxBytes: limit)
        }

        let exposed = root.appendingPathComponent("exposed")
        try SecureTrustFile.write(Data("secret".utf8), to: exposed, maxBytes: limit)
        #expect(Darwin.chmod(exposed.path, mode_t(0o644)) == 0)
        #expect(throws: SecureTrustFile.FileError.unsafeFile) {
            _ = try SecureTrustFile.read(exposed, maxBytes: limit)
        }
        #expect(!SecureTrustFile.exists(exposed, maxBytes: limit))
    }

    @Test("an extended ACL cannot bypass 0600 mode")
    func extendedACLRejected() throws {
        let root = try trustRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("acl-root")
        try SecureTrustFile.write(Data("secret".utf8), to: file, maxBytes: limit)

        let chmod = Process()
        chmod.executableURL = URL(fileURLWithPath: "/bin/chmod")
        chmod.arguments = ["+a", "everyone allow read", file.path]
        try chmod.run()
        chmod.waitUntilExit()
        #expect(chmod.terminationStatus == 0)

        #expect(throws: SecureTrustFile.FileError.unsafeFile) {
            _ = try SecureTrustFile.read(file, maxBytes: limit)
        }
        #expect(!SecureTrustFile.exists(file, maxBytes: limit))
        #expect(throws: SecureTrustFile.FileError.unsafeFile) {
            try SecureTrustFile.remove(file, maxBytes: limit)
        }
    }

    @Test("failure before rename preserves the old file and removes the temp")
    func preCommitFailureIsAtomic() throws {
        let root = try trustRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("root")
        try SecureTrustFile.write(Data("old".utf8), to: file, maxBytes: limit)

        #expect(throws: InjectedWriteFailure.stop) {
            try SecureTrustFile.writeForTesting(
                Data("new".utf8), to: file, maxBytes: limit) {
                    throw InjectedWriteFailure.stop
                }
        }
        #expect(try SecureTrustFile.read(file, maxBytes: limit) == Data("old".utf8))
        #expect(try FileManager.default.contentsOfDirectory(atPath: root.path) == ["root"])
    }

    @Test("a live parent replacement never redirects the pinned commit")
    func liveParentSwapDetected() throws {
        let root = try trustRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let live = root.appendingPathComponent("live", isDirectory: true)
        let moved = root.appendingPathComponent("moved", isDirectory: true)
        try SecureTrustFile.prepareDirectory(live)
        let file = live.appendingPathComponent("root")

        #expect(throws: SecureTrustFile.FileError.unsafeParent) {
            try SecureTrustFile.writeForTesting(
                Data("pinned".utf8), to: file, maxBytes: limit) {
                    try FileManager.default.moveItem(at: live, to: moved)
                    try SecureTrustFile.prepareDirectory(live)
                    try SecureTrustFile.write(
                        Data("decoy".utf8),
                        to: live.appendingPathComponent("root"),
                        maxBytes: limit)
                }
        }

        #expect(try SecureTrustFile.read(
            moved.appendingPathComponent("root"), maxBytes: limit) == Data("pinned".utf8))
        #expect(try SecureTrustFile.read(
            live.appendingPathComponent("root"), maxBytes: limit) == Data("decoy".utf8))
    }

    @Test("concurrent readers and writers never expose a partial snapshot")
    func concurrentSnapshotsAreWhole() async throws {
        let root = try trustRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("contended")
        let byteCount = 4_096
        try SecureTrustFile.write(Data(repeating: 0, count: byteCount),
                                  to: file, maxBytes: limit)

        try await withThrowingTaskGroup(of: Void.self) { group in
            for value in UInt8(1)...UInt8(4) {
                group.addTask {
                    let payload = Data(repeating: value, count: byteCount)
                    for _ in 0..<10 {
                        do {
                            try SecureTrustFile.write(payload, to: file, maxBytes: self.limit)
                        } catch SecureTrustFile.FileError.unsafeFile {
                            // Another writer won after this writer's atomic
                            // rename. The call fails closed; it never reports a
                            // torn or redirected commit as successful.
                        }
                    }
                }
            }
            for _ in 0..<4 {
                group.addTask {
                    for _ in 0..<50 {
                        do {
                            let snapshot = try SecureTrustFile.read(file, maxBytes: self.limit)
                            guard snapshot.count == byteCount,
                                  let first = snapshot.first,
                                  first <= 4,
                                  snapshot.allSatisfy({ $0 == first }) else {
                                throw ConcurrentSnapshotError.tornWrite
                            }
                        } catch SecureTrustFile.FileError.unsafeFile {
                            // A rename between open and the final path-identity
                            // check is detected and refused; it is never returned
                            // as a mixed snapshot.
                        }
                    }
                }
            }
            try await group.waitForAll()
        }

        let final = try SecureTrustFile.read(file, maxBytes: limit)
        #expect(final.count == byteCount)
        #expect(final.allSatisfy { $0 == final.first })
    }
}

@Suite("Keychain file fallback")
struct KeychainFileStoreTests {
    @Test("fallback round-trips, rejects ambiguous accounts, and deletes durably")
    func roundTripAccountValidationAndDelete() throws {
        let root = try trustRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let store = KeychainFileStore(directory: root)
        let payload = Data("opaque-SE-handle".utf8)

        #expect(store.set(payload, account: "kwrap.blob.biometric") == errSecSuccess)
        #expect(store.get(account: "kwrap.blob.biometric") == payload)
        for invalid in ["", ".", "..", "a/b", "a\\b", "space name", "ümlaut"] {
            #expect(store.set(payload, account: invalid) == errSecIO)
            #expect(store.get(account: invalid) == nil)
        }
        #expect(store.set(Data(repeating: 0, count: KeychainFileStore.maxBlobBytes + 1),
                          account: "too.large") == errSecIO)
        #expect(store.delete(account: "kwrap.blob.biometric") == errSecSuccess)
        #expect(store.get(account: "kwrap.blob.biometric") == nil)
        #expect(store.delete(account: "kwrap.blob.biometric") == errSecItemNotFound)
    }

    @Test("fallback refuses symlink and hardlink slots without changing their targets")
    func hostileSlotsRejected() throws {
        let root = try trustRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let store = KeychainFileStore(directory: root)
        let victim = root.appendingPathComponent("victim")
        try SecureTrustFile.write(Data("victim".utf8), to: victim,
                                  maxBytes: KeychainFileStore.maxBlobBytes)
        let symlink = root.appendingPathComponent("redirect.blob")
        try FileManager.default.createSymbolicLink(atPath: symlink.path,
                                                   withDestinationPath: victim.path)

        #expect(store.set(Data("secret".utf8), account: "redirect") == errSecIO)
        #expect(store.get(account: "redirect") == nil)
        #expect(store.delete(account: "redirect") == errSecIO)
        #expect(try SecureTrustFile.read(victim,
                                        maxBytes: KeychainFileStore.maxBlobBytes) == Data("victim".utf8))

        #expect(store.set(Data("root".utf8), account: "linked") == errSecSuccess)
        let linked = root.appendingPathComponent("linked.blob")
        try FileManager.default.linkItem(at: linked,
                                         to: root.appendingPathComponent("linked-alias"))
        #expect(store.get(account: "linked") == nil)
        #expect(store.set(Data("new".utf8), account: "linked") == errSecIO)
        #expect(store.delete(account: "linked") == errSecIO)
    }

    @Test("software audit signer refuses corrupt state and failed persistence")
    func auditSignerInitializationFailsClosed() throws {
        var commitCalled = false
        #expect(throws: AuditSignerError.self) {
            _ = try SoftwareAuditSigner.persistent(existing: Data("not-a-p256-key".utf8)) { _ in
                commitCalled = true
                return true
            }
        }
        #expect(!commitCalled)

        #expect(throws: AuditSignerError.self) {
            _ = try SoftwareAuditSigner.persistent(existing: nil) { _ in false }
        }

        var committed: Data?
        let created = try SoftwareAuditSigner.persistent(existing: nil) { raw in
            committed = raw
            return true
        }
        let raw = try #require(committed)
        let recovered = try P256.Signing.PrivateKey(rawRepresentation: raw)
        #expect(created.publicKeyX963 == recovered.publicKey.x963Representation)
    }
}
