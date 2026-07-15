import Foundation
import Testing
import SallyportKit
import Darwin
@testable import SallyportVault

private enum IntegrityInjectedFailure: Error, Equatable {
    case operation
    case load
    case save
}

/// Models a substituted/broken root that authenticates a wrapper but returns a
/// non-AES-256 plaintext. CryptoKit accepts multiple AES key sizes, so the store
/// itself must enforce the vault's exact 32-byte DEK contract.
private struct InvalidLengthKeystore: Keystore {
    func wrap(_ dek: Data) throws -> Data { dek }
    func unwrap(_ blob: Data) throws -> Data { Data(blob.prefix(31)) }
}

private final class MemoryAnchorStore: AnchorStore, @unchecked Sendable {
    private let lock = NSLock()
    private var current: AnchorState?
    private var history: [AnchorState] = []
    private var loadFailure = false
    private var saveFailure = false

    func load() throws -> AnchorState? {
        try lock.withLock {
            if loadFailure { throw IntegrityInjectedFailure.load }
            return current
        }
    }

    func save(_ anchor: AnchorState) throws {
        try lock.withLock {
            if saveFailure { throw IntegrityInjectedFailure.save }
            if let current, anchor.counter <= current.counter {
                throw AnchorStoreError.nonMonotonic(previous: current.counter, next: anchor.counter)
            }
            current = anchor
            history.append(anchor)
        }
    }

    func reset() {
        lock.withLock {
            current = nil
            history = []
        }
    }

    func failLoad(_ value: Bool) { lock.withLock { loadFailure = value } }
    func failSave(_ value: Bool) { lock.withLock { saveFailure = value } }
    func replace(_ anchor: AnchorState?) { lock.withLock { current = anchor } }
    func snapshot() -> (AnchorState?, [AnchorState]) { lock.withLock { (current, history) } }
}

private actor DeterministicSuspension {
    private var entered = false
    private var released = false
    private var enteredWaiters: [CheckedContinuation<Void, Never>] = []
    private var releaseWaiters: [CheckedContinuation<Void, Never>] = []

    func pause() async {
        entered = true
        enteredWaiters.forEach { $0.resume() }
        enteredWaiters.removeAll()
        if released { return }
        await withCheckedContinuation { releaseWaiters.append($0) }
    }

    func waitUntilEntered() async {
        if entered { return }
        await withCheckedContinuation { enteredWaiters.append($0) }
    }

    func release() {
        released = true
        releaseWaiters.forEach { $0.resume() }
        releaseWaiters.removeAll()
    }
}

@Suite("Integrity lifecycle transactions", .serialized)
struct IntegrityTransactionTests {
    private struct Approve: Approver {
        func requestApproval(_ req: EngineApproval) async -> ApprovalOutcome { .approved }
    }

    private struct Fixture {
        let home: URL
        let store: VaultStore
        let host: VaultHost
        let anchors: MemoryAnchorStore

        func close() async {
            host.stop()
            await store.close()
            try? FileManager.default.removeItem(at: home)
        }
    }

    private func fixture() async throws -> Fixture {
        let home = URL(fileURLWithPath: "/tmp/spit-\(UUID().uuidString.prefix(8))", isDirectory: true)
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        let store = try VaultStore(creatingAt: home.appendingPathComponent("vault.db"),
                                   keystore: FileAgeKeystore())
        let anchors = MemoryAnchorStore()
        let host = try await VaultHost(
            store: store, hosts: HostsStore(),
            paths: .init(socket: home.appendingPathComponent("s.sock").path,
                         auditDir: home.appendingPathComponent("audit").path,
                         knownHosts: home.appendingPathComponent("known_hosts").path,
                         recordDir: home.appendingPathComponent("recordings").path,
                         sshHelper: "/usr/bin/false"),
            approver: Approve(), signer: SoftwareAuditSigner(), anchorStore: anchors)
        let epoch = try await store.deferReadinessForHost()
        let issues = try #require(await host.activateUnlockedVault(expectedEpoch: epoch))
        #expect(issues.isEmpty)
        #expect(await store.phaseNow() == .ready)
        return Fixture(home: home, store: store, host: host, anchors: anchors)
    }

    @Test("late hydration from an old unlock cannot publish into a newer lifecycle")
    func staleHydrationCannotPublish() async throws {
        let f = try await fixture(); defer { f.host.stop() }
        defer { try? FileManager.default.removeItem(at: f.home) }
        let oldHosts = [HostsStore.Entry(name: "old", addr: "10.0.0.1")]
        try await f.store.setBlob(key: VaultStore.hostsBlobKey,
                                  data: try JSONEncoder().encode(oldHosts))
        await f.store.lock(); f.host.onVaultLocked()
        let oldEpoch = try await f.store.unlock(deferReady: true)

        let pause = DeterministicSuspension()
        f.host._setLifecycleTestHooks(.init(beforeHydrationCommit: { await pause.pause() }))
        let stale = Task { await f.host.activateUnlockedVault(expectedEpoch: oldEpoch) }
        await pause.waitUntilEntered()

        await f.store.lock(); f.host.onVaultLocked()
        let newEpoch = try await f.store.unlock(deferReady: true)
        let newHosts = [HostsStore.Entry(name: "new", addr: "10.0.0.2")]
        try await f.store.setBlob(key: VaultStore.hostsBlobKey,
                                  data: try JSONEncoder().encode(newHosts), expectedEpoch: newEpoch)
        f.host._setLifecycleTestHooks(.init())
        await pause.release()
        #expect(await stale.value == nil)

        let issues = try #require(await f.host.activateUnlockedVault(expectedEpoch: newEpoch))
        #expect(issues.map(\.code).contains("state-rolled-back"),
                "the deliberate out-of-band disk edit remains detectable")
        #expect(f.host.hosts.list().map(\.name) == ["new"])
        await f.store.close()
    }

    @Test("a stale integrity verdict cannot ready or quarantine a later unlock")
    func staleGateCannotCommit() async throws {
        let f = try await fixture(); defer { f.host.stop() }
        defer { try? FileManager.default.removeItem(at: f.home) }
        await f.store.lock(); f.host.onVaultLocked()
        let oldEpoch = try await f.store.unlock(deferReady: true)
        let pause = DeterministicSuspension()
        f.host._setLifecycleTestHooks(.init(beforeGateCommit: { await pause.pause() }))
        let stale = Task { await f.host.activateUnlockedVault(expectedEpoch: oldEpoch) }
        await pause.waitUntilEntered()
        await f.store.lock(); f.host.onVaultLocked()
        let newEpoch = try await f.store.unlock(deferReady: true)
        f.host._setLifecycleTestHooks(.init())
        await pause.release()
        #expect(await stale.value == nil)
        #expect(await f.store.phaseNow() == .unlocking)
        #expect(try #require(await f.host.activateUnlockedVault(expectedEpoch: newEpoch)).isEmpty)
        await f.store.close()
    }

    @Test("post-gate and re-adopt work are epoch-bound")
    func stalePostGateAndReadoptCannotCommit() async throws {
        let f = try await fixture(); defer { f.host.stop() }
        defer { try? FileManager.default.removeItem(at: f.home) }
        let postEpoch = await f.store.epoch()
        let postPause = DeterministicSuspension()
        f.host._setLifecycleTestHooks(.init(beforePostGateEffects: { await postPause.pause() }))
        let post = Task { await f.host.finishPostUnlock(expectedEpoch: postEpoch) }
        await postPause.waitUntilEntered()
        await f.store.lock(); f.host.onVaultLocked()
        let next = try await f.store.unlock(deferReady: true)
        f.host._setLifecycleTestHooks(.init())
        await postPause.release()
        #expect(await post.value == false)
        #expect(await f.store.phaseNow() == .unlocking)
        #expect(try #require(await f.host.activateUnlockedVault(expectedEpoch: next)).isEmpty)

        await f.store.quarantine()
        let adoptEpoch = await f.store.epoch()
        let adoptPause = DeterministicSuspension()
        f.host._setLifecycleTestHooks(.init(beforeReadoptCommit: { await adoptPause.pause() }))
        let adopt = Task { await f.host.readoptIntegrity() }
        await adoptPause.waitUntilEntered()
        await f.store.lock(); f.host.onVaultLocked()
        _ = try await f.store.unlock(deferReady: true)
        f.host._setLifecycleTestHooks(.init())
        await adoptPause.release()
        #expect(await adopt.value == false)
        #expect(await f.store.phaseNow() == .unlocking)
        #expect(await f.store.epoch() != adoptEpoch)
        await f.store.close()
    }

    @Test("concurrent mutations produce one ordered generation/anchor/floor sequence")
    func concurrentMutationsAreGloballyOrdered() async throws {
        let f = try await fixture(); defer { f.host.stop() }
        defer { try? FileManager.default.removeItem(at: f.home) }
        try await withThrowingTaskGroup(of: Void.self) { group in
            for i in 0..<32 {
                group.addTask {
                    try await f.host.commitMutation {
                        try await f.store.setBlob(key: "concurrent.\(i)", data: Data("\(i)".utf8))
                    }
                }
            }
            try await group.waitForAll()
        }
        #expect(try await f.host.dbGeneration() == 32)
        let floor = try await f.store.anchorCounterFloor()
        let (anchor, history) = f.anchors.snapshot()
        #expect(anchor?.generation == 32)
        #expect(anchor?.counter == floor)
        #expect(history.map(\.counter) == Array(1...33).map(Int64.init))
        #expect(anchor?.stateDigest == (try await f.store.trustDigest()))
        await f.store.close()
    }

    @Test("checkpoint failure or partial failed mutation freezes the vault")
    func failuresQuarantine() async throws {
        let f = try await fixture(); defer { f.host.stop() }
        defer { try? FileManager.default.removeItem(at: f.home) }

        await #expect(throws: IntegrityInjectedFailure.operation) {
            try await f.host.commitMutation {
                throw IntegrityInjectedFailure.operation
            }
        }
        #expect(await f.store.phaseNow() == .ready,
                "a validation failure with an unchanged digest is safe to return")

        await #expect(throws: IntegrityInjectedFailure.operation) {
            try await f.host.commitMutation {
                try await f.store.setBlob(key: "partial", data: Data("landed".utf8))
                throw IntegrityInjectedFailure.operation
            }
        }
        #expect(await f.store.phaseNow() == .quarantined)
        await f.store.close()
    }

    @Test("anchor save/load faults are fail-closed, never best-effort")
    func anchorFaultsFailClosed() async throws {
        let saveFixture = try await fixture(); defer { saveFixture.host.stop() }
        defer { try? FileManager.default.removeItem(at: saveFixture.home) }
        saveFixture.anchors.failSave(true)
        await #expect(throws: IntegrityInjectedFailure.save) {
            try await saveFixture.host.commitMutation {
                try await saveFixture.store.setBlob(key: "must-anchor", data: Data([1]))
            }
        }
        #expect(await saveFixture.store.phaseNow() == .quarantined)
        await saveFixture.store.close()

        let loadFixture = try await fixture(); defer { loadFixture.host.stop() }
        defer { try? FileManager.default.removeItem(at: loadFixture.home) }
        await loadFixture.store.lock(); loadFixture.host.onVaultLocked()
        let epoch = try await loadFixture.store.unlock(deferReady: true)
        loadFixture.anchors.failLoad(true)
        let issues = try #require(await loadFixture.host.activateUnlockedVault(expectedEpoch: epoch))
        #expect(issues.map(\.code).contains("trust-state-unreadable"))
        #expect(await loadFixture.store.phaseNow() == .quarantined)
        await loadFixture.store.close()
    }

    @Test("generation, anchor, lifecycle and digest overflow/error paths cannot trap")
    func countersAndDigestFailSafely() async throws {
        let generationFixture = try await fixture(); defer { generationFixture.host.stop() }
        defer { try? FileManager.default.removeItem(at: generationFixture.home) }
        try await generationFixture.store.setBlob(
            key: VaultStore.generationBlobKey, data: try JSONEncoder().encode(Int64.max))
        await #expect(throws: VaultHost.IntegrityTransactionError.generationExhausted) {
            try await generationFixture.host.commitMutation {
                try await generationFixture.store.setBlob(
                    key: "must-not-land-after-generation-exhaustion", data: Data([1]))
            }
        }
        #expect(try await generationFixture.store.blob(
            key: "must-not-land-after-generation-exhaustion") == nil)
        #expect(await generationFixture.store.phaseNow() == .quarantined)
        await generationFixture.store.close()

        let anchorFixture = try await fixture(); defer { anchorFixture.host.stop() }
        defer { try? FileManager.default.removeItem(at: anchorFixture.home) }
        let current = try #require(anchorFixture.anchors.snapshot().0)
        anchorFixture.anchors.replace(AnchorState(
            counter: .max, headSeq: current.headSeq, headHash: current.headHash,
            generation: current.generation, stateDigest: current.stateDigest,
            ts: current.ts, sig: current.sig))
        await #expect(throws: AnchorStoreError.invalidState) {
            try await anchorFixture.host.commitMutation {
                try await anchorFixture.store.setBlob(
                    key: "must-not-land-after-anchor-exhaustion", data: Data([1]))
            }
        }
        #expect(try await anchorFixture.store.blob(
            key: "must-not-land-after-anchor-exhaustion") == nil)
        #expect(await anchorFixture.store.phaseNow() == .quarantined)
        await anchorFixture.store.close()

        let lifecycleFixture = try await fixture(); defer { lifecycleFixture.host.stop() }
        defer { try? FileManager.default.removeItem(at: lifecycleFixture.home) }
        await lifecycleFixture.store._setLifecycleEpochForTesting(Int64.max - 1)
        await lifecycleFixture.store.lock()
        await #expect(throws: VaultStoreError.lifecycleExhausted) {
            _ = try await lifecycleFixture.store.unlock()
        }
        await lifecycleFixture.store.close()

        let digestFixture = try await fixture(); defer { digestFixture.host.stop() }
        defer { try? FileManager.default.removeItem(at: digestFixture.home) }
        await digestFixture.store.close()
        await #expect(throws: VaultStoreError.self) {
            _ = try await digestFixture.store.trustDigest()
        }
    }

    @Test("malformed DEKs and post-close database access fail without force unwrap or stale handles")
    func invalidDEKAndClosedHandleFailSafely() async throws {
        #expect(try VaultStore.checkedSQLiteByteCount(0) == 0)
        #expect(try VaultStore.checkedSQLiteByteCount(1_024) == 1_024)
        #expect(throws: VaultStoreError.sql(
            "SQLite returned a negative byte count for test")) {
            _ = try VaultStore.checkedSQLiteByteCount(-1, context: "test")
        }
        #expect(throws: VaultStoreError.sql(
            "SQLite test exceeds the vault value limit")) {
            _ = try VaultStore.checkedSQLiteByteCount(.max, context: "test")
        }
        #expect(throws: VaultStoreError.io(
            "test exceeds the vault value limit")) {
            try VaultStore.validatePlaintextByteCount(
                VaultStore.maximumPlaintextBytes + 1, context: "test")
        }

        let home = URL(fileURLWithPath: "/tmp/spdek-\(UUID().uuidString.prefix(8))",
                       isDirectory: true)
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: home) }
        let url = home.appendingPathComponent("vault.db")

        let created = try VaultStore(creatingAt: url, keystore: InvalidLengthKeystore())
        await created.close()
        let reopened = try VaultStore(openingAt: url, keystore: InvalidLengthKeystore())
        await #expect(throws: VaultStoreError.invalidIntegrityState(
            "wrapped DEK has an invalid length")) {
            _ = try await reopened.unlock()
        }
        #expect(await reopened.phaseNow() == .locked)
        await reopened.close()
        await #expect(throws: VaultStoreError.io("vault database is closed")) {
            _ = try await reopened.unlock()
        }
        #expect(await reopened.auditRecipient() == nil)
    }

    @Test("vault database path rejects parent redirects, symlinks, hardlinks, and FIFOs")
    func vaultDatabaseFilesystemBoundary() throws {
        let root = URL(fileURLWithPath: "/tmp/spdb-\(UUID().uuidString.prefix(8))",
                       isDirectory: true)
        try FileManager.default.createDirectory(
            at: root, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }

        func privateDirectory(_ name: String) throws -> URL {
            let dir = root.appendingPathComponent(name, isDirectory: true)
            try FileManager.default.createDirectory(
                at: dir, withIntermediateDirectories: false,
                attributes: [.posixPermissions: 0o700])
            return dir
        }

        let real = try privateDirectory("real")
        let redirected = root.appendingPathComponent("redirected", isDirectory: true)
        try FileManager.default.createSymbolicLink(at: redirected, withDestinationURL: real)
        #expect(throws: VaultStoreError.self) {
            _ = try VaultStore(creatingAt: redirected.appendingPathComponent("vault.db"),
                               keystore: FileAgeKeystore())
        }

        let writable = try privateDirectory("writable")
        try FileManager.default.setAttributes([.posixPermissions: 0o777],
                                              ofItemAtPath: writable.path)
        #expect(throws: VaultStoreError.self) {
            _ = try VaultStore(creatingAt: writable.appendingPathComponent("vault.db"),
                               keystore: FileAgeKeystore())
        }

        let symlinkDir = try privateDirectory("symlink")
        let symlinkTarget = root.appendingPathComponent("symlink-target")
        let sentinel = Data("must-remain-untouched".utf8)
        try sentinel.write(to: symlinkTarget)
        try FileManager.default.createSymbolicLink(
            at: symlinkDir.appendingPathComponent("vault.db"),
            withDestinationURL: symlinkTarget)
        #expect(throws: VaultStoreError.self) {
            _ = try VaultStore(creatingAt: symlinkDir.appendingPathComponent("vault.db"),
                               keystore: FileAgeKeystore())
        }
        #expect(try Data(contentsOf: symlinkTarget) == sentinel)

        let hardlinkDir = try privateDirectory("hardlink")
        let hardlinkTarget = root.appendingPathComponent("hardlink-target")
        try sentinel.write(to: hardlinkTarget)
        try FileManager.default.setAttributes([.posixPermissions: 0o600],
                                              ofItemAtPath: hardlinkTarget.path)
        #expect(Darwin.link(hardlinkTarget.path,
                            hardlinkDir.appendingPathComponent("vault.db").path) == 0)
        #expect(throws: VaultStoreError.self) {
            _ = try VaultStore(creatingAt: hardlinkDir.appendingPathComponent("vault.db"),
                               keystore: FileAgeKeystore())
        }
        #expect(try Data(contentsOf: hardlinkTarget) == sentinel)

        let fifoDir = try privateDirectory("fifo")
        let fifo = fifoDir.appendingPathComponent("vault.db")
        #expect(Darwin.mkfifo(fifo.path, mode_t(0o600)) == 0)
        #expect(throws: VaultStoreError.self) {
            _ = try VaultStore(creatingAt: fifo, keystore: FileAgeKeystore())
        }
    }

    @Test("an opened vault detects final-file and parent-directory path swaps before reuse")
    func openedVaultDetectsPathSwap() async throws {
        let root = URL(fileURLWithPath: "/tmp/spdbswap-\(UUID().uuidString.prefix(8))",
                       isDirectory: true)
        try FileManager.default.createDirectory(
            at: root, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }

        let fileDir = root.appendingPathComponent("file", isDirectory: true)
        try FileManager.default.createDirectory(
            at: fileDir, withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700])
        let fileURL = fileDir.appendingPathComponent("vault.db")
        let fileStore = try VaultStore(creatingAt: fileURL, keystore: FileAgeKeystore())
        let movedFile = fileDir.appendingPathComponent("moved.db")
        try FileManager.default.moveItem(at: fileURL, to: movedFile)
        try FileManager.default.createSymbolicLink(at: fileURL, withDestinationURL: movedFile)
        await #expect(throws: VaultStoreError.self) {
            try await fileStore.setBlob(key: "must-not-write", data: Data([1]))
        }
        await fileStore.close()

        let parentDir = root.appendingPathComponent("parent", isDirectory: true)
        try FileManager.default.createDirectory(
            at: parentDir, withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700])
        let parentStore = try VaultStore(
            creatingAt: parentDir.appendingPathComponent("vault.db"),
            keystore: FileAgeKeystore())
        let movedParent = root.appendingPathComponent("parent-moved", isDirectory: true)
        try FileManager.default.moveItem(at: parentDir, to: movedParent)
        try FileManager.default.createDirectory(
            at: parentDir, withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700])
        await #expect(throws: VaultStoreError.self) {
            try await parentStore.setBlob(key: "must-not-write", data: Data([1]))
        }
        await parentStore.close()
    }

    @Test("two consecutive interrupted rekeys preserve the original durable recovery wrapper")
    func repeatedInterruptedRekeyDoesNotBrickVault() async throws {
        let root = URL(fileURLWithPath: "/tmp/sprekey-\(UUID().uuidString.prefix(8))",
                       isDirectory: true)
        try FileManager.default.createDirectory(
            at: root, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let url = root.appendingPathComponent("vault.db")
        let original = FileAgeKeystore()

        let first = try VaultStore(creatingAt: url, keystore: original)
        try await first.set(SecretMeta(name: "survivor", kind: "bearer"),
                            value: Data("still-readable".utf8))
        try await first.rekey(to: FileAgeKeystore())
        // Crash before keystore.json replacement/finalizeRekey.
        await first.close()

        let second = try VaultStore(openingAt: url, keystore: original)
        _ = try await second.unlock() // recovers through the original wrapper
        try await second.rekey(to: FileAgeKeystore())
        // A second failed replacement must not have replaced original with the
        // first uncommitted wrapper.
        await second.close()

        let recovered = try VaultStore(openingAt: url, keystore: original)
        _ = try await recovered.unlock()
        #expect(try await recovered.secretValue(name: "survivor") ==
                Data("still-readable".utf8))
        await recovered.close()
    }

    @Test("the recording async-to-sync bridge times out instead of hanging its worker")
    func recordingSyncBridgeIsBounded() {
        let (neverResult, resultContinuation) = AsyncStream<Void>.makeStream()
        defer { resultContinuation.finish() }
        let started = Date()
        let result: Result<Int, any Error> = syncAwaitResult({
            for await _ in neverResult { }
            return 1
        }, timeout: 0.01)
        switch result {
        case .success:
            Issue.record("a never-completing operation unexpectedly succeeded")
        case .failure(let error):
            #expect(String(describing: error).contains("timed out"))
        }
        #expect(Date().timeIntervalSince(started) < 0.5)
    }

    @Test("anchor persistence rejects redirected or unsafe parent directories")
    func anchorParentIsPinnedAndOwned() throws {
        let root = URL(fileURLWithPath: "/tmp/span-\(UUID().uuidString.prefix(8))", isDirectory: true)
        let real = root.appendingPathComponent("real", isDirectory: true)
        let redirected = root.appendingPathComponent("redirected", isDirectory: true)
        try FileManager.default.createDirectory(at: real, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createSymbolicLink(at: redirected, withDestinationURL: real)
        let state = AnchorState(counter: 1, headSeq: 0, headHash: AuditLog.genesisPrev,
                                generation: 0, ts: AuditLog.timestamp())
        let redirectedStore = FileAnchorStore(url: redirected.appendingPathComponent("anchor.json"))
        #expect(throws: AnchorStoreError.unsafeParent) { try redirectedStore.save(state) }
        #expect(throws: AnchorStoreError.unsafeParent) { _ = try redirectedStore.load() }

        try FileManager.default.setAttributes([.posixPermissions: 0o777], ofItemAtPath: real.path)
        let writableStore = FileAnchorStore(url: real.appendingPathComponent("anchor.json"))
        #expect(throws: AnchorStoreError.unsafeParent) { try writableStore.save(state) }

        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: real.path)
        let target = root.appendingPathComponent("target")
        try Data("do-not-touch".utf8).write(to: target)
        try FileManager.default.createSymbolicLink(
            at: real.appendingPathComponent("anchor.json"), withDestinationURL: target)
        #expect(throws: AnchorStoreError.unsafeFile) { try writableStore.save(state) }
        #expect((try Data(contentsOf: target)) == Data("do-not-touch".utf8))
    }

    @Test("manual lock checkpoints its boundary and re-adopt never lowers the sealed floor")
    func lockAndReadoptKeepCountersPaired() async throws {
        let lockFixture = try await fixture(); defer { lockFixture.host.stop() }
        defer { try? FileManager.default.removeItem(at: lockFixture.home) }
        #expect(lockFixture.anchors.snapshot().0?.counter == 1)
        await lockFixture.host.lockVault()
        #expect(await lockFixture.store.phaseNow() == .locked)
        let epoch = try await lockFixture.store.unlock(deferReady: true)
        #expect(try await lockFixture.store.anchorCounterFloor(expectedEpoch: epoch) == 2)
        #expect(lockFixture.anchors.snapshot().0?.counter == 2)
        #expect(try #require(await lockFixture.host.activateUnlockedVault(expectedEpoch: epoch)).isEmpty)
        await lockFixture.store.close()

        let adoptFixture = try await fixture(); defer { adoptFixture.host.stop() }
        defer { try? FileManager.default.removeItem(at: adoptFixture.home) }
        let highFloor = try JSONEncoder().encode(Int64(50))
        try await adoptFixture.store.setBlob(key: VaultStore.anchorFloorBlobKey, data: highFloor)
        await adoptFixture.store.quarantine()
        #expect(await adoptFixture.host.readoptIntegrity())
        #expect(adoptFixture.anchors.snapshot().0?.counter == 51)
        #expect(try await adoptFixture.store.anchorCounterFloor() == 51)
        await adoptFixture.store.close()
    }

    @Test("a cancelled mutation waiting for the global commit gate never executes later")
    func cancelledQueuedMutationDoesNotLand() async throws {
        let f = try await fixture(); defer { f.host.stop() }
        defer { try? FileManager.default.removeItem(at: f.home) }
        let pause = DeterministicSuspension()
        let first = Task {
            try await f.host.commitMutation {
                await pause.pause()
                try await f.store.setBlob(key: "first", data: Data([1]))
            }
        }
        await pause.waitUntilEntered()
        let cancelled = Task {
            try await f.host.commitMutation {
                try await f.store.setBlob(key: "cancelled", data: Data([2]))
            }
        }
        await Task.yield()
        cancelled.cancel()
        await pause.release()
        try await first.value
        await #expect(throws: CancellationError.self) { try await cancelled.value }
        #expect(try await f.store.blob(key: "cancelled") == nil)
        #expect(try await f.host.dbGeneration() == 1)
        await f.store.close()
    }

    @Test("a pre-biometric mutation token cannot cross lock and re-unlock")
    func mutationEpochCannotCrossRelock() async throws {
        let f = try await fixture(); defer { f.host.stop() }
        defer { try? FileManager.default.removeItem(at: f.home) }
        let approvedWorld = await f.store.epoch()
        await f.host.lockVault()
        let newWorld = try await f.store.unlock(deferReady: true)
        #expect(try #require(await f.host.activateUnlockedVault(expectedEpoch: newWorld)).isEmpty)
        await #expect(throws: VaultStoreError.locked) {
            try await f.host.commitMutation(expectedEpoch: approvedWorld) {
                try await f.store.setBlob(key: "stale-biometric", data: Data([1]))
            }
        }
        #expect(try await f.store.blob(key: "stale-biometric") == nil)
        #expect(try await f.host.dbGeneration() == 0)
        await f.store.close()
    }
}
