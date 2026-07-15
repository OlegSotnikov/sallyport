import Foundation
import Testing
@testable import SallyportVault

private enum ExpectedPersistenceFailure: Error, Equatable { case failed }

private actor PersistenceProbe<Value: Sendable> {
    private var active = 0
    private var peak = 0
    private var last: Value?

    func save(_ value: Value) async {
        active += 1
        peak = max(peak, active)
        try? await Task.sleep(for: .milliseconds(2))
        last = value
        active -= 1
    }

    func result() -> (peak: Int, last: Value?) { (peak, last) }
}

private actor SuspendedLifecycleSink<Value: Sendable> {
    private var currentEpoch: Int64
    private var started = false
    private var startedWaiter: CheckedContinuation<Void, Never>?
    private var releaseWaiter: CheckedContinuation<Void, Never>?
    private(set) var persisted: Value?

    init(epoch: Int64) { currentEpoch = epoch }

    func save(_ value: Value, expectedEpoch: Int64) async throws {
        started = true
        startedWaiter?.resume()
        startedWaiter = nil
        await withCheckedContinuation { releaseWaiter = $0 }
        guard expectedEpoch == currentEpoch else { throw VaultStoreError.locked }
        persisted = value
    }

    func waitUntilStarted() async {
        if started { return }
        await withCheckedContinuation { startedWaiter = $0 }
    }

    func moveLifecycle(to epoch: Int64) {
        currentEpoch = epoch
        releaseWaiter?.resume()
        releaseWaiter = nil
    }
}

@Suite("Vault-backed configuration — transactional persistence races")
struct PersistenceRaceTests {
    @Test("an old mutation cannot persist or publish across clear and a newer hydration")
    func lifecycleInvalidatesQueuedMutation() async throws {
        let hosts = HostsStore()
        hosts.hydrate([.init(name: "old", addr: "10.0.0.1")], lifecycleEpoch: 1)
        let sink = SuspendedLifecycleSink<[String]>(epoch: 1)
        hosts.onPersist { entries, epoch in
            try await sink.save(entries.map(\.name), expectedEpoch: epoch)
        }

        let oldMutation = Task {
            try await hosts.set(.init(name: "stale-edit", addr: "10.0.0.2"))
        }
        await sink.waitUntilStarted()

        // Model lock → unlock/hydrate while the old sink is suspended. The
        // local generation blocks stale publication; the lifecycle token also
        // blocks the more dangerous stale *disk write*.
        hosts.clear()
        hosts.hydrate([.init(name: "new-world", addr: "10.0.0.3")], lifecycleEpoch: 3)
        await sink.moveLifecycle(to: 3)
        await #expect(throws: VaultStoreError.locked) { try await oldMutation.value }
        #expect(hosts.list().map(\.name) == ["new-world"])
        #expect(await sink.persisted == nil)

        // A late hydration task from the older unlock is ignored too.
        hosts.hydrate([.init(name: "late-old", addr: "10.0.0.4")], lifecycleEpoch: 1)
        #expect(hosts.list().map(\.name) == ["new-world"])

        // The real actor performs the epoch comparison and SQLite upsert as one
        // non-reentrant operation; an old epoch cannot write after re-unlock.
        let root = URL(fileURLWithPath: "/tmp/sp-epoch-\(UUID().uuidString.prefix(8))", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let vault = try VaultStore(creatingAt: root.appendingPathComponent("vault.db"),
                                   keystore: FileAgeKeystore())
        let originalEpoch = await vault.epoch()
        try await vault.setBlob(key: "epoch-test", data: Data("old".utf8),
                                expectedEpoch: originalEpoch)
        await vault.lock()
        try await vault.unlock()
        await #expect(throws: VaultStoreError.locked) {
            try await vault.setBlob(key: "epoch-test", data: Data("stale".utf8),
                                    expectedEpoch: originalEpoch)
        }
        #expect(try await vault.blob(key: "epoch-test") == Data("old".utf8))
        await vault.close()
    }

    @Test("a failed sink never publishes an unpersisted host, upstream, or security downgrade")
    func failedPersistenceRollsBackMemory() async {
        let hosts = HostsStore()
        hosts.onPersist { _ in throw ExpectedPersistenceFailure.failed }
        await #expect(throws: ExpectedPersistenceFailure.failed) {
            try await hosts.set(.init(name: "prod", addr: "10.0.0.4"))
        }
        #expect(hosts.get("prod") == nil)

        let upstreams = UpstreamsStore()
        upstreams.onPersist { _ in throw ExpectedPersistenceFailure.failed }
        await #expect(throws: ExpectedPersistenceFailure.failed) {
            try await upstreams.set(.init(name: "github", command: "npx"))
        }
        #expect(upstreams.get("github") == nil)

        let settings = SettingsStore()
        settings.onPersist { _ in throw ExpectedPersistenceFailure.failed }
        await #expect(throws: ExpectedPersistenceFailure.failed) {
            try await settings.update { $0.sessionAuth = SettingsStore.sessionAuthOff }
        }
        #expect(settings.sessionAuth() == SettingsStore.sessionAuthClick,
                "a failed disk write must not leave the live engine in observe mode")
    }

    @Test("a failed delete leaves the live configuration present")
    func failedDeleteRollsBackMemory() async throws {
        let hosts = HostsStore(entries: [.init(name: "prod", addr: "10.0.0.4")])
        hosts.onPersist { _ in throw ExpectedPersistenceFailure.failed }
        await #expect(throws: ExpectedPersistenceFailure.failed) {
            _ = try await hosts.delete("prod")
        }
        #expect(hosts.get("prod") != nil)

        let upstreams = UpstreamsStore(entries: [.init(name: "github", command: "npx")])
        upstreams.onPersist { _ in throw ExpectedPersistenceFailure.failed }
        await #expect(throws: ExpectedPersistenceFailure.failed) {
            _ = try await upstreams.delete("github")
        }
        #expect(upstreams.get("github") != nil)
    }

    @Test("concurrent host writes serialize; the last persisted snapshot equals live memory")
    func concurrentHostsPersistInOrder() async throws {
        let hosts = HostsStore()
        let probe = PersistenceProbe<[String]>()
        hosts.onPersist { entries in await probe.save(entries.map(\.name)) }

        try await withThrowingTaskGroup(of: Void.self) { group in
            for i in 0..<32 {
                group.addTask {
                    try await hosts.set(.init(name: "h\(i)", addr: "10.0.0.\(i)"))
                }
            }
            try await group.waitForAll()
        }
        let result = await probe.result()
        let live = hosts.list().map(\.name)
        #expect(result.peak == 1, "vault writes must never overlap and finish out of order")
        #expect(result.last == live)
        #expect(live.count == 32)
    }

    @Test("concurrent upstream and settings writes use the same single-writer contract")
    func otherStoresPersistInOrder() async throws {
        let upstreams = UpstreamsStore()
        let upstreamProbe = PersistenceProbe<[String]>()
        upstreams.onPersist { entries in await upstreamProbe.save(entries.map(\.name)) }
        try await withThrowingTaskGroup(of: Void.self) { group in
            for i in 0..<16 {
                group.addTask {
                    try await upstreams.set(.init(name: "u\(i)", command: "cmd"))
                }
            }
            try await group.waitForAll()
        }
        let upstreamResult = await upstreamProbe.result()
        #expect(upstreamResult.peak == 1)
        #expect(upstreamResult.last == upstreams.list().map(\.name))

        let settings = SettingsStore()
        let settingsProbe = PersistenceProbe<Int>()
        settings.onPersist { state in await settingsProbe.save(state.autoLockMinutes ?? -1) }
        try await withThrowingTaskGroup(of: Void.self) { group in
            for i in 1...16 {
                group.addTask { try await settings.update { $0.autoLockMinutes = i } }
            }
            try await group.waitForAll()
        }
        let settingsResult = await settingsProbe.result()
        #expect(settingsResult.peak == 1)
        #expect(settingsResult.last == settings.snapshot().autoLockMinutes)
    }

    @Test("legacy upstream records decode to secure modern defaults")
    func legacyUpstreamDecode() throws {
        let legacy = Data(#"{"name":"old","command":"npx","args":["server"],"env":{"MODE":"safe"},"keys":[]}"#.utf8)
        let entry = try JSONDecoder().decode(UpstreamsStore.Entry.self, from: legacy)
        #expect(entry.transport == UpstreamsStore.Entry.stdioTransport)
        #expect(entry.auth == UpstreamsStore.Entry.apiKeyAuth)
        #expect(entry.confirm.isEmpty)
        #expect(entry.enabled)
        #expect(entry.url.isEmpty)
        #expect(!entry.usesOAuth)
    }

    @Test("extreme auto-lock input is bounded arithmetic, never an Int trap")
    func extremeAutoLockTTL() async throws {
        let settings = SettingsStore(initial: SettingsState(autoLockMinutes: Int.max))
        let ttl = settings.autoLockTTL()
        #expect(ttl != nil)
        #expect(ttl?.isFinite == true)
        #expect((ttl ?? 0) > 0)

        let root = URL(fileURLWithPath: "/tmp/sp-ttl-\(UUID().uuidString.prefix(8))", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let store = try VaultStore(creatingAt: root.appendingPathComponent("vault.db"),
                                   keystore: FileAgeKeystore())
        await store.setAutoLockTTL(.infinity)
        #expect(await store.remaining() > 0, "infinity must fold to the safe default")
        await store.setAutoLockTTL(.nan)
        #expect(await store.remaining() > 0, "NaN must fold to the safe default")
        await store.setAutoLockTTL(.greatestFiniteMagnitude)
        let huge = await store.remaining()
        #expect(huge > 0 && huge <= Int.max)
        await store.close()
    }
}
