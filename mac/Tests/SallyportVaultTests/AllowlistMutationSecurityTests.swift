import Foundation
import Testing
@testable import SallyportVault

private enum AllowlistSinkFailure: Error, Equatable { case failed }

private actor AllowlistPersistenceProbe {
    private var active = 0
    private var peak = 0
    private var last: [String] = []

    func save(_ entries: [AllowlistEntry]) async {
        active += 1
        peak = max(peak, active)
        try? await Task.sleep(for: .milliseconds(2))
        last = entries.map(\.id)
        active -= 1
    }

    func result() -> (peak: Int, last: [String]) { (peak, last) }
}

private actor SuspendedAllowlistSink {
    private var currentEpoch: Int64
    private var started = false
    private var startWaiter: CheckedContinuation<Void, Never>?
    private var releaseWaiter: CheckedContinuation<Void, Never>?
    private(set) var persisted: [String]?

    init(epoch: Int64) { currentEpoch = epoch }

    func save(_ entries: [AllowlistEntry], expectedEpoch: Int64) async throws {
        started = true
        startWaiter?.resume()
        startWaiter = nil
        await withCheckedContinuation { releaseWaiter = $0 }
        guard currentEpoch == expectedEpoch else { throw VaultStoreError.locked }
        persisted = entries.map(\.id)
    }

    func waitUntilStarted() async {
        if started { return }
        await withCheckedContinuation { startWaiter = $0 }
    }

    func advance(to epoch: Int64) {
        currentEpoch = epoch
        releaseWaiter?.resume()
        releaseWaiter = nil
    }
}

@Suite("Agent allowlist — transactional mutation and lifecycle isolation")
struct AllowlistMutationSecurityTests {
    private func entry(_ id: String) -> AllowlistEntry {
        AllowlistEntry(id: id, label: id, kind: .cdhash, cdhashes: ["hash-\(id)"])
    }

    @Test("failed persistence never publishes an auto-approval change")
    func failedSinkRollsBack() async throws {
        let allowlist = Allowlist(matcher: { _, _, candidates in candidates.first })
        allowlist.hydrate([entry("existing")])
        allowlist.onPersist { _ in throw AllowlistSinkFailure.failed }

        await #expect(throws: AllowlistSinkFailure.failed) {
            try await allowlist.set(entry("unpersisted"))
        }
        #expect(allowlist.list().map(\.id) == ["existing"])

        await #expect(throws: AllowlistSinkFailure.failed) {
            _ = try await allowlist.delete("existing")
        }
        #expect(allowlist.list().map(\.id) == ["existing"])
    }

    @Test("concurrent add/delete snapshots persist in FIFO order without lost updates")
    func concurrentMutationsSerialize() async throws {
        let allowlist = Allowlist(matcher: { _, _, candidates in candidates.first })
        let probe = AllowlistPersistenceProbe()
        allowlist.onPersist { await probe.save($0) }

        try await withThrowingTaskGroup(of: Void.self) { group in
            for index in 0..<32 {
                group.addTask { try await allowlist.set(entry("agent-\(index)")) }
            }
            try await group.waitForAll()
        }
        let result = await probe.result()
        #expect(result.peak == 1)
        #expect(result.last == allowlist.list().map(\.id))
        #expect(allowlist.list().count == 32)
    }

    @Test("lock and re-unlock invalidate a suspended old-world mutation and late hydration")
    func lifecycleInvalidatesMutation() async throws {
        let allowlist = Allowlist(matcher: { _, _, candidates in candidates.first })
        allowlist.hydrate([entry("old")], lifecycleEpoch: 1)
        let sink = SuspendedAllowlistSink(epoch: 1)
        allowlist.onPersist { entries, epoch in
            try await sink.save(entries, expectedEpoch: epoch)
        }

        let oldMutation = Task { try await allowlist.set(entry("stale-edit")) }
        await sink.waitUntilStarted()
        allowlist.clear()
        allowlist.hydrate([entry("new-world")], lifecycleEpoch: 3)
        await sink.advance(to: 3)

        await #expect(throws: VaultStoreError.locked) { try await oldMutation.value }
        #expect(allowlist.list().map(\.id) == ["new-world"])
        #expect(await sink.persisted == nil)

        allowlist.hydrate([entry("late-old")], lifecycleEpoch: 1)
        #expect(allowlist.list().map(\.id) == ["new-world"])

        // Even the same epoch cannot replay after that epoch was once hydrated
        // and cleared; this is the exact late-task shape created by a lock.
        let replay = Allowlist(matcher: { _, _, candidates in candidates.first })
        replay.hydrate([entry("epoch-five")], lifecycleEpoch: 5)
        replay.clear()
        replay.hydrate([entry("replayed")], lifecycleEpoch: 5)
        #expect(replay.list().isEmpty)
    }

    @Test("unusable entries are rejected before persistence")
    func unusableEntryRejected() async {
        let allowlist = Allowlist(matcher: { _, _, candidates in candidates.first })
        await #expect(throws: AllowlistMutationError.unusable) {
            try await allowlist.set(AllowlistEntry(
                id: "bad", label: "bad", kind: .cdhash, cdhashes: []))
        }
        #expect(allowlist.list().isEmpty)
    }
}
