import Foundation
import Testing
@testable import SallyportVault

/// The canonical origin fixture (mirrors `claudeOrigin` in the Go tests).
private func claudeOrigin() -> Origin {
    Origin(pid: 4242, startedAt: 1_000_000,
           name: "claude", path: "/usr/local/bin/claude",
           signedBy: "Developer ID Application: Anthropic PBC (Q6L2SF6YDW)",
           validSignature: true)
}

/// Minimal mutex box so tests can record from the store's @Sendable hooks
/// without data races.
private final class LockedBox<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: Value
    init(_ value: Value) { stored = value }
    var value: Value { lock.withLock { stored } }
    func withLock<R>(_ body: (inout Value) -> R) -> R {
        lock.lock()
        defer { lock.unlock() }
        return body(&stored)
    }
}

@Suite("SessionStore — live agent sessions")
struct SessionStoreTests {

    // An approved live process is trusted on later calls (the whole point —
    // approve once, work freely).
    @Test("approve → the same live process is covered")
    func approveThenCovered() {
        let s = SessionStore()
        let o = claudeOrigin()
        #expect(!s.approved(o), "a fresh process must not be pre-approved")
        s.approve(o)
        #expect(s.approved(o), "the same live process must be covered after approval")
    }

    // The core safety property: a new process that inherits an old,
    // still-approved PID has a different start time, so it is NOT silently
    // trusted — it must get its own approval.
    @Test("a reused PID (different start time) is NOT trusted")
    func pidReuseIsNotTrusted() {
        let s = SessionStore()
        let approved = claudeOrigin()
        s.approve(approved)

        var reused = approved
        reused.startedAt = 2_000_000 // same PID, different process (OS recycled the number)
        reused.path = "/tmp/not-claude"
        reused.signedBy = ""
        #expect(!s.approved(reused),
                "a reused PID (different start time) must NOT inherit the approved session")
        // The genuine process is still trusted.
        #expect(s.approved(approved), "the original live process must remain trusted")
    }

    // Same (pid,start) but a different signing authority than what was approved
    // is refused and the stale entry dropped.
    @Test("signature drift at the same pid/start invalidates the session (fail-closed)")
    func signatureDriftInvalidates() {
        let s = SessionStore()
        let o = claudeOrigin()
        s.approve(o)

        var drift = o
        drift.signedBy = "Developer ID Application: Someone Else"
        #expect(!s.approved(drift), "a signer mismatch at the same pid/start must not be trusted")
        // And it was invalidated — even the original snapshot no longer matches.
        #expect(!s.approved(o), "a drift must invalidate the session (fail-closed)")
    }

    // An origin with no pinnable pid/start (e.g. a direct CLI call) can't be
    // session-trusted at all — it falls back to per-service confirmation.
    @Test("an origin without pid+start can never be sessioned")
    func unidentifiableNotSessioned() {
        let s = SessionStore()
        let blank = Origin(name: "sp") // no PID / no start time
        #expect(!s.identifiable(blank), "an origin without pid+start must not be identifiable")
        s.approve(blank) // no-op
        #expect(!s.approved(blank), "a blank origin must never be considered approved")
        #expect(s.list().isEmpty, "approving a blank origin must store nothing")
    }

    // Locking the vault (clear) drops all sessions — nothing outlives the vault.
    @Test("clear ends every session (vault lock)")
    func clearRevokesEverything() {
        let s = SessionStore()
        s.approve(claudeOrigin())
        #expect(s.list().count == 1)
        s.clear()
        #expect(!s.approved(claudeOrigin()) && s.list().isEmpty, "clear must revoke every session")
        #expect(s.history().first?.reason == .vaultLocked)
    }

    // expire removes the session and hands back its info for the activity
    // trail — exactly once (idempotent on a gone key).
    @Test("expire returns the info exactly once")
    func expireReturnsInfoOnce() throws {
        let s = SessionStore()
        s.approve(claudeOrigin())
        let key = try #require(s.list().first).key

        let info = try #require(s.expire(key: key), "expire should return the session info")
        #expect(info.pid == 4242)
        #expect(info.name == "claude")
        #expect(info.reason == .exited)
        #expect(info.endedAt != nil)
        #expect(s.expire(key: key) == nil, "a second expire of the same key must be a no-op")
        #expect(!s.approved(claudeOrigin()), "an expired session must no longer be trusted")
    }

    // The sweeper removes sessions whose exact process is gone and keeps the
    // live ones.
    @Test("sweep expires only dead processes")
    func sweepExpiresOnlyDeadProcesses() throws {
        let s = SessionStore()
        let live = claudeOrigin()
        var dead = claudeOrigin()
        dead.pid = 5151
        dead.startedAt = 2_000_000
        s.approve(live)
        s.approve(dead)

        let gone = s.sweep { pid, _ in pid == live.pid }
        #expect(gone.count == 1)
        #expect(gone.first?.pid == dead.pid, "sweep should expire exactly the dead session")
        #expect(s.approved(live), "the live session must survive the sweep")
        #expect(!s.approved(dead), "the dead session must be gone after the sweep")
    }

    // approve arms the watcher, revoke/clear disarm it — the wiring contract
    // the engine relies on.
    @Test("approve arms the watch hook; revoke/clear disarm it")
    func hooksFire() throws {
        let s = SessionStore()
        let watched = LockedBox<[Int]>([])
        let unwatched = LockedBox<[Int]>([])
        s.watch = { pid, _, _ in watched.withLock { $0.append(pid) } }
        s.unwatch = { pid in unwatched.withLock { $0.append(pid) } }

        let o = claudeOrigin()
        s.approve(o)
        #expect(watched.value == [o.pid], "approve must arm the watcher for the pid")

        let key = try #require(s.list().first).key
        s.revoke(key: key)
        #expect(unwatched.value == [o.pid], "revoke must disarm the pid")

        s.approve(o)
        s.clear()
        #expect(unwatched.value == [o.pid, o.pid], "clear must disarm every session")
    }

    // The UI can revoke a single session by its listed key.
    @Test("revoke by listed key")
    func revokeByKey() throws {
        let s = SessionStore()
        s.approve(claudeOrigin())
        let list = s.list()
        #expect(list.count == 1)
        let key = try #require(list.first).key
        #expect(s.revoke(key: key), "revoke of an existing key should return true")
        #expect(!s.approved(claudeOrigin()), "a revoked session must no longer be trusted")
        #expect(!s.revoke(key: key), "revoking a gone key should return false")
    }

    // Status only ever upgrades: observed < per-call < approved.
    @Test("admission status is upgrade-only")
    func statusUpgradeOnly() {
        let s = SessionStore()
        let o = claudeOrigin()
        s.observe(o)
        #expect(!s.approved(o), "observed does not satisfy the session gate")
        #expect(s.list().first?.status == .observed)
        s.approveViaCall(o)
        #expect(s.approved(o))
        #expect(s.list().first?.status == .perCall)
        s.observe(o) // never downgrades
        #expect(s.list().first?.status == .perCall)
        s.approve(o)
        #expect(s.list().first?.status == .approved)
        s.approveViaCall(o) // never downgrades an approved
        #expect(s.list().first?.status == .approved)
    }

    @Test("countCall increments the live session's counter (best-effort)")
    func countCallIncrements() {
        let s = SessionStore()
        let o = claudeOrigin()
        s.countCall(o) // no session yet: silent no-op
        s.approve(o)
        s.countCall(o)
        s.countCall(o)
        #expect(s.list().first?.calls == 2)
    }

    // The journal is a bounded ring, newest first, and the key is the
    // reuse-proof "<pid>:<startedAt>".
    @Test("history: newest first, bounded at the ring cap")
    func historyBoundedRing() throws {
        #expect(SessionStore.sessionKey(claudeOrigin()) == "4242:1000000")

        let s = SessionStore()
        for i in 0..<210 {
            var o = claudeOrigin()
            o.pid = 10_000 + i
            s.approve(o)
            s.revoke(key: try #require(SessionStore.sessionKey(o)))
        }
        let history = s.history()
        #expect(history.count == 200, "the journal must stay bounded")
        #expect(history.first?.pid == 10_209, "newest entry first")
        #expect(history.first?.reason == .revoked)
    }
}
