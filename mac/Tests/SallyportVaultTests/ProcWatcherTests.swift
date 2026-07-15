import Darwin
import Foundation
import Testing
@testable import SallyportVault

/// Mailbox for keys delivered by the watcher's @Sendable onExit callback, with
/// a blocking timed wait (the Swift stand-in for the Go tests' channel).
private final class KeyInbox: @unchecked Sendable {
    private let sem = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private var keys: [String] = []

    func deliver(_ key: String) {
        lock.withLock { keys.append(key) }
        sem.signal()
    }

    /// The next delivered key, or nil if none arrives within the timeout.
    func wait(_ timeout: TimeInterval) -> String? {
        guard sem.wait(timeout: .now() + timeout) == .success else { return nil }
        return lock.withLock { keys.removeFirst() }
    }
}

/// Spawns a long-sleeping child and returns it with its pid + kernel start time
/// (captured through the ported provenance chain, like the Go tests).
private func startChild() throws -> (Process, Int, Int64) {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/bin/sleep")
    p.arguments = ["60"]
    try p.run()
    let pid = Int(p.processIdentifier)
    let origin = Provenance.chain(pid: pid).origin
    try #require(origin.pid == pid, "could not capture the child in its own chain")
    try #require(origin.startedAt != 0, "could not capture child start time")
    return (p, pid, origin.startedAt)
}

/// Kills and reaps a child (idempotent — safe on an already-gone process).
private func reap(_ p: Process) {
    kill(p.processIdentifier, SIGKILL)
    p.waitUntilExit()
}

// Serialized: these tests assert on real kernel event timing; running them in
// parallel makes the negative ("nothing may fire") windows flaky.
@Suite("ProcWatcher — kqueue NOTE_EXIT session expiry", .serialized)
struct ProcWatcherTests {

    // The headline: kill a watched process and the kernel-driven watcher expires
    // its session key promptly, no polling.
    @Test("a watched process's exit fires expiry exactly for its key")
    func exitFiresExpiry() throws {
        let inbox = KeyInbox()
        let w = try ProcWatcher { inbox.deliver($0) }
        defer { w.close() }

        let (p, pid, started) = try startChild()
        defer { reap(p) }
        w.watch(pid: pid, startedAt: started, key: "sess-live")

        // Not yet: the process is alive; nothing may fire.
        #expect(inbox.wait(0.15) == nil, "premature expiry for a live process")

        kill(pid_t(pid), SIGKILL)
        #expect(inbox.wait(3.0) == "sess-live", "watcher did not deliver the exit")
    }

    // Watching an already-exited process (or a recycled pid — same code path:
    // the alive check fails) expires immediately instead of waiting forever on a
    // registration that can never fire for that process.
    @Test("watching a dead-at-registration process expires immediately")
    func deadAtRegistration() throws {
        let inbox = KeyInbox()
        let w = try ProcWatcher { inbox.deliver($0) }
        defer { w.close() }

        let (p, pid, started) = try startChild()
        kill(pid_t(pid), SIGKILL)
        p.waitUntilExit() // fully reaped: the pid is gone

        w.watch(pid: pid, startedAt: started, key: "sess-dead")
        #expect(inbox.wait(3.0) == "sess-dead", "dead-at-registration must expire immediately")
    }

    // A manually revoked session's watch is disarmed — the later process exit
    // must not deliver an expiry.
    @Test("unwatch disarms: the later exit never fires")
    func unwatchNeverFires() throws {
        let inbox = KeyInbox()
        let w = try ProcWatcher { inbox.deliver($0) }
        defer { w.close() }

        let (p, pid, started) = try startChild()
        defer { reap(p) }
        w.watch(pid: pid, startedAt: started, key: "sess-revoked")
        w.unwatch(pid: pid)
        kill(pid_t(pid), SIGKILL)

        #expect(inbox.wait(0.4) == nil, "unwatched pid still fired")
    }

    // Wires a real watcher to a real store the way the engine does:
    // approve → process exits → session gone from the store.
    @Test("store + watcher integration: exit expires the approved session")
    func storeWatcherIntegration() throws {
        let s = SessionStore()
        let expired = KeyInbox()
        let w = try ProcWatcher { key in
            if let info = s.expire(key: key) {
                expired.deliver("\(info.pid)")
            }
        }
        defer { w.close() }
        s.watch = { w.watch(pid: $0, startedAt: $1, key: $2) }
        s.unwatch = { w.unwatch(pid: $0) }

        let (p, pid, started) = try startChild()
        defer { reap(p) }
        let o = Origin(pid: pid, startedAt: started,
                       name: "claude", path: "/usr/local/bin/claude",
                       signedBy: "Developer ID Application: Anthropic PBC (Q6L2SF6YDW)",
                       validSignature: true)
        s.approve(o)
        #expect(s.approved(o), "live child must be approved after approve")

        kill(pid_t(pid), SIGKILL)
        #expect(expired.wait(3.0) == "\(pid)", "session was not expired after the process exited")
        #expect(s.list().isEmpty, "store must be empty after expiry")
    }
}
