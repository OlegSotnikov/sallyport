import Foundation

/// Live agent sessions keyed by process ID and kernel start time. Each call
/// rechecks the executable path and signing authority captured at admission.
/// Sessions can be approved, admitted by a per-call approval, or observed when
/// session approval is disabled. They end on process exit, revocation, or lock.

// MARK: - Status & journal vocabulary

/// How a session was admitted. Ordered by admission strength:
/// `admit` upgrades status in the order observed, per-call, approved.
public enum SessionStatus: String, Sendable, Codable, Hashable, Comparable {
    case observed = "observed"
    case perCall = "per-call"
    case approved = "approved"

    private var rank: Int {
        switch self {
        case .observed: return 0
        case .perCall: return 1
        case .approved: return 2
        }
    }

    public static func < (lhs: SessionStatus, rhs: SessionStatus) -> Bool {
        lhs.rank < rhs.rank
    }
}

/// Why an ended session left the live set (the Sessions journal `reason`).
public enum SessionEndReason: String, Sendable, Codable, Hashable {
    case exited = "exited"
    case revoked = "revoked"
    case vaultLocked = "vault locked"
}

/// Session fields shown in the UI. Ended entries also include time and reason.
public struct SessionInfo: Sendable, Codable, Hashable {
    public var key: String
    public var pid: Int
    public var name: String
    public var app: String
    public var signed: Bool
    public var signedBy: String
    public var status: SessionStatus
    public var calls: Int
    public var approvedAt: Date
    public var endedAt: Date?
    public var reason: SessionEndReason?

    public init(key: String, pid: Int, name: String, app: String = "",
                signed: Bool = false, signedBy: String = "",
                status: SessionStatus, calls: Int = 0, approvedAt: Date,
                endedAt: Date? = nil, reason: SessionEndReason? = nil) {
        self.key = key; self.pid = pid; self.name = name; self.app = app
        self.signed = signed; self.signedBy = signedBy
        self.status = status; self.calls = calls; self.approvedAt = approvedAt
        self.endedAt = endedAt; self.reason = reason
    }
}

// MARK: - Store

/// Thread-safe session storage. Hooks run outside the store lock.
public final class SessionStore: @unchecked Sendable {

    /// Told about each admitted session so a process-exit watcher (kqueue
    /// NOTE_EXIT) can expire it the moment the agent quits.
    public typealias WatchHook = @Sendable (_ pid: Int, _ startedAt: Int64, _ key: String) -> Void
    /// Undoes a watch on manual revoke / vault lock.
    public typealias UnwatchHook = @Sendable (_ pid: Int) -> Void

    /// Bounds the ended-session ring (the durable record is the audit).
    private static let historyCap = 200

    /// One live session. The snapshot fields are what admission was granted
    /// against; a later call whose provenance drifts from them is treated as a
    /// different, unadmitted process.
    private struct Entry {
        var pid: Int
        var startedAt: Int64
        var path: String        // executable path admitted (re-verified each call)
        var signedBy: String    // code-signing authority admitted (re-verified each call)
        var name: String        // display: process/exe basename
        var app: String         // display: .app bundle name, when any
        var signed: Bool        // was the admitted binary validly signed
        var status: SessionStatus
        var calls: Int
        var approvedAt: Date
    }

    private let lock = NSLock()
    private var live: [String: Entry] = [:]
    private var done: [SessionInfo] = []    // ended sessions, newest first
    private var watchHook: WatchHook?
    private var unwatchHook: UnwatchHook?

    public init() {}

    /// Armed on admit and disarmed on revoke or clear. Invoked outside the store lock;
    /// must be safe for concurrent use.
    public var watch: WatchHook? {
        get { lock.withLock { watchHook } }
        set { lock.withLock { watchHook = newValue } }
    }

    public var unwatch: UnwatchHook? {
        get { lock.withLock { unwatchHook } }
        set { lock.withLock { unwatchHook = newValue } }
    }

    /// Process identity as PID and kernel start time. Returns nil for origins
    /// that cannot be pinned to a local process.
    public static func sessionKey(_ o: Origin) -> String? {
        guard o.pid > 0, o.startedAt > 0 else { return nil }
        return "\(o.pid):\(o.startedAt)"
    }

    /// Whether the origin can be pinned to a live process.
    public func identifiable(_ o: Origin) -> Bool {
        Self.sessionKey(o) != nil
    }

    /// Whether the origin has an approved or per-call session. Path or signing
    /// authority drift invalidates the session.
    public func approved(_ o: Origin) -> Bool {
        guard let e = verified(o) else { return false }
        return e.status != .observed
    }

    /// The live entry for `o` after re-verifying path+signer. Deletes and
    /// returns nil on drift.
    private func verified(_ o: Origin) -> Entry? {
        guard let key = Self.sessionKey(o) else { return nil }
        return lock.withLock {
            guard let e = live[key] else { return nil }
            // Ignore an empty path from a transient KERN_PROCARGS2 failure. An
            // empty signing authority is meaningful and still checked strictly.
            let pathDrift = !o.path.isEmpty && e.path != o.path
            if pathDrift || e.signedBy != o.signedBy {
                live.removeValue(forKey: key)
                return nil
            }
            return e
        }
    }

    /// Approves the originating process and upgrades an observed entry.
    public func approve(_ o: Origin) { admit(o, status: .approved) }

    /// Admits the process through per-call approval without downgrading approval.
    public func approveViaCall(_ o: Origin) { admit(o, status: .perCall) }

    /// Observes the process without approval when session approval is disabled.
    public func observe(_ o: Origin) { admit(o, status: .observed) }

    /// Adds or upgrades a session and arms the exit watcher for new entries.
    private func admit(_ o: Origin, status: SessionStatus) {
        guard let key = Self.sessionKey(o) else { return }
        let armWatch: WatchHook? = lock.withLock {
            if var e = live[key] {
                if status > e.status {
                    e.status = status
                    live[key] = e
                }
                return nil // not fresh: nothing to arm
            }
            live[key] = Entry(
                pid: o.pid, startedAt: o.startedAt,
                path: o.path, signedBy: o.signedBy,
                name: Self.procLabel(path: o.path, fallback: o.name), app: o.appName,
                signed: o.validSignature, status: status,
                calls: 0, approvedAt: Date())
            return watchHook
        }
        armWatch?(o.pid, o.startedAt, key)
    }

    /// Increments the call counter when the session is still live.
    public func countCall(_ o: Origin) {
        guard let key = Self.sessionKey(o) else { return }
        lock.withLock {
            guard let calls = live[key]?.calls, calls < Int.max else { return }
            live[key]?.calls = calls + 1
        }
    }

    /// Drops a session by key (as listed in the UI), disarms its exit watch, and
    /// journals it as ended (`.revoked`). Returns whether it existed.
    @discardableResult
    public func revoke(key: String) -> Bool {
        let (pid, disarm): (Int?, UnwatchHook?) = lock.withLock {
            guard let e = live.removeValue(forKey: key) else { return (nil, nil) }
            pushDoneLocked(e, key: key, reason: .revoked)
            return (e.pid, unwatchHook)
        }
        if let pid, let disarm { disarm(pid) }
        return pid != nil
    }

    /// Removes a session after process exit. The one-shot kernel watch has
    /// already retired, so this does not unwatch it.
    public func expire(key: String) -> SessionInfo? {
        lock.withLock {
            guard let e = live.removeValue(forKey: key) else { return nil }
            return pushDoneLocked(e, key: key, reason: .exited)
        }
    }

    /// Removes sessions whose PID and start time are no longer active.
    public func sweep(alive: (_ pid: Int, _ startedAt: Int64) -> Bool) -> [SessionInfo] {
        let (dead, pids, disarm): ([SessionInfo], [Int], UnwatchHook?) = lock.withLock {
            var dead: [SessionInfo] = []
            var pids: [Int] = []
            for (key, e) in live where !alive(e.pid, e.startedAt) {
                dead.append(pushDoneLocked(e, key: key, reason: .exited))
                pids.append(e.pid)
                live.removeValue(forKey: key)
            }
            return (dead, pids, unwatchHook)
        }
        if let disarm {
            for pid in pids { disarm(pid) } // clear any stale watcher bookkeeping
        }
        return dead
    }

    /// Ends all sessions on lock and returns them for `session.ended` records.
    @discardableResult
    public func clear() -> [SessionInfo] {
        let (endedNow, pids, disarm): ([SessionInfo], [Int], UnwatchHook?) = lock.withLock {
            var ended: [SessionInfo] = []
            var pids: [Int] = []
            for (key, e) in live {
                ended.append(pushDoneLocked(e, key: key, reason: .vaultLocked))
                pids.append(e.pid)
            }
            live.removeAll()
            return (ended, pids, unwatchHook)
        }
        if let disarm {
            for pid in pids { disarm(pid) }
        }
        return endedNow
    }

    /// Live sessions in unspecified order.
    public func list() -> [SessionInfo] {
        lock.withLock { live.map { key, e in Self.info(e, key: key) } }
    }

    /// Ended sessions, newest first (the Sessions journal view).
    public func history() -> [SessionInfo] {
        lock.withLock { done }
    }

    // MARK: Internals

    /// The UI-facing view of a live entry.
    private static func info(_ e: Entry, key: String) -> SessionInfo {
        SessionInfo(key: key, pid: e.pid, name: e.name, app: e.app,
                    signed: e.signed, signedBy: e.signedBy,
                    status: e.status, calls: e.calls, approvedAt: e.approvedAt)
    }

    /// Journals an ended session (caller holds `lock`) and returns the entry.
    @discardableResult
    private func pushDoneLocked(_ e: Entry, key: String, reason: SessionEndReason) -> SessionInfo {
        var info = Self.info(e, key: key)
        info.endedAt = Date()
        info.reason = reason
        done.insert(info, at: 0)
        if done.count > Self.historyCap {
            done.removeLast(done.count - Self.historyCap)
        }
        return info
    }

    /// Returns the executable basename or the fallback process name.
    static func procLabel(path: String, fallback: String) -> String {
        guard !path.isEmpty else { return fallback }
        if let i = path.lastIndex(of: "/"), path.index(after: i) < path.endIndex {
            return String(path[path.index(after: i)...])
        }
        return path
    }
}
