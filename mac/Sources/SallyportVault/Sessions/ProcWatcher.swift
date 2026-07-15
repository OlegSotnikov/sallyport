import Darwin
import Foundation

/// Darwin declares both a `kevent` struct and a `kevent` function; in expression
/// position the function wins, so give the struct an unambiguous name.
private typealias KernelEvent = kevent

/// Expires sessions when their processes exit using one kqueue and one thread.
/// Registrations use `EV_ONESHOT`; `SessionStore.sweep` covers missed events.
public final class ProcWatcher: @unchecked Sendable {

    private let kq: Int32
    private let onExit: @Sendable (_ key: String) -> Void

    private let lock = NSLock()
    private var keys: [Int: String] = [:]   // pid → session key (single-delivery bookkeeping)
    private var closed = false

    /// Starts the watcher and calls `onExit` once for each watched process.
    public init(onExit: @escaping @Sendable (_ key: String) -> Void) throws {
        let fd = Darwin.kqueue()
        guard fd >= 0 else {
            throw POSIXError(POSIXError.Code(rawValue: errno) ?? .EIO)
        }
        self.kq = fd
        self.onExit = onExit
        let thread = Thread { [self] in loop() }
        thread.name = "sallyport.proc-watcher"
        thread.start()
    }

    deinit {
        // Reachable only once the loop thread has exited (it retains self); on
        // the normal path close() already released the fd. Defensive close for
        // the pathological path where kevent(2) failed spontaneously.
        if !closed { _ = Darwin.close(kq) }
    }

    /// Watches the process identified by PID and start time. It expires
    /// immediately if the process exited or the PID was reused before arming.
    public func watch(pid: Int, startedAt: Int64, key: String) {
        guard let ident = UInt(exactly: pid), ident > 0 else { return }
        lock.lock()
        if closed {
            lock.unlock()
            return
        }
        keys[pid] = key
        var ev = kevent(ident: ident,
                        filter: Int16(EVFILT_PROC),
                        flags: UInt16(EV_ADD | EV_ONESHOT),
                        fflags: NOTE_EXIT,
                        data: 0,
                        udata: nil)
        let rc = kevent(kq, &ev, 1, nil, 0, nil)
        lock.unlock()

        if rc < 0 || !Provenance.alive(pid: pid, startedAt: startedAt) {
            deregister(pid) // drop the (possibly wrong-process) registration
            if let k = take(pid), k == key {
                onExit(key)
            }
        }
    }

    /// Disarms a pid on manual revoke / vault lock. Never fires `onExit`.
    public func unwatch(pid: Int) {
        guard pid > 0 else { return }
        _ = take(pid)
        deregister(pid)
    }

    /// Stops the loop and releases the kqueue.
    public func close() {
        lock.lock()
        if closed {
            lock.unlock()
            return
        }
        closed = true
        let fd = kq
        lock.unlock()
        _ = Darwin.close(fd) // wakes the loop's kevent with EBADF
    }

    /// Removes the key for a PID to enforce single delivery.
    private func take(_ pid: Int) -> String? {
        lock.withLock { keys.removeValue(forKey: pid) }
    }

    /// Removes a kevent registration and ignores an absent registration.
    private func deregister(_ pid: Int) {
        guard let ident = UInt(exactly: pid), ident > 0 else { return }
        lock.lock()
        defer { lock.unlock() }
        if closed { return }
        var ev = kevent(ident: ident,
                        filter: Int16(EVFILT_PROC),
                        flags: UInt16(EV_DELETE),
                        fflags: NOTE_EXIT,
                        data: 0,
                        udata: nil)
        _ = kevent(kq, &ev, 1, nil, 0, nil)
    }

    /// Blocks in kevent until a watched process exits, then expires its session.
    /// Exits when `close()` closes the kqueue.
    private func loop() {
        var events = [KernelEvent](repeating: KernelEvent(), count: 16)
        while true {
            let n = events.withUnsafeMutableBufferPointer { buf in
                kevent(kq, nil, 0, buf.baseAddress, Int32(buf.count), nil)
            }
            if n < 0 {
                if errno == EINTR { continue }
                return // kqueue closed
            }
            for i in 0..<Int(n) {
                let ev = events[i]
                guard ev.filter == Int16(EVFILT_PROC), (ev.fflags & NOTE_EXIT) != 0 else {
                    continue
                }
                if let key = take(Int(ev.ident)) {
                    onExit(key)
                }
            }
        }
    }
}
