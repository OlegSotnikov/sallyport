import AppKit
import Darwin

/// Brings the terminal tab for an agent process to the front. Terminal and iTerm2
/// are matched by controlling TTY; other applications fall back to activation.
enum AgentFocus {
    enum Result { case exact, appOnly, none }

    /// Bring the terminal window/tab hosting `pid` to the front. `.exact` when we
    /// selected the precise tab by tty; `.appOnly` when we could only raise the
    /// owning app; `.none` when nothing in the ancestry owns a window.
    @discardableResult
    static func reveal(pid: Int) -> Result {
        guard let pid = Int32(exactly: pid), pid > 0 else { return .none }
        let tty = controllingTTY(startingAt: pid)

        // Walk up to the nearest GUI application (the terminal/editor).
        var cur = pid
        for _ in 0..<24 {
            if let app = NSRunningApplication(processIdentifier: cur),
               app.activationPolicy == .regular {
                // Try the tty-exact path for terminals that script it.
                if let tty, let script = script(for: app.bundleIdentifier, tty: tty),
                   runReveal(script) {
                    return .exact
                }
                activate(app)
                return .appOnly
            }
            guard let parent = ppid(of: cur), parent > 1, parent != cur else { break }
            cur = parent
        }
        return .none
    }

    // MARK: - Kernel facts

    /// The controlling terminal of the process (or the first ancestor that has
    /// one), as "/dev/ttysNNN". nil when the process is gone or headless (no tty).
    private static func controllingTTY(startingAt pid: Int32) -> String? {
        var cur = pid
        for _ in 0..<24 {
            guard let kp = kinfo(pid: cur) else { return nil }
            let dev = kp.kp_eproc.e_tdev
            if dev != -1, let namePtr = devname(dev, S_IFCHR) {
                return "/dev/" + String(cString: namePtr)
            }
            let parent = kp.kp_eproc.e_ppid
            if parent <= 1 || parent == cur { return nil }
            cur = parent
        }
        return nil
    }

    private static func ppid(of pid: Int32) -> Int32? { kinfo(pid: pid)?.kp_eproc.e_ppid }

    private static func kinfo(pid: Int32) -> kinfo_proc? {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
        guard sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0) == 0,
              size == MemoryLayout<kinfo_proc>.stride else {
            return nil
        }
        return info
    }

    // MARK: - Reveal

    private static func activate(_ app: NSRunningApplication) {
        if #available(macOS 14.0, *) {
            _ = app.activate(options: [.activateAllWindows])
        } else {
            _ = app.activate(options: [.activateAllWindows, .activateIgnoringOtherApps])
        }
    }

    /// The AppleScript that selects the tab whose tty matches, or nil for a host
    /// we can't script by tty (caller falls back to plain activation).
    private static func script(for bundleID: String?, tty: String) -> String? {
        switch bundleID {
        case "com.apple.Terminal":
            return """
            tell application "Terminal"
              activate
              repeat with w in windows
                repeat with t in tabs of w
                  if tty of t is "\(tty)" then
                    set selected tab of w to t
                    set index of w to 1
                    set frontmost of w to true
                    return true
                  end if
                end repeat
              end repeat
            end tell
            return false
            """
        case "com.googlecode.iterm2":
            return """
            tell application "iTerm2"
              activate
              repeat with w in windows
                repeat with t in tabs of w
                  repeat with s in sessions of t
                    if tty of s is "\(tty)" then
                      select w
                      select t
                      select s
                      return true
                    end if
                  end repeat
                end repeat
              end repeat
            end tell
            return false
            """
        default:
            return nil
        }
    }

    /// Run an AppleScript that returns true/false. Any error (not-permitted on the
    /// first run, terminal not running, no match) resolves to false so the caller
    /// falls back to activating the app.
    private static func runReveal(_ source: String) -> Bool {
        guard let script = NSAppleScript(source: source) else { return false }
        var err: NSDictionary?
        let out = script.executeAndReturnError(&err)
        if err != nil { return false }
        return out.booleanValue
    }
}
