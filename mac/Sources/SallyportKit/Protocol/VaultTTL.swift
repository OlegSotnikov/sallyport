import Foundation

/// Countdown and formatting for the vault auto-lock clock.
public enum VaultTTL {

    /// Seconds remaining from a `ttlSec` snapshot taken at `anchoredAt`, evaluated
    /// at `now`. Never negative; a zero/absent ttl stays zero.
    public static func remaining(ttlSec: Int, anchoredAt: Date, now: Date) -> Int {
        guard ttlSec > 0 else { return 0 }
        let elapsed = now.timeIntervalSince(anchoredAt)
        guard elapsed.isFinite else { return elapsed > 0 ? 0 : ttlSec }
        guard elapsed > 0 else { return ttlSec }
        // Compare while still in floating point. Converting an attacker/corrupt-
        // clock-sized Double directly to Int traps before `max` can clamp it.
        guard elapsed < Double(ttlSec) else { return 0 }
        return ttlSec - Int(elapsed)
    }

    /// A `M:SS` clock (or `H:MM:SS` once there is an hour or more) from a seconds
    /// count. Seconds granularity so the countdown is visibly moving.
    public static func clock(_ seconds: Int) -> String {
        let total = max(0, seconds)
        let h = total / 3600
        let m = (total % 3600) / 60
        let s = total % 60
        return h > 0
            ? String(format: "%d:%02d:%02d", h, m, s)
            : String(format: "%d:%02d", m, s)
    }
}
