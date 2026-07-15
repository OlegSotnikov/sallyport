import Foundation
import Testing
@testable import SallyportKit

@Suite("Vault TTL countdown & formatting")
struct VaultTTLTests {

    private let anchor = Date(timeIntervalSince1970: 1_000_000)

    @Test("remaining subtracts elapsed time and never goes negative")
    func remainingCountsDown() {
        #expect(VaultTTL.remaining(ttlSec: 600, anchoredAt: anchor, now: anchor) == 600)
        #expect(VaultTTL.remaining(ttlSec: 600, anchoredAt: anchor,
                                   now: anchor.addingTimeInterval(1)) == 599)
        #expect(VaultTTL.remaining(ttlSec: 600, anchoredAt: anchor,
                                   now: anchor.addingTimeInterval(599)) == 1)
        // Clamps at zero once the TTL has fully elapsed.
        #expect(VaultTTL.remaining(ttlSec: 600, anchoredAt: anchor,
                                   now: anchor.addingTimeInterval(600)) == 0)
        #expect(VaultTTL.remaining(ttlSec: 600, anchoredAt: anchor,
                                   now: anchor.addingTimeInterval(9_999)) == 0)
    }

    @Test("a zero/absent TTL stays zero; backward clock skew is treated as no elapse")
    func remainingEdges() {
        #expect(VaultTTL.remaining(ttlSec: 0, anchoredAt: anchor, now: anchor) == 0)
        // now before anchor (clock skew) must not inflate the remaining time.
        #expect(VaultTTL.remaining(ttlSec: 600, anchoredAt: anchor,
                                   now: anchor.addingTimeInterval(-30)) == 600)
        // A corrupted clock value must clamp before converting Double to Int;
        // the direct conversion traps for magnitudes this large.
        #expect(VaultTTL.remaining(
            ttlSec: 600,
            anchoredAt: anchor,
            now: Date(timeIntervalSinceReferenceDate: .greatestFiniteMagnitude)
        ) == 0)
        #expect(VaultTTL.remaining(
            ttlSec: 600,
            anchoredAt: anchor,
            now: Date(timeIntervalSinceReferenceDate: -.greatestFiniteMagnitude)
        ) == 600)
    }

    @Test("clock formats M:SS, and H:MM:SS once there is an hour or more")
    func clockFormat() {
        #expect(VaultTTL.clock(0) == "0:00")
        #expect(VaultTTL.clock(7) == "0:07")
        #expect(VaultTTL.clock(72) == "1:12")
        #expect(VaultTTL.clock(600) == "10:00")
        #expect(VaultTTL.clock(3_599) == "59:59")
        #expect(VaultTTL.clock(3_600) == "1:00:00")
        #expect(VaultTTL.clock(21_600) == "6:00:00")
        // The classic "6:12" example now carries seconds and visibly ticks.
        #expect(VaultTTL.clock(22_320) == "6:12:00")
        #expect(VaultTTL.clock(-5) == "0:00")
    }
}
