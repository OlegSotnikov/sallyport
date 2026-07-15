import Testing
@testable import SallyportApp

@Suite("Agent focus boundary")
struct AgentFocusSafetyTests {
    @Test("invalid and non-PID-sized values fail closed without narrowing traps")
    func invalidPID() {
        for pid in [Int.min, -1, 0, Int(Int32.max) + 1, Int.max] {
            switch AgentFocus.reveal(pid: pid) {
            case .none: break
            case .exact, .appOnly:
                Issue.record("invalid pid \(pid) unexpectedly resolved to an application")
            }
        }
    }
}
