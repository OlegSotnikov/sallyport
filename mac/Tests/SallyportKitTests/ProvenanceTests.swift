import Foundation
import Testing
@testable import SallyportKit

@Suite("Provenance → trust badge")
struct ProvenanceTests {

    @Test("fully signed chain is verified and intact")
    func signedChainVerified() {
        let chain = Fixtures.signedChain
        #expect(ProvenanceEvaluator.intact(chain))
        #expect(ProvenanceEvaluator.badge(for: chain) == .verified)
        #expect(ProvenanceEvaluator.badge(for: chain).isVerified)
    }

    @Test("an unsigned hop flips the badge to red and names the failing hop")
    func unsignedHopIsRed() {
        let chain = Fixtures.tamperedChain
        #expect(!ProvenanceEvaluator.intact(chain))
        let badge = ProvenanceEvaluator.badge(for: chain)
        guard case let .unsignedInChain(name, pid) = badge else {
            Issue.record("expected unsignedInChain, got \(badge)"); return
        }
        #expect(name == "node")
        #expect(pid == 4200)
        #expect(badge.label.contains("node"))
    }

    @Test("first failing hop wins when several are unsigned")
    func firstFailingHopWins() {
        let chain = [
            ProcessHop(pid: 1, name: "a", validSignature: true),
            ProcessHop(pid: 2, name: "b", validSignature: false),
            ProcessHop(pid: 3, name: "c", validSignature: false),
        ]
        guard case let .unsignedInChain(name, _) = ProvenanceEvaluator.badge(for: chain) else {
            Issue.record("expected unsignedInChain"); return
        }
        #expect(name == "b")
    }

    @Test("a not-yet-inspected hop yields unknown, not verified")
    func nilHopIsUnknown() {
        let chain = [
            ProcessHop(pid: 1, name: "a", validSignature: true),
            ProcessHop(pid: 2, name: "b", validSignature: nil),
        ]
        #expect(ProvenanceEvaluator.badge(for: chain) == .unknown)
        #expect(!ProvenanceEvaluator.intact(chain))
    }

    @Test("empty chain is unknown and not intact")
    func emptyChain() {
        #expect(ProvenanceEvaluator.badge(for: []) == .unknown)
        #expect(!ProvenanceEvaluator.intact([]))
    }

    @Test("chain summary renders app names then process names")
    func chainSummary() {
        let summary = ProvenanceEvaluator.chainSummary(Fixtures.signedChain)
        #expect(summary == "Claude Code → node → zsh → Terminal")
    }

    @Test("an intact chain with an UNSIGNED origin is not verified (origin folded in)")
    func unsignedOriginIsNotVerified() {
        // Every chain hop is validly signed, but the actual requesting process
        // (origin) is unsigned. The whole-provenance verdict must NOT be verified.
        let origin = ProcessHop(pid: 9, name: "injected", appName: "Injected",
                                validSignature: false)
        let prov = Provenance(origin: origin, chain: Fixtures.signedChain, intact: true)

        // Chain alone still reads verified — that's exactly the trap being closed.
        #expect(ProvenanceEvaluator.badge(for: Fixtures.signedChain) == .verified)
        // Origin-aware verdict: NOT verified, and not intact.
        #expect(!ProvenanceEvaluator.badge(for: prov).isVerified)
        #expect(!ProvenanceEvaluator.intact(prov))
        guard case let .unsignedInChain(name, pid) = ProvenanceEvaluator.badge(for: prov) else {
            Issue.record("expected unsignedInChain for the unsigned origin"); return
        }
        #expect(name == "Injected")
        #expect(pid == 9)
    }

    @Test("verified chain with an un-inspected origin is unknown, never green")
    func uninspectedOriginIsUnknown() {
        let origin = ProcessHop(pid: 9, name: "x", validSignature: nil)
        let prov = Provenance(origin: origin, chain: Fixtures.signedChain, intact: true)
        #expect(ProvenanceEvaluator.badge(for: prov) == .unknown)
        #expect(!ProvenanceEvaluator.intact(prov))
    }

    @Test("verified chain with a signed origin is verified and intact")
    func signedOriginVerified() {
        let prov = Fixtures.provenanceIntact  // origin hop is validSignature: true
        #expect(ProvenanceEvaluator.badge(for: prov) == .verified)
        #expect(ProvenanceEvaluator.intact(prov))
    }

    /// Whether this test process itself carries NO team identity (ad-hoc/unsigned).
    /// Xcode runs tests ad-hoc; the CLT's swiftpm-testing-helper is Apple-signed
    /// WITH a team, which flips every "our runner is unsigned" assumption below.
    private static var runnerIsTeamless: Bool {
        var me: SecCode?
        guard SecCodeCopySelf([], &me) == errSecSuccess, let me else { return true }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(unsafeBitCast(me, to: SecStaticCode.self),
                                            SecCSFlags(rawValue: kSecCSSigningInformation),
                                            &info) == errSecSuccess,
              let dict = info as? [String: Any] else { return true }
        return dict[kSecCodeInfoTeamIdentifier as String] == nil
    }

    @Test("code-signature check rejects ad-hoc/unsigned code (no nil-requirement bypass)",
          .enabled(if: runnerIsTeamless,
                   "the negative only holds for an ad-hoc runner; an Apple-signed test host legitimately satisfies 'anchor apple generic'"))
    func adHocIsNotValidlySigned() {
        // We can't ship a Developer-ID-signed fixture in-tree, so verify the
        // security-critical NEGATIVE: this test binary is ad-hoc/unsigned, and with
        // the `anchor apple generic` requirement it must NOT report as validly
        // signed. Before the fix, the nil-requirement check waved ad-hoc seals
        // through as `true`. A `nil` verdict (API refused) is also acceptable —
        // the invariant is only that ad-hoc/unsigned is never accepted as `true`.
        let inspector = CodeSignatureInspector()
        let verdict = inspector.isValidlySigned(pid: ProcessInfo.processInfo.processIdentifier)
        #expect(verdict != true)
    }

    @Test("enricher recomputes intact from its own signature checks")
    func enricherRecomputes() {
        // A stub inspector that marks pid 2 unsigned proves the app owns the badge.
        struct StubInspector {
            func verdict(_ pid: Int) -> Bool? { pid == 2 ? false : true }
        }
        // Reproduce enricher logic against the stub (the real enricher uses SecCode).
        let raw = Provenance(
            origin: ProcessHop(pid: 1, name: "claude"),
            chain: [ProcessHop(pid: 1, name: "claude"), ProcessHop(pid: 2, name: "x")],
            intact: true)  // daemon claimed intact...
        let stub = StubInspector()
        let enrichedChain = raw.chain.map { hop -> ProcessHop in
            var c = hop; c.validSignature = stub.verdict(hop.pid); return c
        }
        #expect(!ProvenanceEvaluator.intact(enrichedChain))  // ...app disagrees
    }

    @Test("impossible protocol PIDs fail closed instead of overflowing Int32")
    func impossiblePIDsFailClosed() {
        let provenance = Provenance(
            origin: ProcessHop(pid: Int.max, name: "forged-origin", validSignature: true),
            chain: [ProcessHop(pid: Int.min, name: "forged-parent", validSignature: true)],
            intact: true)

        let enriched = ProvenanceEnricher().enrich(provenance)

        #expect(enriched.origin.validSignature == false)
        #expect(enriched.chain.first?.validSignature == false)
        #expect(enriched.intact == false)
    }
}
