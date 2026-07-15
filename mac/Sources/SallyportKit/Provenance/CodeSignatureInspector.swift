import Foundation
import Security

/// Verifies the code signature of a running process by PID.
public struct CodeSignatureInspector: Sendable {
    public init() {}

    /// The designated requirement a hop must satisfy to count as "validly signed".
    ///
    /// Requires an Apple-rooted signature and rejects ad-hoc and unsigned code.
    private static func anchorRequirement() -> SecRequirement? {
        var requirement: SecRequirement?
        let status = SecRequirementCreateWithString(
            "anchor apple generic" as CFString, [], &requirement)
        return status == errSecSuccess ? requirement : nil
    }

    /// Returns `true`/`false` for a definitive verdict, or `nil` when the
    /// process can't be inspected (gone, or the API refused).
    public func isValidlySigned(pid: Int32) -> Bool? {
        var code: SecCode?
        let attrs: [CFString: Any] = [kSecGuestAttributePid: NSNumber(value: pid)]
        let copyStatus = SecCodeCopyGuestWithAttributes(
            nil, attrs as CFDictionary, [], &code)
        guard copyStatus == errSecSuccess, let dynamicCode = code else {
            return nil
        }

        // A missing requirement cannot produce a positive result.
        let requirement = Self.anchorRequirement()

        var staticCode: SecStaticCode?
        let staticStatus = SecCodeCopyStaticCode(dynamicCode, [], &staticCode)
        guard staticStatus == errSecSuccess, let sc = staticCode else {
            // Fall back to validating the dynamic code.
            let dyn = SecCodeCheckValidity(dynamicCode, [], requirement)
            return dyn == errSecSuccess
        }

        let validity = SecStaticCodeCheckValidity(sc, [], requirement)
        return validity == errSecSuccess
    }
}

/// Verifies the origin and every process-chain hop.
public struct ProvenanceEnricher: Sendable {
    private let inspector: CodeSignatureInspector

    public init(inspector: CodeSignatureInspector = CodeSignatureInspector()) {
        self.inspector = inspector
    }

    public func enrich(_ provenance: Provenance) -> Provenance {
        let enrichedChain = provenance.chain.map { hop -> ProcessHop in
            var copy = hop
            copy.validSignature = signatureVerdict(pid: hop.pid)
            return copy
        }
        var origin = provenance.origin
        origin.validSignature = signatureVerdict(pid: origin.pid)
        return Provenance(
            origin: origin,
            chain: enrichedChain,
            // Include the requesting process in the result.
            intact: ProvenanceEvaluator.intact(origin: origin, chain: enrichedChain))
    }

    /// Protocol PIDs are decoded as platform-sized Ints. An impossible value
    /// must render as untrusted, not trap while narrowing it for Security.framework.
    private func signatureVerdict(pid: Int) -> Bool? {
        guard let pid = Int32(exactly: pid), pid > 0 else { return false }
        return inspector.isValidlySigned(pid: pid)
    }
}
