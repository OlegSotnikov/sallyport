import Foundation

/// Process-chain signature result shown on approval cards.
public enum TrustBadge: Sendable, Hashable {
    /// Every hop in the chain is validly signed.
    case verified
    /// At least one hop failed signature validation. Carries the first bad hop.
    case unsignedInChain(hopName: String, pid: Int)
    /// Not enough information yet (empty chain or a hop not inspected).
    case unknown

    public var isVerified: Bool {
        if case .verified = self { return true }
        return false
    }

    /// Badge label.
    public var label: String {
        switch self {
        case .verified:
            return "Verified"
        case .unsignedInChain(let name, _):
            return "Unsigned: \(name)"
        case .unknown:
            return "Verifying…"
        }
    }
}

/// Reduces process signatures to a badge result.
public enum ProvenanceEvaluator {

    /// `intact` = the chain is non-empty and every hop is validly signed.
    public static func intact(_ chain: [ProcessHop]) -> Bool {
        !chain.isEmpty && chain.allSatisfy { $0.validSignature == true }
    }

    /// Checks the origin and every process-chain hop.
    public static func intact(origin: ProcessHop, chain: [ProcessHop]) -> Bool {
        origin.validSignature == true && intact(chain)
    }

    /// Origin-aware verdict for a `Provenance`.
    public static func intact(_ provenance: Provenance) -> Bool {
        intact(origin: provenance.origin, chain: provenance.chain)
    }

    /// Returns the first invalid hop, or unknown if inspection is incomplete.
    public static func badge(for chain: [ProcessHop]) -> TrustBadge {
        guard !chain.isEmpty else { return .unknown }
        if let bad = chain.first(where: { $0.validSignature == false }) {
            return .unsignedInChain(hopName: bad.name, pid: bad.pid)
        }
        if chain.contains(where: { $0.validSignature == nil }) {
            return .unknown
        }
        return .verified
    }

    /// Includes the requesting process in the badge result.
    public static func badge(origin: ProcessHop, chain: [ProcessHop]) -> TrustBadge {
        if origin.validSignature == false {
            return .unsignedInChain(hopName: origin.appName ?? origin.name, pid: origin.pid)
        }
        let chainBadge = badge(for: chain)
        if chainBadge.isVerified, origin.validSignature != true {
            return .unknown
        }
        return chainBadge
    }

    /// Origin-aware badge for a `Provenance`.
    public static func badge(for provenance: Provenance) -> TrustBadge {
        badge(origin: provenance.origin, chain: provenance.chain)
    }

    /// Process-chain display string.
    public static func chainSummary(_ chain: [ProcessHop]) -> String {
        chain.map { $0.appName ?? $0.name }.joined(separator: " → ")
    }
}
