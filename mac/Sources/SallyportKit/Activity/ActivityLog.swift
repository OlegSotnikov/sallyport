import Foundation

public extension ActivityRow {
    /// The `⚠` rows in the feed: denials and errors get highlighted.
    var isFlagged: Bool {
        isError || decision.lowercased().contains("deny")
    }
}

/// Activity filter by identity, channel, decision, text, and flagged state.
public struct ActivityFilter: Sendable, Hashable {
    public var query: String
    public var channel: String?
    public var decision: String?
    public var onlyFlagged: Bool

    public init(query: String = "", channel: String? = nil,
                decision: String? = nil, onlyFlagged: Bool = false) {
        self.query = query
        self.channel = channel
        self.decision = decision
        self.onlyFlagged = onlyFlagged
    }

    /// True when any constraint is set (so an inactive filter skips work).
    public var isActive: Bool {
        !query.trimmingCharacters(in: .whitespaces).isEmpty
            || channel != nil || decision != nil || onlyFlagged
    }

    public func matches(_ row: ActivityRow) -> Bool {
        let q = query.trimmingCharacters(in: .whitespaces).lowercased()
        if !q.isEmpty {
            let haystack = [row.identity, row.tool, row.target, row.argsPreview,
                            row.channel, row.rule ?? ""]
                .joined(separator: " ")
                .lowercased()
            if !haystack.contains(q) { return false }
        }
        if let channel, row.channel != channel { return false }
        if let decision, !row.decision.lowercased().contains(decision.lowercased()) {
            return false
        }
        if onlyFlagged, !row.isFlagged { return false }
        return true
    }
}

/// Capacity-bounded, newest-first activity rows held in memory. The app restores
/// them from the encrypted audit log after unlock and clears them on lock.
public struct ActivityLog: Sendable {
    public private(set) var rows: [ActivityRow]
    public let capacity: Int

    public init(capacity: Int = 2000, rows: [ActivityRow] = []) {
        self.capacity = max(1, capacity)
        self.rows = Array(rows.prefix(self.capacity))
    }

    /// Append a freshly received row (goes to the front). Oldest rows are
    /// dropped once capacity is exceeded.
    public mutating func append(_ row: ActivityRow) {
        rows.insert(row, at: 0)
        if rows.count > capacity {
            rows.removeLast(rows.count - capacity)
        }
    }

    /// Rows matching a filter, preserving newest-first order.
    public func filtered(_ filter: ActivityFilter) -> [ActivityRow] {
        filter.isActive ? rows.filter(filter.matches) : rows
    }

    /// Distinct channels present, for building filter chips.
    public var channels: [String] {
        var seen = Set<String>()
        var ordered: [String] = []
        for row in rows where !seen.contains(row.channel) {
            seen.insert(row.channel)
            ordered.append(row.channel)
        }
        return ordered.sorted()
    }
}
