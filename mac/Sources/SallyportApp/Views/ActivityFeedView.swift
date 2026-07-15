import SwiftUI
import AppKit
import SallyportKit

/// Searchable call history loaded from the encrypted audit journal.
struct ActivityFeedView: View {
    @Bindable var model: AppModel
    var locked: Bool = false
    var onUnlock: (() async -> Bool)?
    @State private var selectedRow: ActivityRow?

    private var rows: [ActivityRow] {
        // Session lifecycle rows are shown on the Sessions screen.
        model.activity.filtered(model.filter).filter { !$0.tool.hasPrefix("session.") }
    }

    var body: some View {
        let rows = self.rows
        return VStack(spacing: 0) {
            ScreenHeader(
                title: "Activity",
                subtitle: "Calls from the encrypted audit journal.",
                symbol: "list.bullet.rectangle"
            ) {
                HStack(spacing: Theme.Spacing.sm) {
                    Button { exportLog() } label: {
                        Label("Export", systemImage: "square.and.arrow.up")
                    }
                    .controlSize(.small)
                    .disabled(model.isDemo || model.vault.locked || model.activity.rows.isEmpty)
                    .help(model.vault.locked
                          ? "Unlock the vault to export the encrypted journal"
                          : "Decrypt and export the audit history as JSONL")
                    Label("Live", systemImage: "dot.radiowaves.left.and.right")
                        .font(.caption).foregroundStyle(Theme.verified)
                        .padding(.horizontal, Theme.Spacing.sm).padding(.vertical, 4)
                        .background(Theme.verified.opacity(0.12), in: Capsule())
                }
            }
            Divider()
            if locked {
                // Audit history is unreadable while the vault is locked.
                LockedVaultView(onUnlock: onUnlock)
            } else {
            filterBar
            Divider()
            if rows.isEmpty {
                EmptyStateView(
                    title: model.activity.rows.isEmpty ? "No activity yet" : "No matches",
                    message: model.activity.rows.isEmpty
                        ? "Actions your agents take will stream here."
                        : "No rows match the current filter. Try clearing it.",
                    symbol: "list.bullet.rectangle")
            } else {
                activityHeader
                Divider()
                List(rows, selection: Binding(
                    get: { selectedRow?.id },
                    set: { id in selectedRow = rows.first { $0.id == id } })
                ) {
                    ActivityRowView(row: $0)
                        .tag($0.id)
                }
                .listStyle(.plain)
                .scrollContentBackground(.hidden)
            }
            }
        }
        .sheet(item: $selectedRow) { row in
            ActivityDetailView(row: row, model: model) { selectedRow = nil }
        }
    }

    /// Uses the same widths as activity rows.
    private var activityHeader: some View {
        ViewThatFits(in: .horizontal) {
            HStack(spacing: Theme.Spacing.md) {
                headerCell("Time", width: ActivityColumns.time, align: .leading)
                headerCell("Agent", width: ActivityColumns.identity, align: .leading)
                Text("Action").frame(maxWidth: .infinity, alignment: .leading)
                headerCell("Target", width: ActivityColumns.target, align: .trailing)
                headerCell("Decision", width: ActivityColumns.decision, align: .leading)
                headerCell("Took", width: ActivityColumns.duration, align: .trailing)
            }
            .frame(minWidth: ActivityColumns.wideMinimumWidth)

            HStack(spacing: Theme.Spacing.md) {
                Text("Action").frame(maxWidth: .infinity, alignment: .leading)
                Text("Decision").fixedSize(horizontal: true, vertical: false)
            }
        }
        .font(.caption2.weight(.semibold)).tracking(0.5)
        .foregroundStyle(.tertiary)
        .padding(.horizontal, Theme.screenPadding)
        .padding(.vertical, Theme.Spacing.sm)
    }

    private func headerCell(_ text: LocalizedStringResource, width: CGFloat, align: Alignment) -> some View {
        Text(text).frame(width: width, alignment: align)
    }

    /// Decrypts the audit journal and writes it as JSONL.
    private func exportLog() {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "sallyport-activity.jsonl"
        panel.canCreateDirectories = true
        guard panel.runModal() == .OK, let url = panel.url else { return }
        Task {
            let jsonl = await model.exportActivityJSONL()
            try? jsonl.write(to: url, atomically: true, encoding: .utf8)
        }
    }

    private var filterBar: some View {
        ViewThatFits(in: .horizontal) {
            HStack(spacing: Theme.Spacing.md) {
                filterField
                    .frame(maxWidth: 320)
                channelPicker
                flaggedToggle
                Spacer(minLength: Theme.Spacing.sm)
                eventCount
            }
            .frame(minWidth: ActivityColumns.wideFilterMinimumWidth)

            VStack(alignment: .leading, spacing: Theme.Spacing.sm) {
                filterField
                HStack(spacing: Theme.Spacing.md) {
                    channelPicker
                    flaggedToggle
                    Spacer(minLength: Theme.Spacing.xs)
                    eventCount
                }
            }
        }
        .padding(.horizontal, Theme.screenPadding).padding(.vertical, Theme.Spacing.sm + 2)
    }

    private var filterField: some View {
        HStack(spacing: Theme.Spacing.sm) {
            Image(systemName: "magnifyingglass")
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            TextField("Filter identity, tool, target…", text: $model.filter.query)
                .textFieldStyle(.plain)
        }
        .padding(.horizontal, Theme.Spacing.sm).padding(.vertical, 5)
        .background(Theme.Surface.inset, in: RoundedRectangle(cornerRadius: Theme.Radius.md))
    }

    private var channelPicker: some View {
        Picker("Channel", selection: Binding(
            get: { model.filter.channel ?? "" },
            set: { model.filter.channel = $0.isEmpty ? nil : $0 })
        ) {
            Text("All channels").tag("")
            ForEach(model.activity.channels, id: \.self) {
                Text(verbatim: $0).tag($0)
            }
        }
        .labelsHidden()
        .fixedSize()
    }

    private var flaggedToggle: some View {
        Toggle(isOn: $model.filter.onlyFlagged) {
            Label("Flagged", systemImage: "exclamationmark.triangle")
        }
        .toggleStyle(.button)
        .controlSize(.small)
        .fixedSize()
    }

    private var eventCount: some View {
        Text("\(rows.count) events",
             comment: "Number of visible activity events. Configure plural variations for the event count.")
            .font(.caption)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: true, vertical: false)
    }
}

/// Shared widths for the activity header and rows.
enum ActivityColumns {
    static let time: CGFloat = 96
    static let identity: CGFloat = 128
    static let target: CGFloat = 140
    static let decision: CGFloat = 220
    static let duration: CGFloat = 72
    static let wideMinimumWidth: CGFloat = 920
    static let wideFilterMinimumWidth: CGFloat = 760
}

struct ActivityRowView: View {
    let row: ActivityRow
    @Environment(\.locale) private var locale

    var body: some View {
        ViewThatFits(in: .horizontal) {
            HStack(spacing: Theme.Spacing.md) {
                Text(verbatim: TimeFormat.clock(row.ts, locale: locale))
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .frame(width: ActivityColumns.time, alignment: .leading)
                identity
                    .frame(width: ActivityColumns.identity, alignment: .leading)
                action
                    .frame(maxWidth: .infinity, alignment: .leading)
                Text(verbatim: row.target)
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .frame(width: ActivityColumns.target, alignment: .trailing)
                DecisionBadge(decision: row.decision, isError: row.isError)
                    .frame(width: ActivityColumns.decision, alignment: .leading)
                duration
                    .frame(width: ActivityColumns.duration, alignment: .trailing)
            }
            .frame(minWidth: ActivityColumns.wideMinimumWidth)

            VStack(alignment: .leading, spacing: Theme.Spacing.xs + 1) {
                HStack(alignment: .top, spacing: Theme.Spacing.md) {
                    action
                        .layoutPriority(1)
                    Spacer(minLength: Theme.Spacing.xs)
                    DecisionBadge(decision: row.decision, isError: row.isError)
                }

                HStack(spacing: Theme.Spacing.md) {
                    identity
                        .layoutPriority(1)
                    Spacer(minLength: Theme.Spacing.xs)
                    Label {
                        Text(verbatim: TimeFormat.clock(row.ts, locale: locale))
                    } icon: {
                        Image(systemName: "clock")
                            .accessibilityHidden(true)
                    }
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: true, vertical: false)
                    .accessibilityLabel("Time")
                    .accessibilityValue(Text(verbatim: TimeFormat.clock(row.ts, locale: locale)))
                }

                HStack(spacing: Theme.Spacing.md) {
                    Label {
                        Text(verbatim: row.target)
                            .lineLimit(1)
                            .truncationMode(.middle)
                    } icon: {
                        Image(systemName: "scope")
                            .accessibilityHidden(true)
                    }
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .layoutPriority(1)
                    .accessibilityLabel("Target")
                    .accessibilityValue(Text(verbatim: row.target))

                    Spacer(minLength: Theme.Spacing.xs)
                    duration
                        .fixedSize(horizontal: true, vertical: false)
                }
            }
        }
        // Match the header inset and remove the list's default row inset.
        .padding(.horizontal, Theme.screenPadding)
        .padding(.vertical, 4)
        .frame(maxWidth: .infinity, alignment: .leading)
        .listRowInsets(EdgeInsets())
        .listRowSeparator(.hidden)
        .listRowBackground(row.isFlagged ? Theme.danger.opacity(0.06) : Color.clear)
    }

    private var identity: some View {
        HStack(spacing: Theme.Spacing.xs) {
            if let o = row.origin {
                Image(systemName: (o.signed ?? false) ? "checkmark.seal.fill" : "exclamationmark.triangle.fill")
                    .font(.caption2)
                    .foregroundStyle((o.signed ?? false) ? Theme.verified : Theme.warning)
                    .accessibilityLabel(
                        Text((o.signed ?? false)
                             ? LocalizedStringResource("Valid code signature")
                             : LocalizedStringResource("Unsigned or not verified"))
                    )
                    .help(signatureHelp(for: o))
            }
            Text(verbatim: shortIdentity)
                .font(.callout)
                .fontWeight(.medium)
                .lineLimit(1)
                .truncationMode(.tail)
                .accessibilityLabel("Agent")
                .accessibilityValue(Text(verbatim: shortIdentity))
        }
    }

    private var action: some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(verbatim: row.tool)
                .font(.callout)
                .lineLimit(1)
            Text(verbatim: row.argsPreview)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(1)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Action")
        .accessibilityValue(Text(verbatim: actionAccessibilityValue))
    }

    private var duration: some View {
        Text(verbatim: durationText)
            .font(.caption2.monospaced())
            .foregroundStyle(.tertiary)
            .lineLimit(1)
            .accessibilityLabel("Took")
            .accessibilityValue(Text(verbatim: durationText))
    }

    private var durationText: String {
        row.durationMs.map { Self.formatDuration($0, locale: locale) } ?? ""
    }

    private var actionAccessibilityValue: String {
        row.argsPreview.isEmpty ? row.tool : "\(row.tool), \(row.argsPreview)"
    }

    private var shortIdentity: String {
        guard row.identity.hasPrefix("agent://") else { return row.identity }
        return String(row.identity.dropFirst("agent://".count))
    }

    /// Keeps captured names verbatim while localizing the app-owned status fallback.
    private func signatureHelp(for origin: ActivityOrigin) -> String {
        let status: String
        if origin.signed ?? false {
            status = origin.signedBy ?? String(localized: "Valid code signature")
        } else {
            status = String(localized: "Unsigned or not verified")
        }
        return "\(origin.displayName): \(status)"
    }

    /// Formats milliseconds for the activity table.
    static func formatDuration(_ ms: Int, locale: Locale = .autoupdatingCurrent) -> String {
        guard ms > 0 else {
            return Measurement(value: 0, unit: UnitDuration.milliseconds)
                .formatted(.measurement(width: .narrow, usage: .asProvided).locale(locale))
        }
        if ms < 1000 {
            return Measurement(value: Double(ms), unit: UnitDuration.milliseconds)
                .formatted(.measurement(width: .narrow, usage: .asProvided).locale(locale))
        }
        return Duration.seconds(Double(ms) / 1000).formatted(
            .units(allowed: [.minutes, .seconds], width: .narrow, maximumUnitCount: 2)
                .locale(locale)
        )
    }
}

struct DecisionBadge: View {
    let decision: String
    let isError: Bool

    @ViewBuilder var body: some View {
        switch decision {
        case "allow": StatusPill("Allowed", tint: tint)
        case "allowlist-allow": StatusPill("Allowed by allowlist", tint: tint)
        case "deny": StatusPill("Denied", tint: tint)
        case "ask→approved", "ask→approved (you)": StatusPill("Approved", tint: tint)
        case "ask→approved (auto)": StatusPill("Auto-approved", tint: tint)
        case "ask→denied", "ask→denied (you)": StatusPill("Denied", tint: tint)
        case "ask→timeout": StatusPill("Timed out", tint: tint)
        case "ask→cancelled": StatusPill("Cancelled", tint: tint)
        case "session-approved": StatusPill("Session approved", tint: tint)
        case "session-expired": StatusPill("Session expired", tint: tint)
        case "config": StatusPill("Configuration", tint: tint)
        case "info": StatusPill("Info", tint: tint)
        default: StatusPill(verbatim: decision, tint: tint)
        }
    }

    private var tint: Color {
        if isError || decision.lowercased().contains("deny") { return Theme.danger }
        if decision.lowercased().contains("ask") { return Theme.warning }
        // Lifecycle and configuration rows are informational.
        if decision == "session-expired" || decision == "config" { return .secondary }
        return Theme.verified
    }
}

struct ActivityDetailView: View {
    let row: ActivityRow
    var model: AppModel? = nil
    let onClose: () -> Void

    @Environment(\.locale) private var locale
    @State private var recordingError: String?
    @State private var savingRecording = false

    var body: some View {
        SheetScaffold("Activity detail", systemImage: "list.bullet.rectangle", width: 460) {
            DecisionBadge(decision: row.decision, isError: row.isError)
            VStack(alignment: .leading, spacing: Theme.Spacing.sm) {
                detailRow("Time", TimeFormat.full(row.ts, locale: locale))
                detailRow("Identity", row.identity)
                detailRow("Channel", row.channel)
                detailRow("Tool", row.tool)
                detailRow("Args", row.argsPreview)
                detailRow("Target", row.target)
                detailRow("Decision", row.decision)
                if let rule = row.rule { detailRow("Rule", rule) }
                if let grant = row.grantId { detailRow("Legacy ID", grant) }
                if let bytes = row.bytesOut { detailRow("Bytes out", "\(bytes)") }
                if let ms = row.durationMs { detailRow("Duration", "\(ms) ms") }
            }
            if let origin = row.origin { originBlock(origin) }
            if let recording = row.recording, !recording.isEmpty, model != nil {
                recordingBlock(path: recording)
            }
        } footer: {
            HStack {
                Spacer()
                Button("Done", action: onClose).keyboardShortcut(.defaultAction)
            }
        }
    }

    /// Displays the captured executable, signature, path, and process chain.
    @ViewBuilder private func originBlock(_ o: ActivityOrigin) -> some View {
        Divider()
        SectionHeader("Calling application")
        VStack(alignment: .leading, spacing: Theme.Spacing.sm) {
            HStack(spacing: Theme.Spacing.sm) {
                Image(systemName: (o.signed ?? false) ? "checkmark.seal.fill" : "exclamationmark.triangle.fill")
                    .foregroundStyle((o.signed ?? false) ? Theme.verified : Theme.warning)
                Text(verbatim: o.displayName).fontWeight(.semibold)
                if let pid = o.pid, pid > 0 {
                    Text(verbatim: "pid \(pid)").font(.caption2.monospaced()).foregroundStyle(.tertiary)
                }
            }
            if let by = o.signedBy, !by.isEmpty {
                detailRow("Signed by", by)
            } else {
                detailRow(
                    "Signature",
                    (o.signed ?? false)
                        ? String(localized: "Valid")
                        : String(localized: "Unsigned or not verified")
                )
            }
            if let path = o.path, !path.isEmpty { detailRow("Path", path) }
            if let chain = o.chain, !chain.isEmpty { detailRow("Process chain", chain) }
        }
    }

    /// Decrypts and saves an SSH session recording for asciinema playback.
    @ViewBuilder private func recordingBlock(path: String) -> some View {
        Divider()
        SectionHeader("Session recording")
        VStack(alignment: .leading, spacing: Theme.Spacing.sm) {
            Text("Encrypted SSH session. Save it for playback with `asciinema play`.")
                .font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            HStack(spacing: Theme.Spacing.sm) {
                Button {
                    Task { await saveRecording(path: path) }
                } label: {
                    Label(savingRecording ? "Decrypting…" : "Save recording…",
                          systemImage: "square.and.arrow.down")
                }
                .disabled(savingRecording)
                if let recordingError {
                    Label {
                        Text(verbatim: recordingError)
                    } icon: {
                        Image(systemName: "exclamationmark.triangle.fill")
                    }
                        .font(.caption).foregroundStyle(Theme.danger)
                }
            }
        }
    }

    private func saveRecording(path: String) async {
        guard let model else { return }
        recordingError = nil
        savingRecording = true
        defer { savingRecording = false }
        let data: Data
        do {
            data = try await model.decryptRecording(path: path)
        } catch {
            recordingError = String(localized: "Could not decrypt the recording. Unlock the vault and try again.")
            return
        }
        let panel = NSSavePanel()
        panel.nameFieldStringValue = (path as NSString).lastPathComponent
            .replacingOccurrences(of: ".sealed", with: "")
        panel.allowedContentTypes = []
        guard panel.runModal() == .OK, let url = panel.url else { return }
        try? data.write(to: url)
    }

    private func detailRow(_ key: LocalizedStringResource, _ value: String) -> some View {
        KeyValueRow(key, keyWidth: 90) {
            Text(verbatim: value).font(.callout.monospaced()).textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
                // Limit untrusted previews to the fixed-width sheet.
                .lineLimit(12)
        }
    }
}

enum TimeFormat {
    /// Parses timestamps with or without fractional seconds.
    private static func parse(_ rfc3339: String) -> Date? {
        try? Date(rfc3339, strategy: .iso8601)
    }

    static func clock(_ rfc3339: String) -> String {
        clock(rfc3339, locale: .autoupdatingCurrent)
    }

    /// Uses the locale's preferred hour cycle, including the user's 12/24-hour override.
    static func clock(
        _ rfc3339: String,
        locale: Locale,
        timeZone: TimeZone = .autoupdatingCurrent
    ) -> String {
        guard let date = parse(rfc3339) else { return rfc3339 }
        return date.formatted(
            Date.FormatStyle(
                date: .omitted,
                time: .standard,
                locale: locale,
                timeZone: timeZone
            )
        )
    }

    static func full(_ rfc3339: String) -> String {
        full(rfc3339, locale: .autoupdatingCurrent)
    }

    static func full(
        _ rfc3339: String,
        locale: Locale,
        timeZone: TimeZone = .autoupdatingCurrent
    ) -> String {
        guard let date = parse(rfc3339) else { return rfc3339 }
        return date.formatted(
            Date.FormatStyle(
                date: .abbreviated,
                time: .standard,
                locale: locale,
                timeZone: timeZone
            )
        )
    }

    /// Formats a date without its time.
    static func day(_ rfc3339: String) -> String {
        day(rfc3339, locale: .autoupdatingCurrent)
    }

    static func day(
        _ rfc3339: String,
        locale: Locale,
        timeZone: TimeZone = .autoupdatingCurrent
    ) -> String {
        guard let date = parse(rfc3339) else { return rfc3339 }
        return date.formatted(
            Date.FormatStyle(
                date: .abbreviated,
                time: .omitted,
                locale: locale,
                timeZone: timeZone
            )
        )
    }
}

#if DEBUG && !SP_NO_PREVIEWS
#Preview("Activity (light)") {
    ActivityFeedView(model: AppModel.previewModel())
        .frame(width: 900, height: 560)
        .preferredColorScheme(.light)
}

#if !SP_NO_PREVIEWS
#Preview("Activity (dark)") {
    ActivityFeedView(model: AppModel.previewModel())
        .frame(width: 900, height: 560)
        .preferredColorScheme(.dark)
}
#endif
#endif
