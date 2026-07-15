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
        HStack(spacing: Theme.Spacing.md) {
            headerCell("Time", width: ActivityColumns.time, align: .leading)
            headerCell("Agent", width: ActivityColumns.identity, align: .leading)
            Text("Action").frame(maxWidth: .infinity, alignment: .leading)
            headerCell("Target", width: ActivityColumns.target, align: .trailing)
            headerCell("Decision", width: ActivityColumns.decision, align: .leading)
            headerCell("Took", width: ActivityColumns.duration, align: .trailing)
        }
        .font(.caption2.weight(.semibold)).tracking(0.5)
        .foregroundStyle(.tertiary)
        .padding(.horizontal, Theme.screenPadding)
        .padding(.vertical, Theme.Spacing.sm)
    }

    private func headerCell(_ text: String, width: CGFloat, align: Alignment) -> some View {
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
        HStack(spacing: Theme.Spacing.md) {
            HStack(spacing: Theme.Spacing.sm) {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                TextField("Filter identity, tool, target…", text: $model.filter.query)
                    .textFieldStyle(.plain)
            }
            .padding(.horizontal, Theme.Spacing.sm).padding(.vertical, 5)
            .background(Theme.Surface.inset, in: RoundedRectangle(cornerRadius: Theme.Radius.md, style: .continuous))
            .frame(maxWidth: 320)

            Picker("Channel", selection: Binding(
                get: { model.filter.channel ?? "" },
                set: { model.filter.channel = $0.isEmpty ? nil : $0 })
            ) {
                Text("All channels").tag("")
                ForEach(model.activity.channels, id: \.self) { Text($0).tag($0) }
            }
            .labelsHidden()
            .fixedSize()

            Toggle(isOn: $model.filter.onlyFlagged) {
                Label("Flagged", systemImage: "exclamationmark.triangle")
            }
            .toggleStyle(.button)
            .controlSize(.small)

            Spacer()

            Text("\(rows.count) \(rows.count == 1 ? "event" : "events")")
                .font(.caption).foregroundStyle(.secondary)
        }
        .padding(.horizontal, Theme.screenPadding).padding(.vertical, Theme.Spacing.sm + 2)
    }
}

/// Shared widths for the activity header and rows.
enum ActivityColumns {
    static let time: CGFloat = 66
    static let identity: CGFloat = 118
    static let target: CGFloat = 120
    static let decision: CGFloat = 150
    static let duration: CGFloat = 62
}

struct ActivityRowView: View {
    let row: ActivityRow

    var body: some View {
        HStack(spacing: Theme.Spacing.md) {
            Text(TimeFormat.clock(row.ts))
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
                .frame(width: ActivityColumns.time, alignment: .leading)
            HStack(spacing: 4) {
                if let o = row.origin {
                    Image(systemName: (o.signed ?? false) ? "checkmark.seal.fill" : "exclamationmark.triangle.fill")
                        .font(.caption2)
                        .foregroundStyle((o.signed ?? false) ? Theme.verified : Theme.warning)
                        .help((o.signed ?? false)
                              ? "\(o.displayName): \(o.signedBy ?? "signed")"
                              : "\(o.displayName): unsigned or not verified")
                }
                Text(shortIdentity)
                    .font(.callout).fontWeight(.medium)
                    .lineLimit(1).truncationMode(.tail)
            }
            .frame(width: ActivityColumns.identity, alignment: .leading)
            // The action column absorbs remaining width.
            VStack(alignment: .leading, spacing: 1) {
                Text(row.tool).font(.callout).lineLimit(1)
                Text(row.argsPreview).font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            Text(row.target).font(.caption.monospaced()).foregroundStyle(.secondary)
                .lineLimit(1).truncationMode(.middle)
                .frame(width: ActivityColumns.target, alignment: .trailing)
            DecisionBadge(decision: row.decision, isError: row.isError)
                .frame(width: ActivityColumns.decision, alignment: .leading)
            Text(row.durationMs.map(Self.formatDuration) ?? "")
                .font(.caption2.monospaced()).foregroundStyle(.tertiary)
                .lineLimit(1)
                .frame(width: ActivityColumns.duration, alignment: .trailing)
        }
        // Match the header inset and remove the list's default row inset.
        .padding(.horizontal, Theme.screenPadding)
        .padding(.vertical, 4)
        .frame(maxWidth: .infinity, alignment: .leading)
        .listRowInsets(EdgeInsets())
        .listRowSeparator(.hidden)
        .listRowBackground(row.isFlagged ? Theme.danger.opacity(0.06) : Color.clear)
    }

    private var shortIdentity: String {
        row.identity.replacingOccurrences(of: "agent://", with: "")
    }

    /// Formats milliseconds for the activity table.
    static func formatDuration(_ ms: Int) -> String {
        guard ms > 0 else { return "0ms" }
        if ms < 1000 { return "\(ms)ms" }
        let s = Double(ms) / 1000
        if s < 10 { return String(format: "%.1fs", s) }
        // Integer quotient/remainder avoids converting a rounded Double near
        // Int.max, which can become Int.max+1 and terminate the UI process.
        let total = ms / 1000 + (ms % 1000 >= 500 ? 1 : 0)
        if total < 60 { return "\(total)s" }
        return "\(total / 60)m \(total % 60)s"
    }
}

struct DecisionBadge: View {
    let decision: String
    let isError: Bool

    var body: some View {
        StatusPill(decision, tint: tint)
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

    @State private var recordingError: String?
    @State private var savingRecording = false

    var body: some View {
        SheetScaffold("Activity detail", systemImage: "list.bullet.rectangle", width: 460) {
            DecisionBadge(decision: row.decision, isError: row.isError)
            VStack(alignment: .leading, spacing: Theme.Spacing.sm) {
                detailRow("Time", TimeFormat.full(row.ts))
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
                Text(o.displayName).fontWeight(.semibold)
                if let pid = o.pid, pid > 0 {
                    Text("pid \(pid)").font(.caption2.monospaced()).foregroundStyle(.tertiary)
                }
            }
            if let by = o.signedBy, !by.isEmpty {
                detailRow("Signed by", by)
            } else {
                detailRow("Signature", (o.signed ?? false) ? "valid" : "unsigned / not verified")
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
                    Label(recordingError, systemImage: "exclamationmark.triangle.fill")
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
            recordingError = "Could not decrypt the recording. Unlock the vault and try again."
            return
        }
        let panel = NSSavePanel()
        panel.nameFieldStringValue = (path as NSString).lastPathComponent
            .replacingOccurrences(of: ".sealed", with: "")
        panel.allowedContentTypes = []
        guard panel.runModal() == .OK, let url = panel.url else { return }
        try? data.write(to: url)
    }

    private func detailRow(_ key: String, _ value: String) -> some View {
        KeyValueRow(key, keyWidth: 90) {
            Text(value).font(.callout.monospaced()).textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
                // Limit untrusted previews to the fixed-width sheet.
                .lineLimit(12)
        }
    }
}

enum TimeFormat {
    // Reuse immutable formatters across rows.
    nonisolated(unsafe) private static let iso = ISO8601DateFormatter()
    nonisolated(unsafe) private static let isoFrac: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()
    private static let hms: DateFormatter = { let f = DateFormatter(); f.dateFormat = "HH:mm:ss"; return f }()
    private static let medium: DateFormatter = { let f = DateFormatter(); f.dateStyle = .medium; f.timeStyle = .medium; return f }()
    private static let dayOnly: DateFormatter = { let f = DateFormatter(); f.dateStyle = .medium; f.timeStyle = .none; return f }()

    /// Parses timestamps with or without fractional seconds.
    private static func parse(_ rfc3339: String) -> Date? {
        isoFrac.date(from: rfc3339) ?? iso.date(from: rfc3339)
    }

    static func clock(_ rfc3339: String) -> String {
        guard let date = parse(rfc3339) else { return String(rfc3339.suffix(8).prefix(8)) }
        return hms.string(from: date)
    }
    static func full(_ rfc3339: String) -> String {
        guard let date = parse(rfc3339) else { return rfc3339 }
        return medium.string(from: date)
    }
    /// Formats a date without its time.
    static func day(_ rfc3339: String) -> String {
        guard let date = parse(rfc3339) else { return rfc3339 }
        return dayOnly.string(from: date)
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
