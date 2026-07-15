import SwiftUI
import AppKit
import SallyportKit

/// Shows pending approvals in a floating panel when native notifications are unavailable.
/// Closing the panel leaves the request pending.
@MainActor
final class ApprovalPanelController: NSObject, NSWindowDelegate {
    /// Stable identity used to keep the approval panel out of main-window routing.
    static let windowIdentifier = NSUserInterfaceItemIdentifier("dev.sallyport.mac.approval-panel")

    private var window: NSWindow?

    /// Updates the panel on the next run-loop turn to avoid re-entering SwiftUI updates.
    func sync(model: AppModel) {
        let shouldShow = model.hasPendingApproval && !model.autoApprove && !model.isDemo
        DispatchQueue.main.async { [weak self] in
            MainActor.assumeIsolated {
                if shouldShow { self?.present(model: model) } else { self?.close() }
            }
        }
    }

    private func present(model: AppModel) {
        // Keep accessory activation policy so MenuBarExtra remains responsive.
        if window == nil {
            let w = NSWindow(
                contentRect: NSRect(x: 0, y: 0, width: 500, height: 560),
                styleMask: [.titled, .closable, .fullSizeContentView],
                backing: .buffered, defer: false)
            w.titlebarAppearsTransparent = true
            w.titleVisibility = .hidden
            w.title = String(localized: "Approval required")
            w.identifier = Self.windowIdentifier
            w.isReleasedWhenClosed = false
            w.level = .floating
            w.hidesOnDeactivate = false
            w.isMovableByWindowBackground = true
            // .canJoinAllSpaces and .moveToActiveSpace are mutually exclusive.
            w.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
            let hosting = NSHostingView(rootView: ApprovalPanelContent(model: model))
            hosting.sizingOptions = [.preferredContentSize]
            w.contentView = hosting
            w.delegate = self
            window = w
        }
        guard let w = window else { return }
        positionTopCenter(w)
        NSApp.activate(ignoringOtherApps: true)
        w.makeKeyAndOrderFront(nil)
    }

    private func close() {
        window?.orderOut(nil)
        window = nil
    }

    /// Positions the panel near the top center of the main screen.
    private func positionTopCenter(_ w: NSWindow) {
        guard let screen = NSScreen.main else { w.center(); return }
        let vf = screen.visibleFrame
        w.layoutIfNeeded()
        let size = w.frame.size
        w.setFrameOrigin(NSPoint(x: vf.midX - size.width / 2, y: vf.maxY - size.height - 24))
    }

    // Closing the panel leaves the request pending.
    func windowShouldClose(_ sender: NSWindow) -> Bool {
        window = nil
        return true
    }
}

/// Current approval and pending-request count for the floating panel.
private struct ApprovalPanelContent: View {
    @Bindable var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            if let approval = model.currentApproval {
                ScrollView {
                    ApprovalCardView(request: approval, model: model)
                        .padding(Theme.Spacing.md)
                }
                if model.pending.count > 1 {
                    let remaining = model.pending.count - 1
                    HStack(spacing: Theme.Spacing.xs + 2) {
                        Image(systemName: "square.stack.3d.up.fill")
                            .font(.caption2)
                            .accessibilityHidden(true)
                        Text("\(remaining) more requests",
                             comment: "Number of approval requests waiting behind the current request. Configure plural variations for the request count.")
                    }
                    .font(.caption).foregroundStyle(.secondary)
                    .padding(.horizontal, Theme.Spacing.lg).padding(.bottom, Theme.Spacing.sm)
                }
            } else {
                Color.clear.frame(width: 460, height: 1)
            }
        }
        .frame(width: 500)
    }
}
