import SwiftUI
import AppKit
import SallyportKit

/// Defines the menu-bar item and main Sallyport window.
struct SallyportApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @State private var model: AppModel
    @State private var updater = SoftwareUpdater()

    init() {
        let model = AppModel()
        if CommandLine.arguments.contains("--demo") {
            model.loadDemo()
        } else {
            // Start the runtime before any scene appears.
            model.startConnecting()
        }
        _model = State(initialValue: model)
    }

    var body: some Scene {
        MenuBarExtra {
            MenuBarContentView(model: model, updater: updater)
        } label: {
            // Capture `openWindow` from the always-present menu-bar scene.
            MenuBarLabel(model: model)
        }
        .menuBarExtraStyle(.window)

        // WindowGroup keeps MenuBarExtra responsive after the main window closes.
        WindowGroup("Sallyport", id: "main") {
            RootWindowView(model: model)
                // startConnecting is idempotent.
                .task { if !model.isDemo { model.startConnecting() } }
        }
        .windowResizability(.contentMinSize)
        .defaultSize(width: 820, height: 560)
        .commands { CommandGroup(replacing: .newItem) {} }
    }
}

/// Uses accessory mode normally and regular app mode for UI rendering.
final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        if CommandLine.arguments.contains("--demo") {
            NSApp.setActivationPolicy(.regular)
            NSApp.activate(ignoringOtherApps: true)
        } else {
            NSApp.setActivationPolicy(.accessory)
            // Normal launch starts with only the menu-bar item visible.
            DispatchQueue.main.async {
                for window in NSApp.windows where window.isVisible && window.canBecomeKey {
                    window.close()
                }
            }
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }
}


/// Menu-bar icon and main-window opener.
private struct MenuBarLabel: View {
    let model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Image(systemName: model.menuBarSymbol)
            .onAppear {
                model.openMainWindow = { raiseOrOpenMainWindow(openWindow) }
            }
    }
}
