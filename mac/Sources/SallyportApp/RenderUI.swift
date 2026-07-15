#if DEBUG
import SwiftUI
import AppKit
import SallyportKit

/// Headless UI snapshots for visual verification (dev only):
///
///     sallyport-app --render-ui [outDir]
///
/// Renders demo-seeded screens in an offscreen window with `cacheDisplay`.
@MainActor
enum RenderUI {
    static func run() -> Never {
        let args = CommandLine.arguments
        let outPath = args.firstIndex(of: "--render-ui").flatMap { i in
            args.indices.contains(i + 1) && !args[i + 1].hasPrefix("-") ? args[i + 1] : nil
        } ?? "/tmp/sallyport-ui"
        let dir = URL(fileURLWithPath: outPath, isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)

        // AppKit must exist for windows; stay invisible (no Dock, no focus).
        let app = NSApplication.shared
        app.setActivationPolicy(.prohibited)

        let model = AppModel.previewModel()

        // Window size mirrors the shipped default (820×560 min 780×560).
        let winSize = CGSize(width: 980, height: 640)
        let menuSize = CGSize(width: 380, height: 560)

        func shoot<V: View>(_ name: String, size: CGSize, dark: Bool = false,
                            settle: TimeInterval = 0.7, @ViewBuilder _ view: () -> V) {
            let root = view()
                .frame(width: size.width, height: size.height)
                .preferredColorScheme(dark ? .dark : .light)
            let window = NSWindow(contentRect: CGRect(origin: CGPoint(x: -20000, y: -20000), size: size),
                                  styleMask: [.titled, .fullSizeContentView], backing: .buffered, defer: false)
            window.appearance = NSAppearance(named: dark ? .darkAqua : .aqua)
            window.contentView = NSHostingView(rootView: root)
            window.orderBack(nil)
            RunLoop.main.run(until: Date().addingTimeInterval(settle))
            guard let content = window.contentView,
                  let rep = content.bitmapImageRepForCachingDisplay(in: content.bounds) else {
                print("FAIL render \(name)"); window.close(); return
            }
            content.cacheDisplay(in: content.bounds, to: rep)
            if let png = rep.representation(using: .png, properties: [:]) {
                try? png.write(to: dir.appendingPathComponent("\(name).png"))
                print("wrote \(name).png")
            }
            window.close()
        }

        // Render the card first. The settings render below can crash on the
        // async notification-status load, and the cards are what we verify.
        shoot("card-credential", size: CGSize(width: 520, height: 560)) {
            ApprovalCardView(request: Fixtures.sessionCredential, model: model)
                .padding()
        }

        // Main window on each tab.
        for tab in MainTab.allCases {
            model.selectedTab = tab
            shoot("win-\(tab.rawValue)", size: winSize) { RootWindowView(model: model) }
        }
        model.selectedTab = .approvals
        shoot("win-approvals-dark", size: winSize, dark: true) { RootWindowView(model: model) }

        // Initial onboarding state.
        let fresh = AppModel.previewModel()
        fresh.onboarding = OnboardingState()
        fresh.selectedTab = .setup
        shoot("win-setup-fresh", size: winSize) { RootWindowView(model: fresh) }

        // Menu bar with and without a pending approval.
        shoot("menubar-pending", size: menuSize) { MenuBarContentView(model: model) }
        let calm = AppModel.previewModel()
        calm.pending = []
        shoot("menubar-calm", size: menuSize, dark: true) { MenuBarContentView(model: calm) }

        // Approval cards and credential request sheet.
        shoot("card-ssh", size: CGSize(width: 520, height: 640)) {
            ApprovalCardView(request: Fixtures.sshRestartNginx, model: model)
                .padding()
        }
        shoot("card-session", size: CGSize(width: 520, height: 640), dark: true) {
            ApprovalCardView(request: Fixtures.sessionClaude, model: model)
                .padding()
        }
        let credReq = CredentialRequest(
            id: "cr-demo", host: "api.stripe.com",
            hosts: ["api.stripe.com", "files.stripe.com"],
            purpose: "Create a payment link for the invoice flow",
            kind: "bearer", suggestedName: "stripe_key",
            docsURL: "https://dashboard.stripe.com/apikeys",
            scopes: ["payment_links:write"], provenance: Fixtures.provenanceIntact)
        shoot("credential-sheet", size: CGSize(width: 560, height: 700)) {
            CredentialRequestSheet(request: credReq, model: model)
        }

        // Reset confirmation sheet.
        shoot("sheet-reset", size: CGSize(width: 560, height: 560)) {
            ResetVaultSheetPreview(model: model)
        }

        // Add-key form in its initial and locked states, plus the SSH host form.
        let locked = AppModel.previewModel()
        locked.vault = VaultState(locked: true, ttlSec: 0)
        shoot("form-addkey-locked", size: CGSize(width: 560, height: 720)) {
            SecretEditor(existing: nil, knownSecrets: [],
                         vaultLocked: true,
                         unlockVault: { true }) { _ in .saved }
        }
        shoot("form-addkey", size: CGSize(width: 560, height: 720)) {
            SecretEditor(existing: nil, knownSecrets: [],
                         prefill: SecretPrefill(name: "", kind: .header, bind: []),
                         vaultLocked: false, unlockVault: { true }) { _ in .saved }
        }

        // Diagnostic: if this bare sidebar list renders rows while the
        // NavigationSplitView sidebar shows blank, the blank is the offscreen
        // cacheDisplay artifact of the sidebar material, not a product bug.
        shoot("diag-sidebar", size: CGSize(width: 240, height: 400)) {
            List {
                Section("Monitor") {
                    Label("Approvals", systemImage: "checkmark.shield")
                    Label("Activity", systemImage: "list.bullet.rectangle")
                }
                Section("Configure") {
                    Label("Keys & APIs", systemImage: "key.fill")
                }
            }.listStyle(.sidebar)
        }

        // Diagnostic: constant switch values distinguish an offscreen
        // NSSwitch rendering regression check.
        shoot("diag-toggles", size: CGSize(width: 300, height: 140)) {
            VStack(spacing: 20) {
                Toggle("On", isOn: .constant(true)).toggleStyle(.switch).tint(Theme.accent)
                Toggle("Off", isOn: .constant(false)).toggleStyle(.switch).tint(Theme.accent)
            }.padding()
        }

        print("done: \(dir.path)")
        exit(0)
    }
}
#endif
