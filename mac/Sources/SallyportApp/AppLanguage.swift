import AppKit
import Foundation

/// Languages Sallyport ships in. Names are intentionally written in each
/// language so the picker remains usable regardless of the current locale.
enum AppLanguage: String, CaseIterable, Identifiable, Sendable {
    case system
    case english = "en"
    case german = "de"
    case spanish = "es"
    case french = "fr"
    case portugueseBrazil = "pt-BR"
    case russian = "ru"
    case simplifiedChinese = "zh-Hans"

    var id: String { rawValue }

    var nativeName: String {
        switch self {
        case .system: ""
        case .english: "English"
        case .german: "Deutsch"
        case .spanish: "Español"
        case .french: "Français"
        case .portugueseBrazil: "Português (Brasil)"
        case .russian: "Русский"
        case .simplifiedChinese: "简体中文"
        }
    }
}

/// Launch-scoped language state. `running` must come from the App instance,
/// while `selected` may change whenever Settings is reopened.
struct AppLanguageSelection: Equatable, Sendable {
    let running: AppLanguage
    var selected: AppLanguage

    var requiresRestart: Bool { selected != running }
}

/// Coordinates an explicit relaunch without losing the new process to the
/// app's single-instance guard while the old process is still shutting down.
enum AppRelaunch {
    static let sourcePIDArgument = "--relaunch-from-pid"

    static func sourcePID(in arguments: [String]) -> pid_t? {
        guard let index = arguments.firstIndex(of: sourcePIDArgument),
              arguments.indices.contains(index + 1),
              let pid = pid_t(arguments[index + 1]),
              pid > 1 else {
            return nil
        }
        return pid
    }

    static func waitForSourceExit(pid: pid_t, timeout: TimeInterval = 15) {
        guard pid != ProcessInfo.processInfo.processIdentifier else { return }
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            guard let source = NSRunningApplication(processIdentifier: pid),
                  !source.isTerminated else {
                return
            }
            Thread.sleep(forTimeInterval: 0.1)
        }
    }
}

/// Stores a per-app language override. macOS chooses a bundle localization at
/// process launch, so a language change is applied by restarting Sallyport.
@MainActor
enum AppLanguagePreference {
    static let defaultsKey = "AppleLanguages"

    static var current: AppLanguage {
        current(appDomain: appDomain())
    }

    /// Pure projection used by tests and by the app-domain preference reader.
    static func current(appDomain: [String: Any]?) -> AppLanguage {
        guard let languages = appDomain?[defaultsKey] as? [String],
              let identifier = languages.first,
              let language = AppLanguage(rawValue: identifier) else {
            return .system
        }
        return language
    }

    static func set(_ language: AppLanguage,
                    defaults: UserDefaults = .standard) {
        if language == .system {
            defaults.removeObject(forKey: defaultsKey)
        } else {
            defaults.set([language.rawValue], forKey: defaultsKey)
        }
        // The app exits immediately after Restart, so flush the app-domain value first.
        defaults.synchronize()
    }

    /// Starts a fresh instance through Launch Services, then exits this one.
    static func restart() {
        let bundleURL = Bundle.main.bundleURL
        guard bundleURL.pathExtension == "app" else {
            NSApp.terminate(nil)
            return
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/open")
        process.arguments = [
            "-n", bundleURL.path, "--args", "--show-settings",
            AppRelaunch.sourcePIDArgument,
            String(ProcessInfo.processInfo.processIdentifier),
        ]
        process.terminationHandler = { process in
            let succeeded = process.terminationStatus == 0
            Task { @MainActor in
                if succeeded {
                    NSApp.terminate(nil)
                } else {
                    showRestartError()
                }
            }
        }
        do {
            try process.run()
        } catch {
            let alert = NSAlert(error: error)
            alert.runModal()
        }
    }

    private static func showRestartError() {
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = String(localized: "Sallyport could not restart.")
        alert.runModal()
    }

    private static func appDomain() -> [String: Any]? {
        guard let identifier = Bundle.main.bundleIdentifier else { return nil }
        return UserDefaults.standard.persistentDomain(forName: identifier)
    }
}
