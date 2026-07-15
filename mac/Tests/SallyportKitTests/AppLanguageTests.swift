import Foundation
import Testing
@testable import SallyportApp

@MainActor
@Suite("App language preference")
struct AppLanguageTests {
    @Test("the app domain distinguishes System Default from an override")
    func currentLanguage() {
        #expect(AppLanguagePreference.current(appDomain: nil) == .system)
        #expect(AppLanguagePreference.current(appDomain: [:]) == .system)
        #expect(AppLanguagePreference.current(
            appDomain: [AppLanguagePreference.defaultsKey: ["ru"]]) == .russian)
        #expect(AppLanguagePreference.current(
            appDomain: [AppLanguagePreference.defaultsKey: ["zh-Hans"]]) == .simplifiedChinese)
    }

    @Test("unsupported overrides fail back to System Default")
    func unsupportedLanguage() {
        #expect(AppLanguagePreference.current(
            appDomain: [AppLanguagePreference.defaultsKey: ["ja"]]) == .system)
        #expect(AppLanguagePreference.current(
            appDomain: [AppLanguagePreference.defaultsKey: "ru"]) == .system)
    }

    @Test("every shipped override has a native display name")
    func nativeNames() {
        for language in AppLanguage.allCases where language != .system {
            #expect(!language.nativeName.isEmpty)
        }
    }

    @Test("the override is written and System Default removes it")
    func writesOverride() {
        let suite = "dev.sallyport.tests.language.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }

        AppLanguagePreference.set(.russian, defaults: defaults)
        #expect(defaults.stringArray(forKey: AppLanguagePreference.defaultsKey) == ["ru"])

        AppLanguagePreference.set(.system, defaults: defaults)
        #expect(defaults.persistentDomain(forName: suite)?[AppLanguagePreference.defaultsKey] == nil)
    }

    @Test("reopening Settings keeps the launch language as the restart baseline")
    func restartBaseline() {
        var selection = AppLanguageSelection(running: .english, selected: .russian)
        #expect(selection.requiresRestart)

        selection.selected = .english
        #expect(!selection.requiresRestart)
    }

    @Test("relaunch source PID parsing rejects malformed handoffs")
    func relaunchPID() {
        #expect(AppRelaunch.sourcePID(in: ["Sallyport"]) == nil)
        #expect(AppRelaunch.sourcePID(in: ["Sallyport", AppRelaunch.sourcePIDArgument]) == nil)
        #expect(AppRelaunch.sourcePID(in: ["Sallyport", AppRelaunch.sourcePIDArgument, "nope"]) == nil)
        #expect(AppRelaunch.sourcePID(in: ["Sallyport", AppRelaunch.sourcePIDArgument, "1"]) == nil)
        #expect(AppRelaunch.sourcePID(in: ["Sallyport", AppRelaunch.sourcePIDArgument, "123"]) == 123)
    }
}
