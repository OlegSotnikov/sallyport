import Testing
import Foundation
@testable import SallyportVault

@Suite("Classify — ssh command risk")
struct ClassifyTests {
    @Test("readonly binary → readonly")
    func readonly() {
        #expect(Classify.classify("df -h /").cls == "readonly")
        #expect(Classify.classify("cat /etc/hostname").cls == "readonly")
    }
    @Test("write binary → write")
    func write() {
        #expect(Classify.classify("systemctl restart nginx").cls == "write")
    }
    @Test("any composition → composite (fail-closed)")
    func composite() {
        #expect(Classify.classify("cat x | grep y").cls == "composite")
        #expect(Classify.classify("sudo ls").cls == "composite")
        #expect(Classify.classify("rm -rf / && echo done").cls == "composite")
    }
    @Test("unknown binary → unknown")
    func unknown() {
        #expect(Classify.classify("frobnicate --all").cls == "unknown")
    }
    @Test("empty → unknown")
    func empty() {
        #expect(Classify.classify("   ").cls == "unknown")
    }
    @Test("RouterOS read verb → readonly, write verb → write")
    func routerOS() {
        #expect(Classify.classify("/system identity print").cls == "readonly")
        #expect(Classify.classify("/ip address add address=1.2.3.4").cls == "write")
        // A Linux absolute path is NOT misread as RouterOS.
        #expect(Classify.classify("/usr/bin/whoami").cls == "unknown")
    }
}

@Suite("Settings — vault-backed posture")
struct SettingsTests {
    @Test("defaults: per-session auth ON, bodies OFF")
    func defaults() {
        let s = SettingsStore()
        #expect(s.perSessionAuth())
        #expect(!s.logBodies())
    }

    @Test("update mutates AND persists through the vault sink")
    func updatePersists() async throws {
        final class Captured: @unchecked Sendable { var last: SettingsState? }
        let captured = Captured()
        let s = SettingsStore()
        s.onPersist { st in captured.last = st }
        try await s.update { $0.sessionAuth = SettingsStore.sessionAuthOff; $0.logBodies = true }
        #expect(!s.perSessionAuth())
        #expect(s.logBodies())
        #expect(captured.last?.sessionAuth == "off")
        #expect(captured.last?.logBodies == true)
    }

    @Test("hydrate installs the vault-decrypted state; clear returns to defaults")
    func hydrateAndClear() {
        let s = SettingsStore()
        s.hydrate(SettingsState(sessionAuth: SettingsStore.sessionAuthOff, logBodies: true))
        #expect(!s.perSessionAuth() && s.logBodies())
        s.clear()
        #expect(s.perSessionAuth() && !s.logBodies())
    }

    @Test("legacy/unknown fields are ignored on decode, v2 fields kept")
    func legacyIgnored() throws {
        let json = #"{"strict":true,"trusted":["x"],"requireToken":true,"logBodies":true}"#
        let st = try JSONDecoder().decode(SettingsState.self, from: Data(json.utf8))
        #expect(st.sessionAuth == nil)      // absent ⇒ the default ceremony
        #expect(st.logBodies)
    }

    @Test("the session gate has THREE ceremonies; the old boolean still reads")
    func sessionAuthThreeWays() throws {
        let s = SettingsStore()
        #expect(s.sessionAuth() == "click")   // default: one click
        #expect(s.perSessionAuth())

        s.hydrate(SettingsState(sessionAuth: "touchid"))
        #expect(s.sessionAuth() == "touchid")
        #expect(s.perSessionAuth())           // touchid still gates

        s.hydrate(SettingsState(sessionAuth: "off"))
        #expect(!s.perSessionAuth())          // observe mode

        // An unknown value can never weaken the gate.
        s.hydrate(SettingsState(sessionAuth: "banana"))
        #expect(s.sessionAuth() == "click")

        // A settings blob sealed by the old two-state build still decodes.
        let legacyOn = try JSONDecoder().decode(
            SettingsState.self, from: Data(#"{"perSessionAuth":true}"#.utf8))
        #expect(legacyOn.sessionAuth == "click")
        let legacyOff = try JSONDecoder().decode(
            SettingsState.self, from: Data(#"{"perSessionAuth":false}"#.utf8))
        #expect(legacyOff.sessionAuth == "off")
    }

    @Test("Touch ID for configuration changes is ON by default and survives a round-trip")
    func touchIDForChanges() throws {
        let s = SettingsStore()
        #expect(s.requireTouchIDForChanges())          // the safe default
        s.hydrate(SettingsState(requireTouchIDForChanges: false))
        #expect(!s.requireTouchIDForChanges())
        s.clear()
        #expect(s.requireTouchIDForChanges())          // lock ⇒ back to the safe default

        let encoded = try JSONEncoder().encode(SettingsState(sessionAuth: "touchid",
                                                             requireTouchIDForChanges: false))
        let back = try JSONDecoder().decode(SettingsState.self, from: encoded)
        #expect(back.sessionAuth == "touchid")
        #expect(back.requireTouchIDForChanges == false)
    }

    @Test("auto-lock TTL: default 8h, minutes map to seconds, 0 disables")
    func autoLockTTLMapping() {
        let s = SettingsStore()
        #expect(s.autoLockTTL() == TimeInterval(480 * 60))     // unset ⇒ default
        s.hydrate(SettingsState(autoLockMinutes: 15))
        #expect(s.autoLockTTL() == 900)
        s.hydrate(SettingsState(autoLockMinutes: 0))
        #expect(s.autoLockTTL() == nil)                        // 0 ⇒ OFF
    }

    @Test("lock-on-screen-lock defaults ON; explicit OFF survives")
    func lockOnScreenLockDefault() {
        let s = SettingsStore()
        #expect(s.lockOnScreenLock())
        s.hydrate(SettingsState(lockOnScreenLock: false))
        #expect(!s.lockOnScreenLock())
        s.clear()
        #expect(s.lockOnScreenLock())     // lock semantics: back to the safe default
    }
}

@Suite("HostsStore — vault-backed inventory")
struct HostsStoreTests {
    @Test("empty until hydrated; clear empties it again (lock semantics)")
    func hydrateClear() {
        let h = HostsStore()
        #expect(h.list().isEmpty)
        h.hydrate([.init(name: "prod-1", addr: "10.0.0.1", keyName: "deploy")])
        #expect(h.get("prod-1")?.addr == "10.0.0.1")
        #expect(h.ref("prod-1")?.keyName == "deploy")
        #expect(h.names() == ["prod-1"])
        h.clear()
        #expect(h.list().isEmpty)
        #expect(h.ref("prod-1") == nil)
    }

    @Test("set/delete persist the whole inventory through the vault sink")
    func persistThroughSink() async throws {
        final class Captured: @unchecked Sendable { var last: [HostsStore.Entry]? }
        let captured = Captured()
        let h = HostsStore()
        h.onPersist { entries in captured.last = entries }
        try await h.set(.init(name: "a", addr: "1.1.1.1"))
        try await h.set(.init(name: "b", addr: "2.2.2.2"))
        #expect(captured.last?.map(\.name) == ["a", "b"])
        let existed = try await h.delete("a")
        #expect(existed)
        #expect(captured.last?.map(\.name) == ["b"])
    }
}
