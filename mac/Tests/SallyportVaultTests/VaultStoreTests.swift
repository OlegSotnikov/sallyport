import Testing
import Foundation
import CryptoKit
@testable import SallyportVault

/// A fresh per-test vault path under a unique temp directory.
private func freshVaultURL() throws -> URL {
    let dir = FileManager.default.temporaryDirectory
        .appendingPathComponent("sallyport-vaultstore-tests", isDirectory: true)
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    return dir.appendingPathComponent("vault.db", isDirectory: false)
}

@Suite("VaultStore — encrypted SQLite secret store")
struct VaultStoreTests {

    private func newStore() throws -> VaultStore {
        try VaultStore(creatingAt: freshVaultURL(), keystore: FileAgeKeystore())
    }

    // MARK: Round-trip

    @Test("init → set → list → resolve round-trip; the value never appears in metadata or on disk")
    func roundTrip() async throws {
        let url = try freshVaultURL()
        let store = try VaultStore(creatingAt: url, keystore: FileAgeKeystore())
        let secret = Data("cf_live_token_abc123".utf8)
        try await store.set(
            SecretMeta(name: "cf_token", kind: "bearer",
                       bindHosts: ["api.cloudflare.com"],
                       inject: Inject(adapter: "bearer", header: "Authorization",
                                      format: "Bearer {secret}")),
            value: secret)

        let listed = try await store.list()
        #expect(listed.count == 1)
        #expect(listed[0].name == "cf_token")
        #expect(listed[0].version == 1)
        #expect(listed[0].kind == "bearer")
        #expect(listed[0].bindHosts == ["api.cloudflare.com"])

        // The secret value must never surface through metadata.
        let metaJSON = String(decoding: try JSONEncoder().encode(listed), as: UTF8.self)
        #expect(!metaJSON.contains("cf_live_token_abc123"))

        // The bound host injects the right value.
        let cred = try await store.resolve(host: "api.cloudflare.com", path: "/zones")
        #expect(cred?.secret == secret)
        #expect(cred?.name == "cf_token")
        #expect(cred?.kind == "bearer")
        #expect(cred?.inject.adapter == "bearer")
        #expect(cred?.inject.header == "Authorization")

        // An unbound host resolves to nothing.
        let none = try await store.resolve(host: "evil.com", path: "/zones")
        #expect(none == nil)

        // Ciphertext at rest — v2 seals METADATA too: neither the value nor the
        // name, kind, bound host or header ever appear in the raw DB file.
        let raw = try Data(contentsOf: url)
        #expect(raw.range(of: secret) == nil)
        #expect(raw.range(of: Data("cf_token".utf8)) == nil)
        #expect(raw.range(of: Data("api.cloudflare.com".utf8)) == nil)
        #expect(raw.range(of: Data("bearer".utf8)) == nil)
        #expect(raw.range(of: Data("Authorization".utf8)) == nil)

        // secretValue (bind-by-name path, e.g. ssh keys) returns the same bytes.
        let byName = try await store.secretValue(name: "cf_token")
        #expect(byName == secret)
        await store.close()
    }

    @Test("overlapping host bindings resolve deterministically — boundMeta and resolve agree (#7)")
    func overlappingBindingsDeterministic() async throws {
        let store = try newStore()
        // Two secrets bind the SAME host with DIFFERENT ceremony flags. If the
        // ladder's flag read (boundMeta) and the injected credential (resolve)
        // picked different rows, you could approve one key and inject another.
        try await store.set(SecretMeta(name: "zzz_key", kind: "bearer", bindHosts: ["api.x.com"],
                                       inject: Inject(adapter: "bearer", header: "Authorization",
                                                      format: "Bearer {secret}"), confirm: ""),
                            value: Data("ZZZ".utf8))
        try await store.set(SecretMeta(name: "aaa_key", kind: "bearer", bindHosts: ["api.x.com"],
                                       inject: Inject(adapter: "bearer", header: "Authorization",
                                                      format: "Bearer {secret}"), confirm: "touchid"),
                            value: Data("AAA".utf8))
        let meta = try await store.boundMeta(host: "api.x.com", path: "/")
        let cred = try await store.resolve(host: "api.x.com", path: "/")
        #expect(meta?.name == cred?.name, "the flag read and the injected key MUST be the same secret")
        #expect(meta?.name == "aaa_key", "the alphabetically-first binding wins in BOTH paths")
        #expect(cred?.secret == Data("AAA".utf8))
        await store.close()
    }

    @Test("insecureTLS round-trips through sealed metadata and resolve; old records default OFF")
    func insecureTLSRoundTrip() async throws {
        let store = try newStore()
        try await store.set(
            SecretMeta(name: "internal", kind: "bearer", bindHosts: ["intra.corp"],
                       inject: Inject(adapter: "bearer"), insecureTLS: true),
            value: Data("v".utf8))
        let cred = try await store.resolve(host: "intra.corp", path: "/")
        #expect(cred?.insecureTLS == true)
        // updateMeta with nil leaves the flag untouched; false clears it.
        try await store.updateMeta(name: "internal", bindHosts: ["intra.corp"], bindPaths: [],
                                   inject: Inject(adapter: "bearer"), confirm: "")
        #expect(try await store.resolve(host: "intra.corp", path: "/")?.insecureTLS == true)
        try await store.updateMeta(name: "internal", bindHosts: ["intra.corp"], bindPaths: [],
                                   inject: Inject(adapter: "bearer"), confirm: "", insecureTLS: false)
        #expect(try await store.resolve(host: "intra.corp", path: "/")?.insecureTLS == false)
        // A pre-flag record (no key in the JSON) decodes as OFF, never insecure.
        let old = Data("""
        {"name":"legacy","version":1,"kind":"bearer","bindHosts":[],"bindPaths":[],
         "inject":{"adapter":"","header":"","format":"","params":{}},
         "createdAt":0,"confirm":""}
        """.utf8)
        let dec = JSONDecoder(); dec.dateDecodingStrategy = .secondsSince1970
        #expect(try dec.decode(SecretMeta.self, from: old).insecureTLS == false)
        await store.close()
    }

    @Test("the plaintext audit recipient is authenticated against the sealed identity (#11)")
    func auditRecipientAuthenticated() async throws {
        let store = try newStore()
        let genuine = try #require(await store.auditRecipient())
        #expect(await store.auditRecipientMatches(genuine), "the genuine recipient matches the sealed identity")
        // The recipient the WRITER actually holds is an attacker's key → detected,
        // even if the DB value was restored to the genuine one (#8).
        let attacker = P256.KeyAgreement.PrivateKey().publicKey.x963Representation
        #expect(await store.auditRecipientMatches(attacker) == false,
                "a redirected active recipient must be caught (journal encryption redirected)")
        await store.close()
    }

    @Test("set bumps the version; resolve returns the newest value")
    func versionBump() async throws {
        let store = try newStore()
        let meta = SecretMeta(name: "s", kind: "bearer", bindHosts: ["h.example"])
        let v1 = try await store.set(meta, value: Data("one".utf8))
        let v2 = try await store.set(meta, value: Data("two".utf8))
        #expect(v1.version == 1)
        #expect(v2.version == 2)

        let cred = try await store.resolve(host: "h.example", path: "/")
        #expect(cred?.secret == Data("two".utf8))
        let m = try await store.meta(name: "s")
        #expect(m?.version == 2)
        await store.close()
    }

    // MARK: Binding

    @Test("host wildcard *. and path /* glob match exactly like the Go resolver")
    func bindingMatch() async throws {
        let store = try newStore()
        try await store.set(
            SecretMeta(name: "wild", kind: "bearer", bindHosts: ["*.example.com"]),
            value: Data("wild-secret".utf8))
        try await store.set(
            SecretMeta(name: "gl", kind: "header", bindHosts: ["gitlab.example.net"],
                       bindPaths: ["/api/v4/*"],
                       inject: Inject(adapter: "header", header: "PRIVATE-TOKEN")),
            value: Data("gl-secret".utf8))
        try await store.set(
            SecretMeta(name: "exact", kind: "bearer", bindHosts: ["one.test"],
                       bindPaths: ["/only"]),
            value: Data("exact-secret".utf8))

        // *. wildcard: subdomains yes (case-insensitively), the apex no.
        let sub = try await store.boundMeta(host: "api.example.com", path: "/anything")
        #expect(sub?.name == "wild")
        let mixedCase = try await store.boundMeta(host: "API.Sub.Example.COM", path: "/")
        #expect(mixedCase?.name == "wild")
        let apex = try await store.boundMeta(host: "example.com", path: "/")
        #expect(apex == nil)

        // Path glob: inside /api/v4/* yes (including the bare prefix dir), outside no.
        let inScope = try await store.boundMeta(host: "gitlab.example.net", path: "/api/v4/projects")
        #expect(inScope?.name == "gl")
        let prefixDir = try await store.boundMeta(host: "gitlab.example.net", path: "/api/v4/")
        #expect(prefixDir?.name == "gl")
        let noSlash = try await store.boundMeta(host: "gitlab.example.net", path: "/api/v4")
        #expect(noSlash == nil)
        let outOfScope = try await store.boundMeta(host: "gitlab.example.net", path: "/other")
        #expect(outOfScope == nil)

        // Exact path binding: only the exact path.
        let exact = try await store.boundMeta(host: "one.test", path: "/only")
        #expect(exact?.name == "exact")
        let deeper = try await store.boundMeta(host: "one.test", path: "/only/deeper")
        #expect(deeper == nil)

        // No credential binds a foreign host.
        let evil = try await store.boundMeta(host: "evil.com", path: "/")
        #expect(evil == nil)

        // Resolution through the wildcard injects the wildcard's value.
        let cred = try await store.resolve(host: "api.example.com", path: "/x")
        #expect(cred?.secret == Data("wild-secret".utf8))
        await store.close()
    }

    @Test("absolute lock: metadata, bindings, blobs and edits ALL fail closed while locked")
    func absoluteLock() async throws {
        let store = try newStore()
        try await store.set(
            SecretMeta(name: "s", kind: "bearer", bindHosts: ["h.example"], confirm: "touchid"),
            value: Data("v".utf8))
        await store.lock()
        let isLocked = await store.locked()
        #expect(isLocked)

        // NOTHING works while locked — metadata is ciphertext like the values.
        await #expect(throws: VaultStoreError.locked) { _ = try await store.list() }
        await #expect(throws: VaultStoreError.locked) { _ = try await store.meta(name: "s") }
        await #expect(throws: VaultStoreError.locked) {
            _ = try await store.resolve(host: "h.example", path: "/")
        }
        await #expect(throws: VaultStoreError.locked) {
            _ = try await store.resolve(host: "other.example", path: "/")   // even "unbound"
        }
        await #expect(throws: VaultStoreError.locked) {
            try await store.updateMeta(name: "s", bindHosts: ["evil.example"], bindPaths: [],
                                       inject: Inject(), confirm: "")
        }
        await #expect(throws: VaultStoreError.locked) { _ = try await store.delete(name: "s") }
        await #expect(throws: VaultStoreError.locked) {
            _ = try await store.blob(key: VaultStore.hostsBlobKey)
        }
        await #expect(throws: VaultStoreError.locked) {
            try await store.setBlob(key: VaultStore.settingsBlobKey, data: Data("{}".utf8))
        }
        await #expect(throws: VaultStoreError.locked) { _ = try await store.auditIdentity() }
        await #expect(throws: VaultStoreError.locked) {
            _ = try await store.sealRecording(Data("cast".utf8), filename: "x.cast.sealed")
        }

        // boundMeta FAILS CLOSED (H10): an unreadable store throws rather than
        // folding to "nothing bound" — otherwise a transient read failure would
        // erase a per-call key's confirmation flag (confirm="") and inject
        // without ceremony.
        await #expect(throws: VaultStoreError.locked) {
            _ = try await store.boundMeta(host: "h.example", path: "/")
        }

        // The ONE readable fact while locked: the audit recipient PUBLIC key —
        // what lets deny events be recorded against a locked vault.
        let recipient = await store.auditRecipient()
        #expect(recipient != nil)

        // Unlock restores everything.
        try await store.unlock()
        let listed = try await store.list()
        #expect(listed.count == 1)
        #expect(listed[0].confirm == "touchid")
        await store.close()
    }

    // MARK: Sealed blobs + audit keypair

    @Test("blobs (hosts/settings) round-trip sealed; absent reads nil")
    func blobsRoundTrip() async throws {
        let store = try newStore()
        let empty = try await store.blob(key: VaultStore.hostsBlobKey)
        #expect(empty == nil)
        let doc = Data(#"[{"name":"prod-1","addr":"203.0.113.7"}]"#.utf8)
        try await store.setBlob(key: VaultStore.hostsBlobKey, data: doc)
        let back = try await store.blob(key: VaultStore.hostsBlobKey)
        #expect(back == doc)
        // Overwrite (upsert) sticks.
        try await store.setBlob(key: VaultStore.hostsBlobKey, data: Data("[]".utf8))
        #expect(try await store.blob(key: VaultStore.hostsBlobKey) == Data("[]".utf8))
        await store.close()
    }

    @Test("audit keypair: recipient is public; identity is DEK-sealed and matches it")
    func auditKeypair() async throws {
        let url = try freshVaultURL()
        let store = try VaultStore(creatingAt: url, keystore: FileAgeKeystore())
        guard let recipient = await store.auditRecipient() else {
            Issue.record("fresh v2 vault has no audit recipient")
            return
        }
        let identity = try await store.auditIdentity()
        let key = try CryptoKit.P256.KeyAgreement.PrivateKey(rawRepresentation: identity)
        #expect(key.publicKey.x963Representation == recipient)

        // Locked: recipient still readable, identity is not (asserted in
        // absoluteLock; here we assert the recipient survives reopen too).
        await store.close()
        let reopened = try VaultStore(openingAt: url, keystore: FileAgeKeystore())
        let stillThere = await reopened.auditRecipient()
        #expect(stillThere == recipient)
        await reopened.close()
    }

    // MARK: updateMeta

    @Test("updateMeta rebinds without touching the encrypted value")
    func updateMetaPreservesValue() async throws {
        let store = try newStore()
        let secret = Data("keep-me-intact".utf8)
        try await store.set(
            SecretMeta(name: "s", kind: "bearer", bindHosts: ["old.example"]),
            value: secret)

        try await store.updateMeta(
            name: "s", bindHosts: ["new.example"], bindPaths: ["/api/*"],
            inject: Inject(adapter: "header", header: "X-Token", format: "{secret}"),
            confirm: "click")

        let m = try await store.meta(name: "s")
        #expect(m?.bindHosts == ["new.example"])
        #expect(m?.bindPaths == ["/api/*"])
        #expect(m?.inject.header == "X-Token")
        #expect(m?.confirm == "click")
        #expect(m?.version == 1)          // no version bump — the value was untouched
        #expect(m?.kind == "bearer")      // kind is immutable (bound into the AAD)

        let old = try await store.resolve(host: "old.example", path: "/api/x")
        #expect(old == nil)
        let cred = try await store.resolve(host: "new.example", path: "/api/x")
        #expect(cred?.secret == secret)

        await #expect(throws: VaultStoreError.notFound("nope")) {
            try await store.updateMeta(name: "nope", bindHosts: [], bindPaths: [],
                                       inject: Inject(), confirm: "")
        }
        await store.close()
    }

    // MARK: Lock / unlock

    @Test("lock zeroizes the DEK: value reads and writes fail until unlock")
    func lockFailsClosed() async throws {
        let store = try newStore()
        try await store.set(SecretMeta(name: "s", kind: "bearer"), value: Data("v".utf8))
        await store.lock()

        await #expect(throws: VaultStoreError.locked) {
            _ = try await store.secretValue(name: "s")
        }
        await #expect(throws: VaultStoreError.locked) {
            try await store.set(SecretMeta(name: "t", kind: "bearer"), value: Data("w".utf8))
        }

        try await store.unlock()
        let v = try await store.secretValue(name: "s")
        #expect(v == Data("v".utf8))
        await store.close()
    }

    @Test("a different keystore cannot unlock the vault; the right one still can")
    func wrongKeystore() async throws {
        let url = try freshVaultURL()
        let ks1 = FileAgeKeystore()
        do {
            let store = try VaultStore(creatingAt: url, keystore: ks1)
            try await store.set(SecretMeta(name: "s", kind: "bearer"), value: Data("value".utf8))
            await store.close()
        }

        let wrong = try VaultStore(openingAt: url, keystore: FileAgeKeystore())
        let bootsLocked = await wrong.locked()
        #expect(bootsLocked)              // an opened vault starts LOCKED
        await #expect(throws: (any Error).self) {
            try await wrong.unlock()      // wrong wrap key → AEAD unwrap fails
        }
        await wrong.close()

        let right = try VaultStore(openingAt: url, keystore: ks1)
        try await right.unlock()
        let v = try await right.secretValue(name: "s")
        #expect(v == Data("value".utf8))
        await right.close()
    }

    // MARK: Auto-lock TTL

    @Test("auto-lock: the DEK dies when the TTL deadline passes, latching the event once")
    func autoLockTTL() async throws {
        let store = try newStore()
        try await store.set(SecretMeta(name: "s", kind: "bearer"), value: Data("v".utf8))
        await store.lock()
        await store.setAutoLockTTL(0.05)
        try await store.unlock()
        let unlockedNow = await store.locked()
        #expect(!unlockedNow)

        try await Task.sleep(for: .milliseconds(150))
        let relocked = await store.locked()
        #expect(relocked)
        let rem = await store.remaining()
        #expect(rem == 0)
        await #expect(throws: VaultStoreError.locked) {
            _ = try await store.secretValue(name: "s")
        }

        let event = await store.takeAutoLockEvent()
        #expect(event)
        let drained = await store.takeAutoLockEvent()
        #expect(!drained)
        await store.close()
    }

    @Test("auto-lock OFF (nil TTL): the vault stays unlocked past any deadline")
    func autoLockDisabled() async throws {
        let store = try newStore()
        try await store.set(SecretMeta(name: "s", kind: "bearer"), value: Data("v".utf8))
        await store.lock()
        await store.setAutoLockTTL(nil)          // the user turned auto-lock off
        try await store.unlock()
        let rem = await store.remaining()
        #expect(rem == 0)                         // no deadline to count down
        try await Task.sleep(for: .milliseconds(150))
        let stillUnlocked = await store.locked()
        #expect(!stillUnlocked)
        let event = await store.takeAutoLockEvent()
        #expect(!event)

        // Flipping auto-lock back ON re-arms the LIVE deadline immediately.
        await store.setAutoLockTTL(0.05)
        try await Task.sleep(for: .milliseconds(150))
        let relocked = await store.locked()
        #expect(relocked)
        await store.close()
    }

    @Test("a manual lock never latches the auto-lock event")
    func manualLockIsNotAutoLock() async throws {
        let store = try newStore()
        await store.setAutoLockTTL(3600)
        await store.lock()
        try await store.unlock()
        await store.lock()
        let event = await store.takeAutoLockEvent()
        #expect(!event)
        await store.close()
    }

    @Test("remaining() reports the live countdown, ceiled to whole seconds")
    func remainingReflectsTTL() async throws {
        let store = try newStore()
        await store.lock()
        await store.setAutoLockTTL(10)
        try await store.unlock()
        let rem = await store.remaining()
        #expect(rem >= 8 && rem <= 10)
        let stillUnlocked = await store.locked()
        #expect(!stillUnlocked)
        await store.close()
    }

    @Test("shortening the TTL while unlocked re-arms the deadline immediately")
    func ttlChangeReArms() async throws {
        let store = try newStore()
        await store.lock()
        await store.setAutoLockTTL(3600)
        try await store.unlock()
        await store.setAutoLockTTL(0.05)   // live change from the UI
        try await Task.sleep(for: .milliseconds(150))
        let relocked = await store.locked()
        #expect(relocked)
        await store.close()
    }

    // MARK: Delete + init guards

    @Test("delete removes every version; missing names are reported as notFound")
    func deleteAndNotFound() async throws {
        let store = try newStore()
        try await store.set(SecretMeta(name: "s", kind: "bearer"), value: Data("1".utf8))
        try await store.set(SecretMeta(name: "s", kind: "bearer"), value: Data("2".utf8))

        let existed = try await store.delete(name: "s")
        #expect(existed)
        let gone = try await store.meta(name: "s")
        #expect(gone == nil)
        let again = try await store.delete(name: "s")
        #expect(!again)

        await #expect(throws: VaultStoreError.notFound("s")) {
            _ = try await store.secretValue(name: "s")
        }
        await store.close()
    }

    @Test("creatingAt refuses an already-initialized vault; openingAt refuses a fresh one")
    func initGuards() async throws {
        let url = try freshVaultURL()
        let store = try VaultStore(creatingAt: url, keystore: FileAgeKeystore())
        await store.close()

        #expect(throws: VaultStoreError.alreadyInitialized(url.path)) {
            _ = try VaultStore(creatingAt: url, keystore: FileAgeKeystore())
        }

        let freshURL = try freshVaultURL()
        #expect(throws: VaultStoreError.notInitialized(freshURL.path)) {
            _ = try VaultStore(openingAt: freshURL, keystore: FileAgeKeystore())
        }
    }
}

@Suite("VaultStore — binding match unit rules")
struct BindMatchTests {

    @Test("hostMatch: exact, case-insensitive, and *. wildcard (never the apex)")
    func hostRules() {
        #expect(VaultStore.hostMatch(patterns: ["api.example.com"], host: "api.example.com"))
        #expect(VaultStore.hostMatch(patterns: ["API.EXAMPLE.COM"], host: "api.example.com"))
        #expect(VaultStore.hostMatch(patterns: ["*.example.com"], host: "a.example.com"))
        #expect(VaultStore.hostMatch(patterns: ["*.example.com"], host: "a.b.example.com"))
        #expect(!VaultStore.hostMatch(patterns: ["*.example.com"], host: "example.com"))
        #expect(!VaultStore.hostMatch(patterns: ["*.example.com"], host: "notexample.com"))
        #expect(!VaultStore.hostMatch(patterns: [], host: "example.com"))
    }

    @Test("pathMatch: exact or trailing /* prefix glob")
    func pathRules() {
        #expect(VaultStore.pathMatch(pattern: "/only", path: "/only"))
        #expect(!VaultStore.pathMatch(pattern: "/only", path: "/only/deeper"))
        #expect(VaultStore.pathMatch(pattern: "/api/v4/*", path: "/api/v4/projects"))
        #expect(VaultStore.pathMatch(pattern: "/api/v4/*", path: "/api/v4/"))
        #expect(!VaultStore.pathMatch(pattern: "/api/v4/*", path: "/api/v4"))
        #expect(!VaultStore.pathMatch(pattern: "/api/v4/*", path: "/other"))
    }

    @Test("pathMatch rejects raw and percent-decoded dot segments")
    func pathDotSegments() throws {
        let rawPaths = [
            "/api/v4/./projects",
            "/api/v4/../admin",
        ]
        for path in rawPaths {
            #expect(!VaultStore.pathMatch(pattern: "/api/v4/*", path: path))
        }

        let encodedURLs = [
            "https://api.example.test/api/v4/%2e/projects",
            "https://api.example.test/api/v4/%2E%2E/admin",
            "https://api.example.test/api/v4/.%2e/admin",
            "https://api.example.test/api/v4/%2e./admin",
        ]
        for rawURL in encodedURLs {
            let url = try #require(URL(string: rawURL))
            let decodedPath = url.path(percentEncoded: false)
            #expect(!VaultStore.pathMatch(pattern: "/api/v4/*", path: decodedPath))
        }
    }

    @Test("bindMatches: empty bindPaths means any path on a matched host")
    func anyPathOnHost() {
        let m = SecretMeta(name: "s", kind: "bearer", bindHosts: ["h.example"])
        #expect(VaultStore.bindMatches(m, host: "h.example", path: "/anything"))
        #expect(VaultStore.bindMatches(m, host: "h.example", path: ""))
        #expect(!VaultStore.bindMatches(m, host: "other.example", path: "/anything"))
    }
}

/// The in-place upgrade from the software root of trust to the hardware gate:
/// the SAME secrets must survive, and the OLD wrap key must stop working.
/// The file-age keystore persists its raw wrap key; a test reconstructs the SAME
/// keystore from disk to simulate a restart that loads the unchanged keystore.json.
private func fileAgeKeyBytes(_ k: FileAgeKeystore) -> [UInt8] {
    // Round-trip through save/load to get the exact bytes the loader would use.
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent("fak-\(UUID().uuidString)")
    try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    let url = dir.appendingPathComponent("keystore.json")
    try? k.save(to: url)
    let json = (try? Data(contentsOf: url)).flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
    let b64 = (json?["wrap_key"] as? String) ?? ""
    return [UInt8](Data(base64Encoded: b64) ?? Data())
}

@Suite("VaultStore — rekey to the hardware gate")
struct VaultRekeyTests {

    @Test("rekey re-wraps the DEK: secrets survive, the old keystore is powerless")
    func rekeyPreservesSecretsAndRevokesOldKey() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("spk-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("vault.db")

        // A software vault holding a real secret.
        let fileAge = FileAgeKeystore()
        let store = try VaultStore(creatingAt: url, keystore: fileAge)
        _ = try await store.set(SecretMeta(name: "k", kind: "bearer"), value: Data("sk_live_original".utf8))

        // Arm the gate: same DEK, new wrapping.
        let (delegated, identity) = try SEDelegatedKeystore.generate()
        try await store.rekey(to: delegated)

        // The secret is untouched and still readable through the SAME open store.
        #expect(try await store.secretValue(name: "k") == Data("sk_live_original".utf8))

        // Reopen from disk under the gated keystore: sealed → cannot unwrap yet…
        await store.close()
        let sealed = try SEDelegatedKeystore(recipientBase64: delegated.recipient)
        let reopened = try VaultStore(openingAt: url, keystore: sealed)
        await #expect(throws: (any Error).self) { try await reopened.unlock() }

        // …until the identity is delivered (what Touch ID does in the app).
        try sealed.deliver(identity: identity)
        try await reopened.unlock()
        #expect(try await reopened.secretValue(name: "k") == Data("sk_live_original".utf8))

        // And the OLD software key is now powerless — the whole point of the move.
        await reopened.close()
        let withOldKey = try VaultStore(openingAt: url, keystore: fileAge)
        await #expect(throws: (any Error).self) { try await withOldKey.unlock() }
    }

    @Test("a rekey whose keystore.json never lands is recoverable via the prior wrapper (#9 no-brick)")
    func rekeyIsCrashSafe() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("spk-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("vault.db")

        // A software vault holding a secret.
        let fileAge = FileAgeKeystore()
        let store = try VaultStore(creatingAt: url, keystore: fileAge)
        _ = try await store.set(SecretMeta(name: "k", kind: "bearer"), value: Data("sk_live".utf8))

        // Rekey to a hardware gate, then SIMULATE the crash BEFORE keystore.json
        // is saved: close the store without ever persisting the new keystore file.
        let (delegated, _) = try SEDelegatedKeystore.generate()
        try await store.rekey(to: delegated)
        await store.close()

        // Restart with the OLD keystore (the new keystore.json was never written).
        // The new wrapped_dek can't be opened by file-age, but the prior wrapper
        // can — the vault must OPEN, not brick.
        let reopened = try VaultStore(openingAt: url, keystore: FileAgeKeystore(rawWrapKey: fileAgeKeyBytes(fileAge)))
        try await reopened.unlock()
        #expect(try await reopened.secretValue(name: "k") == Data("sk_live".utf8))
        await reopened.close()
    }

    @Test("rekey refuses on a LOCKED vault (the DEK must be in memory to re-wrap)")
    func rekeyRequiresUnlocked() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("spk-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = try VaultStore(creatingAt: dir.appendingPathComponent("v.db"), keystore: FileAgeKeystore())
        await store.lock()
        let (delegated, _) = try SEDelegatedKeystore.generate()
        await #expect(throws: VaultStoreError.locked) { try await store.rekey(to: delegated) }
    }
}
