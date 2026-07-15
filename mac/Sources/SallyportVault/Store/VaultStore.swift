import Foundation
import CryptoKit
import SQLite3
import Darwin

/// Vault lifecycle. Engine and management operations require `.ready`.
public enum VaultPhase: String, Sendable, Equatable {
    case locked        // no DEK
    case unlocking     // DEK armed, not yet hydrated / integrity-checked
    case ready         // hydrated and integrity clean
    case quarantined   // blocked after an integrity failure
}

/// Vault store errors.
public enum VaultStoreError: Error, Equatable, Sendable {
    /// An operation needed the DEK but the vault is locked (or auto-locked).
    case locked
    /// No secret with that name exists.
    case notFound(String)
    /// `init(creatingAt:)` found an already-initialized vault at the path.
    case alreadyInitialized(String)
    /// `init(openingAt:)` found no initialized vault at the path.
    case notInitialized(String)
    /// The on-disk vault uses a schema this build does not read (e.g. the v1
    /// plaintext-metadata layout). There is no migration: onboarding archives the
    /// home aside and creates a new vault.
    case incompatible(String)
    /// A SQLite operation failed.
    case sql(String)
    /// A filesystem-level failure (paths, closed handles).
    case io(String)
    /// The vault path crossed an unsafe filesystem boundary (redirected parent,
    /// symlink/hardlink/device, wrong owner, or writable permissions).
    case unsafeFilesystem(String)
    /// The lifecycle counter cannot wrap because stale operations use it for ownership.
    case lifecycleExhausted
    /// A sealed integrity counter was malformed, negative, or exhausted.
    case invalidIntegrityState(String)
}

/// Encrypted SQLite vault. A wrapped 256-bit data-encryption key seals secret
/// metadata, values, and configuration. The key is present in memory only while
/// unlocked. The actor serializes database and key access.
public actor VaultStore {

    /// The auto-lock duration used when none is configured (8h).
    public static let defaultAutoLockTTL: TimeInterval = 8 * 60 * 60
    /// Upper bound used for safe date and integer conversion.
    private static let maxAutoLockTTL: TimeInterval = TimeInterval(Int.max / 2)

    /// Blob keys for the singleton sealed documents.
    public static let hostsBlobKey = "hosts"
    public static let settingsBlobKey = "settings"
    public static let upstreamsBlobKey = "upstreams"
    /// Adopted audit-signer public key.
    public static let auditSignerBlobKey = "audit.signer.pub"
    /// Sealed configuration generation mirrored into the integrity anchor.
    public static let generationBlobKey = "meta.generation"
    /// Highest anchor counter sealed by this vault.
    public static let anchorFloorBlobKey = "anchor.counter"
    /// Sealed agent allowlist.
    public static let allowlistBlobKey = "allowlist"

    static let schemaVersion = "2"

    /// Every `sealed_*` column holds a `VaultCrypto` combined blob.
    private static let schema = """
        CREATE TABLE IF NOT EXISTS meta (
          k TEXT PRIMARY KEY,
          v BLOB
        );
        CREATE TABLE IF NOT EXISTS secrets (
          sid          TEXT    NOT NULL,
          version      INTEGER NOT NULL,
          sealed_meta  BLOB    NOT NULL,
          sealed_value BLOB    NOT NULL,
          PRIMARY KEY (sid, version)
        );
        CREATE TABLE IF NOT EXISTS blobs (
          k      TEXT PRIMARY KEY,
          sealed BLOB NOT NULL
        );
        """

    private let handle: SQLiteHandle
    /// Mutable so `rekey` can swap the software root of trust for the hardware one.
    private var keystore: any Keystore
    /// False between writing a new wrapper and the caller durably replacing
    /// keystore.json. While false, unlock must not prune the original recovery
    /// wrapper even if the in-process new keystore opens the primary slot.
    private var keystoreIsDurable = true

    /// True only for a database created by this store during this launch. The
    /// integrity gate uses it to decide whether a new trust root can be adopted.
    /// nonisolated: a plain immutable fact, safe to read without the actor.
    public nonisolated let createdThisLaunch: Bool

    /// Raw DEK bytes held only while unlocked so `lock()` can overwrite them.
    private var dek: [UInt8]?
    /// Operational state while the DEK is present. Engine and management calls
    /// require `.ready`; `.quarantined` remains blocked until explicit adoption.
    /// Direct test callers default to `.ready`, while the host defers readiness
    /// until hydration and integrity checks finish.
    private var phase: VaultPhase = .ready

    /// Configured auto-lock timeout. Nil disables auto-lock.
    /// Starts at the default so an unconfigured vault still self-locks.
    private var ttl: TimeInterval? = VaultStore.defaultAutoLockTTL
    /// Auto-lock deadline while the DEK is active.
    private var deadline: Date?
    /// Set when expiry, rather than a manual lock, clears the DEK.
    private var autoLocked = false
    /// Monotonic epoch used to discard work that spans a lock or unlock.
    private var epochCounter: Int64 = 0
    private var lifecycleExhausted = false

    /// The wrapped data-encryption key is always AES-256. Accepting an arbitrary
    /// length from an invalid keystore would change the cryptographic contract.
    private static let dekByteCount = 32
    /// Bound every SQLite scalar before Swift allocates/copies it. Management
    /// frames are already far smaller; this ceiling primarily prevents a locally
    /// corrupted database from turning unlock/integrity verification into a
    /// near-gigabyte allocation.
    private static let maxSQLiteValueBytes: Int32 = 64 * 1024 * 1024
    static let maximumPlaintextBytes = Int(maxSQLiteValueBytes) - 28 // ChaCha nonce + tag

    // MARK: - Lifecycle

    /// Creates an unlocked vault with a wrapped DEK and sealed audit identity.
    public init(creatingAt url: URL, keystore: any Keystore) throws {
        self.keystore = keystore
        self.createdThisLaunch = true
        let handle = try Self.openDatabase(at: url)
        do {
            guard try Self.readMeta(handle, key: "wrapped_dek") == nil else {
                throw VaultStoreError.alreadyInitialized(url.path)
            }
            let dekBytes = SymmetricKey(size: .bits256).withUnsafeBytes { [UInt8]($0) }
            let wrapped = try keystore.wrap(Data(dekBytes))
            try Self.writeMeta(handle, key: "wrapped_dek", value: wrapped)
            try Self.writeMeta(handle, key: "schema", value: Data(Self.schemaVersion.utf8))

            // Keep the audit recipient readable for writes and seal its private
            // identity under the DEK for reads.
            let identity = P256.KeyAgreement.PrivateKey()
            try Self.writeMeta(handle, key: "audit_recipient",
                               value: identity.publicKey.x963Representation)
            let sealedIdentity = try VaultCrypto.sealBlob(
                identity.rawRepresentation, dek: SymmetricKey(data: dekBytes), key: "audit-identity")
            try Self.writeMeta(handle, key: "audit_identity", value: sealedIdentity)

            self.handle = handle
            self.dek = dekBytes
            self.deadline = Date().addingTimeInterval(Self.defaultAutoLockTTL)
        } catch {
            handle.close()
            throw error
        }
    }

    /// Opens an existing vault in the locked state.
    public init(openingAt url: URL, keystore: any Keystore) throws {
        self.keystore = keystore
        self.createdThisLaunch = false
        let handle = try Self.openDatabase(at: url)
        do {
            guard try Self.readMeta(handle, key: "wrapped_dek") != nil else {
                throw VaultStoreError.notInitialized(url.path)
            }
            let schema = try Self.readMeta(handle, key: "schema")
                .map { String(decoding: $0, as: UTF8.self) }
            guard schema == Self.schemaVersion else {
                throw VaultStoreError.incompatible(
                    "vault schema \(schema ?? "v1/none"); this build reads only v\(Self.schemaVersion)")
            }
            self.handle = handle
        } catch {
            handle.close()
            throw error
        }
    }

    /// Rewraps the current DEK with a new keystore while unlocked. The prior
    /// wrapper lets an interrupted update reopen with the previous keystore.
    public func rekey(to newKeystore: any Keystore) throws {
        let dekBytes = try requireDEKBytes()
        let wrapped = try newKeystore.wrap(Data(dekBytes))
        // Preserve the first durable wrapper across retries.
        if try Self.readMeta(handle, key: "wrapped_dek_prev") == nil,
           let current = try Self.readMeta(handle, key: "wrapped_dek") {
            try Self.writeMeta(handle, key: "wrapped_dek_prev", value: current)
        }
        try Self.writeMeta(handle, key: "wrapped_dek", value: wrapped)
        keystore = newKeystore
        keystoreIsDurable = false
    }

    /// Completes rekeying after `keystore.json` is replaced atomically.
    public func finalizeRekey() throws {
        _ = try requireDEKBytes()
        keystoreIsDurable = true
        try Self.deleteMeta(handle, key: "wrapped_dek_prev")
    }

    /// Zeroize the DEK and release the database. The store is unusable after.
    public func close() {
        zeroizeDEK()
        handle.close()
    }

    deinit {
        if let indices = dek?.indices {
            for index in indices { dek?[index] = 0 }
        }
        dek = nil
    }

    // MARK: - Lock state

    /// Unwraps the DEK, holds it in memory, and starts the auto-lock deadline.
    /// If rekeying was interrupted, `wrapped_dek_prev` allows the previous
    /// keystore to reopen the vault. A successful primary unlock removes that slot.
    @discardableResult
    public func unlock(deferReady: Bool = false) throws -> Int64 {
        if dek != nil { return epochCounter }
        guard !lifecycleExhausted, epochCounter < Int64.max else {
            throw VaultStoreError.lifecycleExhausted
        }
        guard let wrapped = try Self.readMeta(handle, key: "wrapped_dek") else {
            throw VaultStoreError.notInitialized("missing wrapped_dek")
        }
        let openedViaPrimary: Bool
        let unwrapped: Data
        do {
            let candidate = try keystore.unwrap(wrapped)
            guard candidate.count == Self.dekByteCount else {
                throw VaultStoreError.invalidIntegrityState("wrapped DEK has an invalid length")
            }
            unwrapped = candidate
            openedViaPrimary = true
        } catch {
            // Try the prior wrapper after an interrupted rekey.
            guard let prev = try? Self.readMeta(handle, key: "wrapped_dek_prev"),
                  let candidate = try? keystore.unwrap(prev) else {
                throw error
            }
            guard candidate.count == Self.dekByteCount else {
                throw VaultStoreError.invalidIntegrityState("previous wrapped DEK has an invalid length")
            }
            unwrapped = candidate
            openedViaPrimary = false
        }
        dek = [UInt8](unwrapped)
        if openedViaPrimary, keystoreIsDurable {
            // Remove the recovery wrapper before accepting a primary-key unlock.
            do {
                try Self.deleteMeta(handle, key: "wrapped_dek_prev")
            } catch {
                zeroizeDEK()
                throw error
            }
        }
        deadline = ttl.map { Date().addingTimeInterval($0) }
        // Host callers defer readiness until hydration + the integrity gate;
        // direct callers become operational at once.
        phase = deferReady ? .unlocking : .ready
        // Clear a pending auto-lock event after unlock.
        autoLocked = false
        epochCounter += 1
        return epochCounter
    }

    /// A newly-created store starts ready for direct unit-test callers. The host
    /// invokes this before exposing its socket so hydration + integrity still run
    /// behind `.unlocking`, exactly like every later unlock.
    @discardableResult
    public func deferReadinessForHost() throws -> Int64 {
        let _ = try requireDEK()
        guard !lifecycleExhausted else { throw VaultStoreError.lifecycleExhausted }
        if phase == .ready { phase = .unlocking }
        return epochCounter
    }

    /// Current lifecycle epoch for stale-operation checks.
    public func epoch() -> Int64 { epochCounter }

    /// Test hook for lifecycle-counter exhaustion.
    func _setLifecycleEpochForTesting(_ value: Int64) {
        epochCounter = value
        lifecycleExhausted = false
    }

    /// Validate an unlock transaction token without publishing any state. Host
    /// hydration and integrity work spans several awaits; every outward commit
    /// must still belong to the lifecycle that started it.
    public func lifecycleIsCurrent(_ expectedEpoch: Int64,
                                   phase expectedPhase: VaultPhase? = nil) -> Bool {
        enforceAutoLock()
        guard dek != nil, epochCounter == expectedEpoch else { return false }
        return expectedPhase.map { phase == $0 } ?? true
    }

    /// Zeroizes the DEK. Operations fail until the next unlock.
    public func lock() {
        zeroizeDEK()
    }

    /// Close the operational gate before the host clears memory and checkpoints
    /// the final audit boundary. Engine/mgmt calls fail immediately while the DEK
    /// remains available only to finish the integrity transaction.
    @discardableResult
    public func beginLock(expectedEpoch: Int64) -> Bool {
        enforceAutoLock()
        guard dek != nil, epochCounter == expectedEpoch, phase == .ready else { return false }
        phase = .unlocking
        return true
    }

    /// Marks the vault ready after hydration and integrity checks.
    public func markReady() {
        if phase == .unlocking { phase = .ready }
    }

    /// Epoch-bound publish used by VaultHost. A stale integrity task must never
    /// mark a later unlock ready.
    @discardableResult
    public func markReady(expectedEpoch: Int64) -> Bool {
        enforceAutoLock()
        guard dek != nil, epochCounter == expectedEpoch, phase == .unlocking else { return false }
        phase = .ready
        return true
    }

    /// Quarantines the vault after an integrity failure. The DEK remains available
    /// for explicit adoption, while ordinary engine and management calls stop.
    public func quarantine() {
        if dek != nil { phase = .quarantined }
    }

    @discardableResult
    public func quarantine(expectedEpoch: Int64) -> Bool {
        enforceAutoLock()
        guard dek != nil, epochCounter == expectedEpoch else { return false }
        phase = .quarantined
        return true
    }

    /// Lift quarantine after a successful, verified re-adopt. Host-only.
    public func clearQuarantine() {
        if phase == .quarantined { phase = .ready }
    }

    @discardableResult
    public func clearQuarantine(expectedEpoch: Int64) -> Bool {
        enforceAutoLock()
        guard dek != nil, epochCounter == expectedEpoch, phase == .quarantined else { return false }
        phase = .ready
        return true
    }

    /// The operational phase (auto-lock enforced first). `.locked` is derived
    /// from DEK absence; stored `phase` covers unlocking, ready, and quarantined.
    public func phaseNow() -> VaultPhase {
        enforceAutoLock()
        return dek == nil ? .locked : phase
    }

    /// Whether the vault is ready for engine and management use.
    public func operational() -> Bool {
        phaseNow() == .ready
    }

    /// Whether the vault is locked. Checks the auto-lock deadline first.
    public func locked() -> Bool {
        enforceAutoLock()
        return dek == nil
    }

    /// Whole seconds until auto-lock, ceiled. 0 when locked, elapsed, or when
    /// auto-lock is disabled (unlocked with no deadline).
    public func remaining() -> Int {
        enforceAutoLock()
        guard dek != nil, let deadline else { return 0 }
        let rem = deadline.timeIntervalSinceNow
        guard rem > 0 else { return 0 }
        let whole = rem.rounded(.up)
        guard whole.isFinite else { return Int.max }
        if whole >= Double(Int.max) { return Int.max }
        return Int(exactly: whole) ?? Int.max
    }

    /// Sets the auto-lock duration. Nil disables auto-lock (the vault stays
    /// unlocked until an explicit lock / screen lock / sleep / quit);
    /// a non-positive value resets to the default. Takes effect immediately
    /// if currently unlocked.
    public func setAutoLockTTL(_ duration: TimeInterval?) {
        switch duration {
        case nil: ttl = nil
        case let d? where !d.isFinite || d <= 0: ttl = Self.defaultAutoLockTTL
        case let d?: ttl = min(d, Self.maxAutoLockTTL)
        }
        if dek != nil {
            deadline = ttl.map { Date().addingTimeInterval($0) }
        }
    }

    /// Epoch-bound variant used by the unlock transaction. A delayed hydration
    /// must not replace a newer unlock's live auto-lock deadline.
    @discardableResult
    public func setAutoLockTTL(_ duration: TimeInterval?, expectedEpoch: Int64) -> Bool {
        enforceAutoLock()
        guard dek != nil, epochCounter == expectedEpoch else { return false }
        setAutoLockTTL(duration)
        return true
    }

    /// Returns (and clears) whether the vault auto-locked since the last call.
    public func takeAutoLockEvent() -> Bool {
        let event = autoLocked
        autoLocked = false
        return event
    }

    private func enforceAutoLock() {
        guard dek != nil, let deadline, Date() >= deadline else { return }
        zeroizeDEK()
        autoLocked = true
    }

    private func zeroizeDEK() {
        if let indices = dek?.indices {
            for index in indices { dek?[index] = 0 }
        }
        dek = nil
        deadline = nil
        phase = .ready   // ignored while locked (phaseNow derives .locked); armed for next unlock
        if epochCounter == Int64.max {
            lifecycleExhausted = true
        } else {
            epochCounter += 1
        }
    }

    /// Returns DEK bytes after enforcing auto-lock.
    private func requireDEKBytes() throws -> [UInt8] {
        enforceAutoLock()
        guard let dek else { throw VaultStoreError.locked }
        guard dek.count == Self.dekByteCount else {
            throw VaultStoreError.invalidIntegrityState("in-memory DEK has an invalid length")
        }
        return dek
    }

    private func requireDEK() throws -> SymmetricKey {
        SymmetricKey(data: try requireDEKBytes())
    }

    // MARK: - Writes

    /// Store a new version of a secret: version = max(existing)+1, createdAt =
    /// now, meta AND value sealed via `VaultCrypto`. Returns the stored metadata
    /// (with the bumped version). The caller zeroizes `value` afterwards.
    @discardableResult
    public func set(_ meta: SecretMeta, value: Data) throws -> SecretMeta {
        let dekKey = try requireDEK()
        var m = meta
        let sid = try sidForName(m.name, dek: dekKey) ?? Self.newSID()
        let currentVersion = try maxVersion(sid: sid)
        let (nextVersion, overflow) = currentVersion.addingReportingOverflow(1)
        guard !overflow, nextVersion > 0 else {
            throw VaultStoreError.invalidIntegrityState("secret version exhausted")
        }
        m.version = nextVersion
        m.createdAt = Date()
        let metaPlain = try Self.encodeMeta(m)
        try Self.validatePlaintextByteCount(value.count, context: "secret value")
        try Self.validatePlaintextByteCount(metaPlain.count, context: "secret metadata")
        let sealedMeta = try VaultCrypto.seal(metaPlain, dek: dekKey,
                                              sid: sid, version: m.version, domain: VaultCrypto.metaDomain)
        let sealedValue = try VaultCrypto.seal(value, dek: dekKey,
                                               sid: sid, version: m.version, domain: VaultCrypto.valueDomain)

        let db = try requireDB()
        let stmt = try prepare("INSERT INTO secrets(sid,version,sealed_meta,sealed_value) VALUES(?,?,?,?)")
        defer { sqlite3_finalize(stmt) }
        try bindText(stmt, 1, sid)
        try bindInt(stmt, 2, m.version)
        try bindBlob(stmt, 3, sealedMeta)
        try bindBlob(stmt, 4, sealedValue)
        guard sqlite3_step(stmt) == SQLITE_DONE else {
            throw VaultStoreError.sql(String(cString: sqlite3_errmsg(db)))
        }
        return m
    }

    /// Replaces mutable metadata on the latest version without changing its value.
    public func updateMeta(name: String, bindHosts: [String], bindPaths: [String],
                           inject: Inject, confirm: String, insecureTLS: Bool? = nil) throws {
        let dekKey = try requireDEK()
        guard let row = try latestRow(name: name, dek: dekKey) else {
            throw VaultStoreError.notFound(name)
        }
        var m = row.meta
        m.bindHosts = bindHosts
        m.bindPaths = bindPaths
        m.inject = inject
        m.confirm = confirm
        if let insecureTLS { m.insecureTLS = insecureTLS }
        let metaPlain = try Self.encodeMeta(m)
        try Self.validatePlaintextByteCount(metaPlain.count, context: "secret metadata")
        let sealedMeta = try VaultCrypto.seal(metaPlain, dek: dekKey,
                                              sid: row.sid, version: m.version, domain: VaultCrypto.metaDomain)
        let db = try requireDB()
        let stmt = try prepare("UPDATE secrets SET sealed_meta=? WHERE sid=? AND version=?")
        defer { sqlite3_finalize(stmt) }
        try bindBlob(stmt, 1, sealedMeta)
        try bindText(stmt, 2, row.sid)
        try bindInt(stmt, 3, m.version)
        guard sqlite3_step(stmt) == SQLITE_DONE else {
            throw VaultStoreError.sql(String(cString: sqlite3_errmsg(db)))
        }
        guard sqlite3_changes(db) > 0 else { throw VaultStoreError.notFound(name) }
    }

    /// Remove every version of a named secret. Returns whether it existed.
    /// Requires the DEK because name lookup decrypts metadata.
    @discardableResult
    public func delete(name: String) throws -> Bool {
        let dekKey = try requireDEK()
        guard let sid = try sidForName(name, dek: dekKey) else { return false }
        let db = try requireDB()
        let stmt = try prepare("DELETE FROM secrets WHERE sid=?")
        defer { sqlite3_finalize(stmt) }
        try bindText(stmt, 1, sid)
        guard sqlite3_step(stmt) == SQLITE_DONE else {
            throw VaultStoreError.sql(String(cString: sqlite3_errmsg(db)))
        }
        return sqlite3_changes(db) > 0
    }

    // MARK: - Metadata reads

    /// Metadata for the latest version of every secret, ordered by name. Never
    /// includes values.
    public func list() throws -> [SecretMeta] {
        let dekKey = try requireDEK()
        return try latestRows(dek: dekKey).map(\.meta).sorted { $0.name < $1.name }
    }

    /// Metadata for the latest version of a secret (never the value), or nil.
    public func meta(name: String) throws -> SecretMeta? {
        let dekKey = try requireDEK()
        return try latestRow(name: name, dek: dekKey)?.meta
    }

    /// Returns metadata for the credential bound to a host and path. Read errors
    /// remain distinct from an absent binding.
    public func boundMeta(host: String, path: String) throws -> SecretMeta? {
        try list().first { Self.bindMatches($0, host: host, path: path) }
    }

    // MARK: - Value reads

    /// Returns the decrypted credential bound to a host and path. The caller
    /// zeroizes `Cred.secret` as soon
    /// as it is consumed.
    public func resolve(host: String, path: String) throws -> Cred? {
        let dekKey = try requireDEK()
        // Match `boundMeta` by choosing the first bound credential by name.
        guard let row = try latestRows(dek: dekKey)
            .sorted(by: { $0.meta.name < $1.meta.name })
            .first(where: { Self.bindMatches($0.meta, host: host, path: path) }) else {
            return nil
        }
        let value = try VaultCrypto.open(row.sealedValue, dek: dekKey,
                                         sid: row.sid, version: row.meta.version,
                                         domain: VaultCrypto.valueDomain)
        return Cred(name: row.meta.name, kind: row.meta.kind, inject: row.meta.inject,
                    secret: value, insecureTLS: row.meta.insecureTLS)
    }

    /// Returns the latest value of a named secret. The caller must zeroize it.
    public func secretValue(name: String) throws -> Data {
        let dekKey = try requireDEK()
        guard let row = try latestRow(name: name, dek: dekKey) else {
            throw VaultStoreError.notFound(name)
        }
        return try VaultCrypto.open(row.sealedValue, dek: dekKey,
                                    sid: row.sid, version: row.meta.version,
                                    domain: VaultCrypto.valueDomain)
    }

    // MARK: - Sealed blobs (hosts inventory, settings)

    /// Read + decrypt a singleton document, or nil when absent. Requires the DEK.
    public func blob(key: String) throws -> Data? {
        let dekKey = try requireDEK()
        let db = try requireDB()
        let stmt = try prepare("SELECT sealed FROM blobs WHERE k=?")
        defer { sqlite3_finalize(stmt) }
        try bindText(stmt, 1, key)
        switch sqlite3_step(stmt) {
        case SQLITE_ROW:
            return try VaultCrypto.openBlob(try columnBlob(stmt, 0), dek: dekKey, key: key)
        case SQLITE_DONE:
            return nil
        default:
            throw VaultStoreError.sql(String(cString: sqlite3_errmsg(db)))
        }
    }

    /// Seal + upsert a singleton document. Requires the DEK.
    public func setBlob(key: String, data: Data) throws {
        let dekKey = try requireDEK()
        try Self.validatePlaintextByteCount(data.count, context: "sealed document")
        let sealed = try VaultCrypto.sealBlob(data, dek: dekKey, key: key)
        let db = try requireDB()
        let stmt = try prepare("INSERT INTO blobs(k,sealed) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET sealed=excluded.sealed")
        defer { sqlite3_finalize(stmt) }
        try bindText(stmt, 1, key)
        try bindBlob(stmt, 2, sealed)
        guard sqlite3_step(stmt) == SQLITE_DONE else {
            throw VaultStoreError.sql(String(cString: sqlite3_errmsg(db)))
        }
    }

    /// Writes only when the caller's lifecycle epoch is still current.
    public func setBlob(key: String, data: Data, expectedEpoch: Int64) throws {
        enforceAutoLock()
        guard epochCounter == expectedEpoch else { throw VaultStoreError.locked }
        try setBlob(key: key, data: data)
    }

    // MARK: - Audit keypair

    /// Audit recipient public key, readable while locked so denials can be recorded.
    public func auditRecipient() -> Data? {
        try? Self.readMeta(handle, key: "audit_recipient")
    }

    /// Vault-sealed P-256 audit identity. The caller zeroizes it after use.
    public func auditIdentity() throws -> Data {
        let dekKey = try requireDEK()
        guard let sealed = try Self.readMeta(handle, key: "audit_identity") else {
            throw VaultStoreError.notInitialized("missing audit_identity")
        }
        return try VaultCrypto.openBlob(sealed, dek: dekKey, key: "audit-identity")
    }

    /// Checks the active audit recipient against the public key derived from the
    /// vault-sealed audit identity.
    public func auditRecipientMatches(_ activeRecipientX963: Data) -> Bool {
        guard let dekKey = try? requireDEK(),
              let sealed = try? Self.readMeta(handle, key: "audit_identity"),
              let raw = try? VaultCrypto.openBlob(sealed, dek: dekKey, key: "audit-identity"),
              let identity = try? P256.KeyAgreement.PrivateKey(rawRepresentation: raw) else {
            return false
        }
        var scalar = raw; scalar.resetBytes(in: 0..<scalar.count)   // wipe our copy
        return identity.publicKey.x963Representation == activeRecipientX963
    }

    /// SHA-256 over encrypted secrets and blobs, excluding the derived anchor
    /// counter. The signed anchor binds this digest to the recorded state.
    public func trustDigest(expectedEpoch: Int64? = nil) throws -> String {
        if let expectedEpoch {
            enforceAutoLock()
            guard dek != nil, epochCounter == expectedEpoch else { throw VaultStoreError.locked }
        }
        let db = try requireDB()
        var hasher = SHA256()
        func feed(_ label: String, _ parts: [Data]) {
            hasher.update(data: Data(label.utf8))
            for p in parts {
                var len = UInt64(p.count).bigEndian
                withUnsafeBytes(of: &len) { hasher.update(data: Data($0)) }
                hasher.update(data: p)
            }
        }
        let secrets = try prepare("SELECT sid,version,sealed_meta,sealed_value FROM secrets ORDER BY sid,version")
        defer { sqlite3_finalize(secrets) }
        while true {
            let rc = sqlite3_step(secrets)
            if rc == SQLITE_DONE { break }
            guard rc == SQLITE_ROW else {
                throw VaultStoreError.sql("trust digest secrets: \(String(cString: sqlite3_errmsg(db)))")
            }
            let rawVersion = sqlite3_column_int64(secrets, 1)
            guard rawVersion > 0 else {
                throw VaultStoreError.invalidIntegrityState("secret version is invalid")
            }
            feed("secret", [Data(try columnText(secrets, 0).utf8),
                            Data(String(rawVersion).utf8),
                            try columnBlob(secrets, 2), try columnBlob(secrets, 3)])
        }
        let blobs = try prepare("SELECT k,sealed FROM blobs WHERE k != ? ORDER BY k")
        defer { sqlite3_finalize(blobs) }
        try bindText(blobs, 1, Self.anchorFloorBlobKey)
        while true {
            let rc = sqlite3_step(blobs)
            if rc == SQLITE_DONE { break }
            guard rc == SQLITE_ROW else {
                throw VaultStoreError.sql("trust digest blobs: \(String(cString: sqlite3_errmsg(db)))")
            }
            feed("blob", [Data(try columnText(blobs, 0).utf8), try columnBlob(blobs, 1)])
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    /// Strict sealed generation read. Missing means generation zero;
    /// malformed, negative, unreadable, or stale-lifecycle data is an error.
    public func configurationGeneration(expectedEpoch: Int64? = nil) throws -> Int64 {
        if let expectedEpoch {
            enforceAutoLock()
            guard dek != nil, epochCounter == expectedEpoch else { throw VaultStoreError.locked }
        }
        guard let data = try blob(key: Self.generationBlobKey) else { return 0 }
        let value: Int64
        do {
            value = try JSONDecoder().decode(Int64.self, from: data)
        } catch {
            throw VaultStoreError.invalidIntegrityState("configuration generation is malformed")
        }
        guard value >= 0 else {
            throw VaultStoreError.invalidIntegrityState("configuration generation is negative")
        }
        return value
    }

    /// Strict sealed replay floor read. Once a signer root is adopted this must
    /// exist and be non-negative; callers decide whether absence is legitimate.
    public func anchorCounterFloor(expectedEpoch: Int64? = nil) throws -> Int64? {
        if let expectedEpoch {
            enforceAutoLock()
            guard dek != nil, epochCounter == expectedEpoch else { throw VaultStoreError.locked }
        }
        guard let data = try blob(key: Self.anchorFloorBlobKey) else { return nil }
        let value: Int64
        do {
            value = try JSONDecoder().decode(Int64.self, from: data)
        } catch {
            throw VaultStoreError.invalidIntegrityState("anchor counter floor is malformed")
        }
        guard value >= 0 else {
            throw VaultStoreError.invalidIntegrityState("anchor counter floor is negative")
        }
        return value
    }

    /// Test hook: overwrite the plaintext audit recipient (models an attacker
    /// swapping it in the DB file while Sallyport is stopped).
    func _swapAuditRecipientForTesting(_ pub: Data) {
        try? Self.writeMeta(handle, key: "audit_recipient", value: pub)
    }

    /// Test hook for a missing audit recipient during host construction.
    func _removeAuditRecipientForTesting() throws {
        try Self.deleteMeta(handle, key: "audit_recipient")
    }

    // MARK: - Recordings

    /// Seals a session recording and authenticates its filename.
    public func sealRecording(_ cast: Data, filename: String) throws -> Data {
        let dekKey = try requireDEK()
        return try VaultCrypto.sealRecording(cast, dek: dekKey, filename: filename)
    }

    /// Decrypt one sealed session recording (viewer/export path).
    public func openRecording(_ blob: Data, filename: String) throws -> Data {
        let dekKey = try requireDEK()
        return try VaultCrypto.openRecording(blob, dek: dekKey, filename: filename)
    }

    // MARK: - Binding match

    /// Check a secret's host/path binding against a request.
    static func bindMatches(_ m: SecretMeta, host: String, path: String) -> Bool {
        guard hostMatch(patterns: m.bindHosts, host: host) else { return false }
        if m.bindPaths.isEmpty { return true }
        return m.bindPaths.contains { pathMatch(pattern: $0, path: path) }
    }

    /// Exact match plus a leading `*.` wildcard (`*.example.com` matches
    /// `api.example.com` but not the apex). Case-insensitive.
    static func hostMatch(patterns: [String], host: String) -> Bool {
        let host = host.lowercased()
        for pattern in patterns {
            let p = pattern.lowercased()
            if p == host { return true }
            if p.hasPrefix("*."), host.hasSuffix(String(p.dropFirst())) { return true }
        }
        return false
    }

    /// Exact match plus a trailing `/*` prefix glob (`/api/v4/*` matches
    /// `/api/v4/projects` and `/api/v4/`, but not `/api/v4`).
    static func pathMatch(pattern: String, path: String) -> Bool {
        if pattern.hasSuffix("/*") {
            return path.hasPrefix(String(pattern.dropLast()))
        }
        return pattern == path
    }

    // MARK: - Row plumbing

    private struct Row {
        var sid: String
        var meta: SecretMeta
        var sealedValue: Data
    }

    /// Decrypt the latest version of every secret (one row per sid).
    private func latestRows(dek: SymmetricKey) throws -> [Row] {
        let db = try requireDB()
        let stmt = try prepare("""
            SELECT s.sid, s.version, s.sealed_meta, s.sealed_value
            FROM secrets s
            WHERE s.version = (SELECT MAX(version) FROM secrets WHERE sid = s.sid)
            """)
        defer { sqlite3_finalize(stmt) }
        var rows: [Row] = []
        while true {
            let rc = sqlite3_step(stmt)
            if rc == SQLITE_DONE { break }
            guard rc == SQLITE_ROW else {
                throw VaultStoreError.sql(String(cString: sqlite3_errmsg(db)))
            }
            let sid = try columnText(stmt, 0)
            guard let version = Int(exactly: sqlite3_column_int64(stmt, 1)), version > 0 else {
                throw VaultStoreError.invalidIntegrityState("secret version is invalid")
            }
            let metaPlain = try VaultCrypto.open(try columnBlob(stmt, 2), dek: dek,
                                                 sid: sid, version: version, domain: VaultCrypto.metaDomain)
            let meta = try Self.decodeMeta(metaPlain)
            guard meta.version == version else {
                throw VaultStoreError.invalidIntegrityState("sealed metadata version does not match its row")
            }
            rows.append(Row(sid: sid, meta: meta, sealedValue: try columnBlob(stmt, 3)))
        }
        return rows
    }

    private func latestRow(name: String, dek: SymmetricKey) throws -> Row? {
        try latestRows(dek: dek).first { $0.meta.name == name }
    }

    private func sidForName(_ name: String, dek: SymmetricKey) throws -> String? {
        try latestRow(name: name, dek: dek)?.sid
    }

    /// max(version) for a sid, 0 when absent.
    private func maxVersion(sid: String) throws -> Int {
        let db = try requireDB()
        let stmt = try prepare("SELECT COALESCE(MAX(version),0) FROM secrets WHERE sid=?")
        defer { sqlite3_finalize(stmt) }
        try bindText(stmt, 1, sid)
        guard sqlite3_step(stmt) == SQLITE_ROW else {
            throw VaultStoreError.sql(String(cString: sqlite3_errmsg(db)))
        }
        guard let value = Int(exactly: sqlite3_column_int64(stmt, 0)), value >= 0 else {
            throw VaultStoreError.invalidIntegrityState("secret version is invalid")
        }
        return value
    }

    private static func newSID() -> String {
        UUID().uuidString.lowercased()
    }

    // MARK: - Meta codec (the sealed_meta plaintext)

    static func encodeMeta(_ meta: SecretMeta) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        do {
            return try encoder.encode(meta)
        } catch {
            throw VaultStoreError.io("encode metadata: \(error)")
        }
    }

    static func decodeMeta(_ data: Data) throws -> SecretMeta {
        do {
            return try JSONDecoder().decode(SecretMeta.self, from: data)
        } catch {
            throw VaultStoreError.io("decode metadata: \(error)")
        }
    }

    // MARK: - SQLite helpers (actor-isolated; the handle never leaves the actor)

    private func requireDB() throws -> OpaquePointer {
        guard !handle.isClosed else { throw VaultStoreError.io("vault database is closed") }
        try handle.validatePath()
        return handle.raw
    }

    private func prepare(_ sql: String) throws -> OpaquePointer {
        let db = try requireDB()
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK, let stmt else {
            throw VaultStoreError.sql(String(cString: sqlite3_errmsg(db)))
        }
        return stmt
    }

    private func bindText(_ stmt: OpaquePointer, _ index: Int32, _ value: String) throws {
        guard sqlite3_bind_text(stmt, index, value, -1, sqliteTransient) == SQLITE_OK else {
            throw VaultStoreError.sql("bind text at \(index) failed")
        }
    }

    private func bindInt(_ stmt: OpaquePointer, _ index: Int32, _ value: Int) throws {
        guard let exact = Int64(exactly: value) else {
            throw VaultStoreError.sql("bind int at \(index) exceeds SQLite's Int64 range")
        }
        guard sqlite3_bind_int64(stmt, index, exact) == SQLITE_OK else {
            throw VaultStoreError.sql("bind int at \(index) failed")
        }
    }

    private func bindBlob(_ stmt: OpaquePointer, _ index: Int32, _ value: Data) throws {
        guard value.count <= Int(Self.maxSQLiteValueBytes),
              let byteCount = Int32(exactly: value.count) else {
            throw VaultStoreError.sql("bind blob at \(index) exceeds the vault value limit")
        }
        let rc = value.withUnsafeBytes { buf -> Int32 in
            if let base = buf.baseAddress, !buf.isEmpty {
                return sqlite3_bind_blob(stmt, index, base, byteCount, sqliteTransient)
            }
            return sqlite3_bind_zeroblob(stmt, index, 0)
        }
        guard rc == SQLITE_OK else {
            throw VaultStoreError.sql("bind blob at \(index) failed")
        }
    }

    private func columnText(_ stmt: OpaquePointer, _ index: Int32) throws -> String {
        let rawCount = sqlite3_column_bytes(stmt, index)
        let count = try Self.checkedSQLiteByteCount(rawCount, context: "text at column \(index)")
        guard let base = sqlite3_column_text(stmt, index) else {
            throw VaultStoreError.sql("SQLite returned NULL text at column \(index)")
        }
        let bytes = UnsafeBufferPointer(start: base, count: count)
        guard let value = String(bytes: bytes, encoding: .utf8) else {
            throw VaultStoreError.sql("SQLite returned invalid UTF-8 at column \(index)")
        }
        return value
    }

    private func columnBlob(_ stmt: OpaquePointer, _ index: Int32) throws -> Data {
        let rawCount = sqlite3_column_bytes(stmt, index)
        let count = try Self.checkedSQLiteByteCount(rawCount, context: "blob at column \(index)")
        guard count > 0 else { return Data() }
        guard let base = sqlite3_column_blob(stmt, index) else {
            throw VaultStoreError.sql("SQLite returned NULL for a non-empty blob at column \(index)")
        }
        return Data(bytes: base, count: count)
    }

    /// Central proof obligation for every SQLite-owned byte count. SQLite's C
    /// API uses signed Int32; reject negative or oversized
    /// value into an allocation.
    static func checkedSQLiteByteCount(_ rawCount: Int32, context: String = "value") throws -> Int {
        guard rawCount >= 0 else {
            throw VaultStoreError.sql("SQLite returned a negative byte count for \(context)")
        }
        guard rawCount <= maxSQLiteValueBytes else {
            throw VaultStoreError.sql("SQLite \(context) exceeds the vault value limit")
        }
        return Int(rawCount)
    }

    static func validatePlaintextByteCount(_ count: Int, context: String = "value") throws {
        guard count >= 0, count <= maximumPlaintextBytes else {
            throw VaultStoreError.io("\(context) exceeds the vault value limit")
        }
    }

    // MARK: - Database bootstrap (static: usable before `self` is initialized)

    private static func openDatabase(at url: URL) throws -> SQLiteHandle {
        let dir = url.deletingLastPathComponent()
        do {
            try FileManager.default.createDirectory(
                at: dir, withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700])
        } catch {
            throw VaultStoreError.io("create \(dir.path): \(error)")
        }
        let pathGuard = try DatabasePathGuard(url: url)
        let descriptorsBefore = pathGuard.matchingDescriptorCount()
        var db: OpaquePointer?
        let rc = sqlite3_open_v2(
            pathGuard.sqlitePath, &db,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_NOFOLLOW, nil)
        guard rc == SQLITE_OK, let db else {
            if let db { sqlite3_close(db) }
            throw VaultStoreError.io("open database at \(url.path) (sqlite rc \(rc))")
        }
        // Prove the descriptor SQLite retained is the exact inode opened with
        // openat(O_NOFOLLOW), not a same-UID path swap during sqlite3_open_v2.
        // External processes cannot inject descriptors into this process, so an
        // increased matching-fd count is an actual main-database handle.
        guard pathGuard.matchingDescriptorCount() > descriptorsBefore else {
            sqlite3_close(db)
            throw VaultStoreError.unsafeFilesystem("SQLite opened a different database inode")
        }
        do {
            try pathGuard.validate()
        } catch {
            sqlite3_close(db)
            throw error
        }
        sqlite3_limit(db, SQLITE_LIMIT_LENGTH, Self.maxSQLiteValueBytes)
        sqlite3_busy_timeout(db, 5_000)
        guard sqlite3_exec(db, schema, nil, nil, nil) == SQLITE_OK else {
            let message = String(cString: sqlite3_errmsg(db))
            sqlite3_close(db)
            throw VaultStoreError.sql("schema: \(message)")
        }
        do {
            try pathGuard.validate()
        } catch {
            sqlite3_close(db)
            throw error
        }
        return SQLiteHandle(raw: db, pathGuard: pathGuard)
    }

    private static func readMeta(_ handle: SQLiteHandle, key: String) throws -> Data? {
        guard !handle.isClosed else { throw VaultStoreError.io("vault database is closed") }
        try handle.validatePath()
        let db = handle.raw
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, "SELECT v FROM meta WHERE k=?", -1, &stmt, nil) == SQLITE_OK,
              let stmt else {
            throw VaultStoreError.sql(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_bind_text(stmt, 1, key, -1, sqliteTransient) == SQLITE_OK else {
            throw VaultStoreError.sql("bind meta key failed")
        }
        switch sqlite3_step(stmt) {
        case SQLITE_ROW:
            let rawCount = sqlite3_column_bytes(stmt, 0)
            let count = try checkedSQLiteByteCount(rawCount, context: "metadata")
            guard count > 0 else { return Data() }
            guard let base = sqlite3_column_blob(stmt, 0) else {
                throw VaultStoreError.sql("SQLite returned NULL for non-empty metadata")
            }
            return Data(bytes: base, count: count)
        case SQLITE_DONE:
            return nil
        default:
            throw VaultStoreError.sql(String(cString: sqlite3_errmsg(db)))
        }
    }

    private static func writeMeta(_ handle: SQLiteHandle, key: String, value: Data) throws {
        guard !handle.isClosed else { throw VaultStoreError.io("vault database is closed") }
        try handle.validatePath()
        let db = handle.raw
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(
            db, "INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
            -1, &stmt, nil) == SQLITE_OK, let stmt else {
            throw VaultStoreError.sql(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_bind_text(stmt, 1, key, -1, sqliteTransient) == SQLITE_OK else {
            throw VaultStoreError.sql("bind meta key failed")
        }
        guard value.count <= Int(Self.maxSQLiteValueBytes),
              let byteCount = Int32(exactly: value.count) else {
            throw VaultStoreError.sql("write meta \(key) exceeds the vault value limit")
        }
        let rc = value.withUnsafeBytes { buf -> Int32 in
            guard let base = buf.baseAddress, !buf.isEmpty else {
                return sqlite3_bind_zeroblob(stmt, 2, 0)
            }
            return sqlite3_bind_blob(stmt, 2, base, byteCount, sqliteTransient)
        }
        guard rc == SQLITE_OK, sqlite3_step(stmt) == SQLITE_DONE else {
            throw VaultStoreError.sql("write meta \(key): \(String(cString: sqlite3_errmsg(db)))")
        }
    }

    private static func deleteMeta(_ handle: SQLiteHandle, key: String) throws {
        guard !handle.isClosed else { throw VaultStoreError.io("vault database is closed") }
        try handle.validatePath()
        let db = handle.raw
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, "DELETE FROM meta WHERE k=?", -1, &stmt, nil) == SQLITE_OK,
              let stmt else {
            throw VaultStoreError.sql(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_bind_text(stmt, 1, key, -1, sqliteTransient) == SQLITE_OK,
              sqlite3_step(stmt) == SQLITE_DONE else {
            throw VaultStoreError.sql("delete meta \(key): \(String(cString: sqlite3_errmsg(db)))")
        }
    }
}

// MARK: - SQLite filesystem boundary + handle box

/// Pins and continuously verifies the exact private directory and regular file
/// used by SQLite. SQLite receives `SQLITE_OPEN_NOFOLLOW`; this guard adds
/// openat/fstat identity, ownership, link-count and permission checks, including
/// proof that SQLite retained a descriptor for the same inode.
private final class DatabasePathGuard: @unchecked Sendable {
    let url: URL
    let parentPath: String
    let canonicalParentPath: String
    let sqlitePath: String
    let filename: String
    let directoryFD: Int32
    let fileFD: Int32
    private let directoryDevice: dev_t
    private let directoryInode: ino_t
    private let fileDevice: dev_t
    private let fileInode: ino_t
    private var closed = false

    init(url: URL) throws {
        let filename = url.lastPathComponent
        let parentPath = url.deletingLastPathComponent().path
        guard !filename.isEmpty, filename != ".", filename != "..",
              !filename.contains("/"), !filename.utf8.contains(0),
              !parentPath.utf8.contains(0) else {
            throw VaultStoreError.unsafeFilesystem("invalid vault database path")
        }

        let directoryFD = parentPath.withCString {
            Darwin.open($0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        }
        guard directoryFD >= 0 else {
            throw VaultStoreError.unsafeFilesystem("vault parent is not a direct directory")
        }
        var keepDirectory = true
        defer { if keepDirectory { Darwin.close(directoryFD) } }

        var directoryInfo = stat()
        guard Darwin.fstat(directoryFD, &directoryInfo) == 0,
              (directoryInfo.st_mode & S_IFMT) == S_IFDIR,
              directoryInfo.st_uid == geteuid(),
              (directoryInfo.st_mode & 0o022) == 0 else {
            throw VaultStoreError.unsafeFilesystem(
                "vault parent must be owned by the current user and not group/other writable")
        }
        var canonicalBuffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        let canonicalRC: Int32 = canonicalBuffer.withUnsafeMutableBufferPointer { buffer in
            guard let base = buffer.baseAddress else { return -1 }
            return Darwin.fcntl(directoryFD, F_GETPATH, UnsafeMutableRawPointer(base))
        }
        guard canonicalRC == 0 else {
            throw VaultStoreError.unsafeFilesystem("cannot resolve the pinned vault parent")
        }
        let canonicalParentPath = canonicalBuffer.withUnsafeBufferPointer { buffer in
            guard let base = buffer.baseAddress else { return "" }
            return String(cString: base)
        }
        guard !canonicalParentPath.isEmpty, !canonicalParentPath.utf8.contains(0) else {
            throw VaultStoreError.unsafeFilesystem("invalid canonical vault parent")
        }
        let sqlitePath = URL(fileURLWithPath: canonicalParentPath, isDirectory: true)
            .appendingPathComponent(filename, isDirectory: false).path

        let fileFD = filename.withCString {
            Darwin.openat(directoryFD, $0,
                          O_RDWR | O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC,
                          mode_t(0o600))
        }
        guard fileFD >= 0 else {
            throw VaultStoreError.unsafeFilesystem("vault database path is redirected or failed validation")
        }
        var keepFile = true
        defer { if keepFile { Darwin.close(fileFD) } }

        var fileInfo = stat()
        guard Darwin.fstat(fileFD, &fileInfo) == 0,
              (fileInfo.st_mode & S_IFMT) == S_IFREG,
              fileInfo.st_nlink == 1,
              fileInfo.st_uid == geteuid(),
              (fileInfo.st_mode & 0o077) == 0 else {
            throw VaultStoreError.unsafeFilesystem(
                "vault database must be one private, current-user-owned regular file")
        }

        self.url = url
        self.parentPath = parentPath
        self.canonicalParentPath = canonicalParentPath
        self.sqlitePath = sqlitePath
        self.filename = filename
        self.directoryFD = directoryFD
        self.fileFD = fileFD
        self.directoryDevice = directoryInfo.st_dev
        self.directoryInode = directoryInfo.st_ino
        self.fileDevice = fileInfo.st_dev
        self.fileInode = fileInfo.st_ino
        keepDirectory = false
        keepFile = false
        try validate()
    }

    func validate() throws {
        guard !closed else { throw VaultStoreError.io("vault database path guard is closed") }
        var pinnedDirectory = stat()
        var pathDirectory = stat()
        var canonicalDirectory = stat()
        guard Darwin.fstat(directoryFD, &pinnedDirectory) == 0,
              parentPath.withCString({ Darwin.lstat($0, &pathDirectory) }) == 0,
              canonicalParentPath.withCString({ Darwin.lstat($0, &canonicalDirectory) }) == 0,
              pinnedDirectory.st_dev == directoryDevice,
              pinnedDirectory.st_ino == directoryInode,
              pathDirectory.st_dev == directoryDevice,
              pathDirectory.st_ino == directoryInode,
              canonicalDirectory.st_dev == directoryDevice,
              canonicalDirectory.st_ino == directoryInode,
              (pinnedDirectory.st_mode & S_IFMT) == S_IFDIR,
              pinnedDirectory.st_uid == geteuid(),
              (pinnedDirectory.st_mode & 0o022) == 0 else {
            throw VaultStoreError.unsafeFilesystem("vault parent identity or permissions changed")
        }

        var pinnedFile = stat()
        var directoryEntry = stat()
        var pathEntry = stat()
        let atRC = filename.withCString {
            Darwin.fstatat(directoryFD, $0, &directoryEntry, AT_SYMLINK_NOFOLLOW)
        }
        let pathRC = url.path.withCString { Darwin.lstat($0, &pathEntry) }
        guard Darwin.fstat(fileFD, &pinnedFile) == 0, atRC == 0, pathRC == 0,
              pinnedFile.st_dev == fileDevice, pinnedFile.st_ino == fileInode,
              directoryEntry.st_dev == fileDevice, directoryEntry.st_ino == fileInode,
              pathEntry.st_dev == fileDevice, pathEntry.st_ino == fileInode,
              (pinnedFile.st_mode & S_IFMT) == S_IFREG,
              pinnedFile.st_nlink == 1,
              pinnedFile.st_uid == geteuid(),
              (pinnedFile.st_mode & 0o077) == 0 else {
            throw VaultStoreError.unsafeFilesystem("vault database identity or permissions changed")
        }
    }

    /// Count this process's descriptors for the pinned inode. The caller samples
    /// before and after sqlite3_open_v2 to prove SQLite's retained main fd did not
    /// follow a raced path to another file.
    func matchingDescriptorCount() -> Int {
        var matches = 0
        let limit = Int(Darwin.getdtablesize())
        for fd in 0..<limit {
            var info = stat()
            if Darwin.fstat(Int32(fd), &info) == 0,
               info.st_dev == fileDevice, info.st_ino == fileInode {
                matches += 1
            }
        }
        return matches
    }

    func close() {
        guard !closed else { return }
        closed = true
        Darwin.close(fileFD)
        Darwin.close(directoryFD)
    }

    deinit { close() }
}

/// Owns the SQLite handle. Access stays within the `VaultStore` actor.
private final class SQLiteHandle: @unchecked Sendable {
    let raw: OpaquePointer
    private let pathGuard: DatabasePathGuard
    private(set) var isClosed = false

    init(raw: OpaquePointer, pathGuard: DatabasePathGuard) {
        self.raw = raw
        self.pathGuard = pathGuard
    }

    func validatePath() throws { try pathGuard.validate() }

    func close() {
        guard !isClosed else { return }
        sqlite3_close_v2(raw)
        pathGuard.close()
        isClosed = true
    }

    deinit {
        close()
    }
}

/// SQLITE_TRANSIENT: tells SQLite to copy bound text/blobs immediately, so Swift
/// temporaries are safe to hand over. `nonisolated(unsafe)` because a
/// `@convention(c)` function type is not formally `Sendable`; the value is an
/// immutable constant, so unguarded global access is sound.
private nonisolated(unsafe) let sqliteTransient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
