import Foundation
import AppKit
import SallyportKit
import SallyportVault

/// Handles management API operations against the live vault runtime.
/// Only `status` is available while the vault is locked. Secret listings expose
/// metadata, not secret values.
@MainActor
final class VaultMgmtDaemon {
    private let runtime: VaultRuntime
    /// Confirms a named configuration change with Touch ID.
    var confirmChange: (@MainActor (String) async -> Bool)?
    /// Test-only bypass for environments without biometrics.
    var allowChangesWithoutBiometrics = false

    init(runtime: VaultRuntime) { self.runtime = runtime }

    struct Failure: Error {
        let message: String
        let code: String?
        init(_ message: String, code: String? = nil) { self.message = message; self.code = code }
    }

    /// Applies the Touch ID change gate at the management API boundary.
    /// Security settings and allowlist changes are always gated. Reads, locking,
    /// and session revocation are exempt.
    private func requireTouchID(_ reason: String, always: Bool = false) async throws {
        if !always {
            guard let settings = runtime.host?.settings, settings.requireTouchIDForChanges() else { return }
        }
        // A missing biometric handler denies the change outside tests.
        guard let confirmChange else {
            if allowChangesWithoutBiometrics { return }
            throw Failure("Touch ID is unavailable. Change not applied: \(reason).",
                          code: "touchid_required")
        }
        guard await confirmChange(reason) else {
            throw Failure("Touch ID was not confirmed. Change not applied: \(reason).",
                          code: "touchid_required")
        }
    }

    /// The mutation name shown in the biometric prompt.
    private static func changeReason(op: String, arg: JSONValue?) -> String {
        let name = arg?.objectValue?["name"]?.stringValue ?? ""
        let quoted = name.isEmpty ? "" : " \"\(name)\""
        switch op {
        case "secrets.set":    return "Add the key\(quoted)"
        case "secrets.update": return "Change the key\(quoted)"
        case "secrets.rotate": return "Rotate the key\(quoted)"
        case "secrets.delete": return "Delete the key\(quoted)"
        case "hosts.set":      return "Add or change the SSH host\(quoted)"
        case "hosts.delete":   return "Delete the SSH host\(quoted)"
        case "upstreams.set":  return "Add or change the MCP server\(quoted)"
        case "upstreams.delete": return "Delete the MCP server\(quoted)"
        case "upstreams.authorize": return "Sign in to the MCP server\(quoted)"
        case "upstreams.disconnect": return "Sign out of the MCP server\(quoted)"
        case "settings.set":   return settingsChangeReason(arg)
        case "allowlist.add":  return "Auto-approve the agent\(quoted.isEmpty ? " \"\(arg?.objectValue?["label"]?.stringValue ?? "")\"" : quoted)"
        case "allowlist.delete": return "Remove an agent from the allowlist"
        default:               return "Change Sallyport configuration"
        }
    }

    /// Returns the setting name shown in the Touch ID prompt.
    private static func settingsChangeReason(_ arg: JSONValue?) -> String {
        let o = arg?.objectValue
        if let v = o?["sessionAuth"]?.stringValue {
            let mode = ["off": "Off", "click": "One click", "touchid": "Touch ID"][v] ?? v
            return "Set new-agent approval to \"\(mode)\""
        }
        if o?["autoLockMinutes"] != nil { return "Change the auto-lock timeout" }
        if o?["lockOnScreenLock"] != nil { return "Change lock-on-screen-lock" }
        if o?["requireTouchIDForChanges"] != nil { return "Change whether config changes need Touch ID" }
        if o?["logBodies"] != nil { return "Change the compatibility logBodies setting" }
        return "Change Sallyport security settings"
    }

    /// Operations that always require Touch ID.
    private static let alwaysGatedOps: Set<String> = ["settings.set", "allowlist.add", "allowlist.delete"]

    /// Handle one outbound message. Returns a `mgmt.reply` for `mgmt` messages,
    /// nil for anything else (the app has no other loopback traffic).
    func handle(_ message: OutboundMessage) async -> InboundMessage? {
        guard case let .mgmt(id, op, arg) = message else { return nil }
        do {
            let result = try await dispatch(op: op, arg: arg)
            return .mgmtReply(id: id, ok: true, result: result, error: nil, detail: nil, code: nil)
        } catch let f as Failure {
            return .mgmtReply(id: id, ok: false, result: nil, error: f.message, detail: nil, code: f.code)
        } catch {
            return .mgmtReply(id: id, ok: false, result: nil, error: "\(error)", detail: nil, code: nil)
        }
    }

    // MARK: - Dispatch

    private func dispatch(op: String, arg: JSONValue?) async throws -> JSONValue {
        // Status is available while locked.
        if op == "status" { return try await encodeStatus() }
        let readyStore = try await requireUnlockedStore()
        // Bind biometric confirmation to the current vault lifecycle.
        let mutationEpoch = Self.mutatingOps.contains(op) ? await readyStore.epoch() : nil

        // Gate configuration changes as required by the current settings.
        if Self.mutatingOps.contains(op) {
            try await requireTouchID(Self.changeReason(op: op, arg: arg),
                                     always: Self.alwaysGatedOps.contains(op))
        }

        // Commit the mutation and integrity state as one serialized transaction.
        if Self.mutatingOps.contains(op) {
            guard let host = runtime.host else { throw Failure("Create your vault first.") }
            let result: JSONValue
            do {
                result = try await host.commitMutation(expectedEpoch: mutationEpoch) { @Sendable [self] in
                    try await dispatchOp(op: op, arg: arg)
                }
            } catch VaultStoreError.locked {
                throw Failure("The vault state changed. Configuration was not updated.",
                              code: "locked")
            } catch VaultHost.IntegrityTransactionError.staleLifecycle {
                throw Failure("The vault state changed. Configuration was not updated.",
                              code: "locked")
            }
            applyCommittedEffects(op: op, arg: arg, host: host)
            return result
        }
        return try await dispatchOp(op: op, arg: arg)
    }

    private func dispatchOp(op: String, arg: JSONValue?) async throws -> JSONValue {
        switch op {
        case "secrets.list":  return try await listSecrets()
        case "secrets.set":   try await setSecret(arg);    return .object([:])
        case "secrets.update":try await updateSecret(arg); return .object([:])
        case "secrets.rotate":try await rotateSecret(arg); return .object([:])
        case "secrets.delete":try await deleteSecret(arg); return .object([:])

        case "hosts.list":    return try listHosts()
        case "hosts.set":     try await setHost(arg);      return .object([:])
        case "hosts.delete":  try await deleteHost(arg);   return .object([:])

        case "upstreams.list":       return try await listUpstreams()
        case "upstreams.set":        try await setUpstream(arg);    return .object([:])
        case "upstreams.delete":     try await deleteUpstream(arg); return .object([:])
        case "upstreams.authorize":  return try await authorizeUpstream(arg)
        case "upstreams.disconnect": try await disconnectUpstream(arg); return .object([:])

        case "settings.get":  return try encodePosture()
        case "settings.set":  try await applySettings(arg); return try encodePosture()

        case "sessions.list":    return try sessionList(runtime.host?.sessions.list() ?? [])
        case "sessions.history": return try sessionList(runtime.host?.sessions.history() ?? [])
        case "sessions.revoke":
            if let key = arg?.objectValue?["key"]?.stringValue,
               runtime.host?.sessions.revoke(key: key) == true {
                // Record session revocation in the audit journal.
                _ = try? runtime.host?.audit.append(SessionJournal.revokedEvent(key: key))
            }
            return .object([:])

        case "allowlist.list":    return try listAllowlist()
        case "allowlist.capture": return try captureAllowlist(arg)
        case "allowlist.add":     try await addAllowlist(arg);    return .object([:])
        case "allowlist.delete":  try await deleteAllowlist(arg); return .object([:])

        default:
            throw Failure("unknown op \"\(op)\"")
        }
    }

    /// Operations that change stored configuration.
    private static let mutatingOps: Set<String> = [
        "secrets.set", "secrets.update", "secrets.rotate", "secrets.delete",
        "hosts.set", "hosts.delete",
        "upstreams.set", "upstreams.delete", "upstreams.authorize", "upstreams.disconnect",
        "settings.set",
        "allowlist.add", "allowlist.delete",
    ]

    // MARK: - Secrets

    private func requireUnlockedStore() async throws -> VaultStore {
        guard let store = runtime.host?.store else {
            throw Failure("Create your vault first in Setup.")
        }
        // Management operations require a ready vault.
        switch await store.phaseNow() {
        case .ready:
            return store
        case .quarantined:
            throw Failure("Vault data changed. Sallyport blocked access. Accept the current state in the app to continue.",
                          code: "quarantined")
        case .locked, .unlocking:
            throw Failure("The vault is locked. Unlock it first.", code: "locked")
        }
    }

    private func listSecrets() async throws -> JSONValue {
        let store = try await requireUnlockedStore()
        let metas = (try? await store.list()) ?? []
        let wire = metas.map(Self.toWire).sorted { $0.name < $1.name }
        return try .object(["secrets": .array(wire.map { try .encoding($0) })])
    }

    private func setSecret(_ arg: JSONValue?) async throws {
        guard let o = arg?.objectValue, let name = o["name"]?.stringValue, !name.isEmpty else {
            throw Failure("secrets.set requires a name")
        }
        guard let value = o["value"]?.stringValue, !value.isEmpty else {
            throw Failure("secrets.set requires a value")
        }
        let store = try await requireUnlockedStore()
        let kind = o["kind"]?.stringValue ?? "bearer"
        let meta = SecretMeta(
            name: name, kind: kind,
            bindHosts: (o["bind"].flatMap { try? $0.decoded([String].self) }) ?? [],
            inject: Self.inject(kind: kind, o: o),
            confirm: o["confirm"]?.stringValue ?? "",
            insecureTLS: o["insecure_tls"]?.boolValue ?? false)
        var bytes = try Self.importValue(kind: kind, value: value,
                                         passphrase: o["passphrase"]?.stringValue ?? "")
        defer { bytes.resetBytes(in: 0..<bytes.count) }
        _ = try await store.set(meta, value: bytes)
    }

    /// Validates and normalizes imported SSH keys.
    private static func importValue(kind: String, value: String, passphrase: String) throws -> Data {
        guard kind.hasPrefix("ssh-") else { return Data(value.utf8) }
        do {
            return try SSHKeyImport.normalize(
                helperPath: SallyportSetup.bundledBinary("sp-ssh")?.path ?? "",
                pem: Data(value.utf8), passphrase: passphrase)
        } catch SSHKeyImport.ImportError.passphraseRequired {
            // Stable message + code: the add-key sheet shows the passphrase field
            // and retries (MgmtError.isPassphraseRequired matches both).
            throw Failure("ssh private key is passphrase-protected; provide the passphrase",
                          code: MgmtError.passphraseRequiredCode)
        } catch SSHKeyImport.ImportError.invalid(let reason) {
            throw Failure(reason)
        }
    }

    private func updateSecret(_ arg: JSONValue?) async throws {
        guard let o = arg?.objectValue, let name = o["name"]?.stringValue else {
            throw Failure("secrets.update requires a name")
        }
        let store = try await requireUnlockedStore()
        guard let existing = try? await store.meta(name: name) else {
            throw Failure("no such secret \"\(name)\"")
        }
        var inject = existing.inject
        if let h = o["header"]?.stringValue { inject.header = h }
        if let f = o["format"]?.stringValue { inject.format = f }
        let bind = (o["bind"].flatMap { try? $0.decoded([String].self) }) ?? existing.bindHosts
        try await store.updateMeta(name: name, bindHosts: bind, bindPaths: existing.bindPaths,
                                   inject: inject, confirm: o["confirm"]?.stringValue ?? existing.confirm,
                                   insecureTLS: o["insecure_tls"]?.boolValue)
    }

    private func rotateSecret(_ arg: JSONValue?) async throws {
        guard let o = arg?.objectValue, let name = o["name"]?.stringValue,
              let value = o["value"]?.stringValue, !value.isEmpty else {
            throw Failure("secrets.rotate requires a name and value")
        }
        let store = try await requireUnlockedStore()
        guard let existing = try? await store.meta(name: name) else {
            throw Failure("no such secret \"\(name)\"")
        }
        var bytes = try Self.importValue(kind: existing.kind, value: value,
                                         passphrase: o["passphrase"]?.stringValue ?? "")
        defer { bytes.resetBytes(in: 0..<bytes.count) }
        // Set bumps the version, preserving bindings/inject/confirm.
        _ = try await store.set(SecretMeta(name: name, kind: existing.kind,
                                           bindHosts: existing.bindHosts, bindPaths: existing.bindPaths,
                                           inject: existing.inject, confirm: existing.confirm),
                                value: bytes)
    }

    private func deleteSecret(_ arg: JSONValue?) async throws {
        guard let name = arg?.objectValue?["name"]?.stringValue else {
            throw Failure("secrets.delete requires a name")
        }
        let store = try await requireUnlockedStore()
        _ = try await store.delete(name: name)
    }

    /// Build the inject descriptor from the wire form. Adapter = kind for HTTP
    /// credentials (bearer/basic/header/aws-sigv4/oauth2); SSH keys are referenced by name.
    private static func inject(kind: String, o: [String: JSONValue]) -> Inject {
        if kind == "ssh-ed25519" { return Inject(adapter: "ssh") }
        let params = (o["params"].flatMap { try? $0.decoded([String: String].self) }) ?? [:]
        return Inject(adapter: kind,
                      header: o["header"]?.stringValue ?? "",
                      format: o["format"]?.stringValue ?? "",
                      params: params)
    }

    private static func toWire(_ m: SecretMeta) -> SecretMetadata {
        SecretMetadata(
            name: m.name, kind: m.kind, bind: m.bindHosts,
            adapter: m.inject.adapter.isEmpty ? m.kind : m.inject.adapter,
            header: m.inject.header.isEmpty ? nil : m.inject.header,
            format: m.inject.format.isEmpty ? nil : m.inject.format,
            params: m.inject.params, version: m.version,
            rotatedAt: iso(m.createdAt), confirm: m.confirm,
            insecureTLS: m.insecureTLS)
    }

    // MARK: - Hosts

    private func listHosts() throws -> JSONValue {
        let entries = runtime.host?.hosts.list() ?? []
        let wire = entries.map { e in
            Host(name: e.name, addr: e.addr, user: e.user, port: e.port,
                 tags: e.tags, key: e.keyName.isEmpty ? nil : e.keyName, hostkey: e.hostKeyPolicy)
        }
        return try .object(["hosts": .array(wire.map { try .encoding($0) })])
    }

    private func setHost(_ arg: JSONValue?) async throws {
        guard let hosts = runtime.host?.hosts else { throw Failure("Create your vault first.") }
        let h = try (arg ?? .null).decoded(Host.self)
        try await hosts.set(HostsStore.Entry(name: h.name, addr: h.addr, user: h.user, port: h.port,
                                             tags: h.tags, keyName: h.key ?? "", hostKeyPolicy: h.hostkey))
    }

    private func deleteHost(_ arg: JSONValue?) async throws {
        guard let name = arg?.objectValue?["name"]?.stringValue else { throw Failure("hosts.delete requires a name") }
        _ = try await runtime.host?.hosts.delete(name)
    }

    // MARK: - Upstream MCP servers

    /// Names reserved by built-in tool channels.
    private static let reservedUpstreamNames: Set<String> = ["http", "ssh", "sallyport"]

    private func listUpstreams() async throws -> JSONValue {
        guard let host = runtime.host else { return .object(["upstreams": .array([])]) }
        var wire: [Upstream] = []
        for e in host.upstreams.list() {
            wire.append(await Self.toWire(e, manager: host.upstreamManager))
        }
        return try .object(["upstreams": .array(wire.map { try .encoding($0) })])
    }

    /// One inventory row + (for OAuth servers) its live sign-in status.
    private static func toWire(_ e: UpstreamsStore.Entry, manager: UpstreamManager) async -> Upstream {
        var u = Upstream(
            name: e.name, transport: e.transport, command: e.command, args: e.args, env: e.env,
            keys: e.keys.map { UpstreamKeyBinding(secret: $0.secret, envVar: $0.envVar) },
            url: e.url, auth: e.auth, confirm: e.confirm, enabled: e.enabled)
        if e.usesOAuth {
            let status = await manager.oauthStatus(upstream: e.name)
            u.oauthConnected = status.connected
            u.oauthAccount = status.account
            u.oauthExpiry = status.expiry.map(iso) ?? ""
        }
        return u
    }

    /// Runs OAuth 2.1 sign-in in the system browser.
    private func authorizeUpstream(_ arg: JSONValue?) async throws -> JSONValue {
        guard let host = runtime.host else { throw Failure("Create your vault first.") }
        guard let name = arg?.objectValue?["name"]?.stringValue,
              let entry = host.upstreams.get(name) else {
            throw Failure("upstreams.authorize requires a known server name")
        }
        guard entry.usesOAuth else {
            throw Failure("\(name) does not use OAuth. Set authentication to OAuth first.")
        }
        do {
            _ = try await host.upstreamManager.oauthAuthorize(entry: entry, openBrowser: { url in
                Task { @MainActor in NSWorkspace.shared.open(url) }
            })
        } catch let e as MCPOAuth.OAuthError {
            throw Failure(e.description)
        } catch let e as LoopbackCallbackServer.CallbackError {
            throw Failure(e.description)
        } catch VaultStoreError.locked {
            throw Failure("The vault is locked. Unlock it first.", code: "locked")
        } catch {
            throw Failure("Sign-in failed: \(error)")
        }
        guard let fresh = host.upstreams.get(name) else { throw Failure("The MCP server was removed during sign-in.") }
        return try .encoding(await Self.toWire(fresh, manager: host.upstreamManager))
    }

    private func disconnectUpstream(_ arg: JSONValue?) async throws {
        guard let host = runtime.host else { throw Failure("Create your vault first.") }
        guard let name = arg?.objectValue?["name"]?.stringValue else {
            throw Failure("upstreams.disconnect requires a name")
        }
        try await host.upstreamManager.oauthDisconnect(upstream: name)
    }

    private func setUpstream(_ arg: JSONValue?) async throws {
        guard let host = runtime.host else { throw Failure("Create your vault first.") }
        let u = try (arg ?? .null).decoded(Upstream.self)
        let name = u.name.lowercased()
        guard !name.isEmpty, name.count <= 40,
              name.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "_" || $0 == "-" }) else {
            throw Failure("upstream name must be 1-40 characters from [a-z0-9_-]")
        }
        guard !Self.reservedUpstreamNames.contains(name) else {
            throw Failure("\(name) is reserved for a built-in channel")
        }
        switch u.transport {
        case "stdio":
            guard !u.command.trimmingCharacters(in: .whitespaces).isEmpty else {
                throw Failure("a local (stdio) MCP server needs a command to run")
            }
        case "http":
            guard UpstreamManager.validatedRemoteURL(u.url) != nil else {
                throw Failure("Remote MCP servers require HTTPS; loopback HTTP is allowed.")
            }
            guard ["apikey", "oauth"].contains(u.auth) else {
                throw Failure("unknown authentication \"\(u.auth)\"; use API key or OAuth")
            }
        default:
            throw Failure("unknown transport \"\(u.transport)\"; use stdio or http")
        }
        guard ["", "click", "touchid"].contains(u.confirm) else {
            throw Failure("unknown per-call approval \"\(u.confirm)\"")
        }
        // Remove OAuth tokens when the endpoint or authentication method changes.
        if let prior = host.upstreams.get(name) {
            let stillOAuthSameEndpoint =
                u.transport == "http" && u.auth == "oauth" &&
                prior.transport == "http" && prior.auth == "oauth" && prior.url == u.url
            if !stillOAuthSameEndpoint {
                try? await host.upstreamManager.oauthDisconnect(upstream: name)
            }
        }
        try await host.upstreams.set(UpstreamsStore.Entry(
            name: name, transport: u.transport, command: u.command, args: u.args, env: u.env,
            keys: u.keys.map { UpstreamsStore.KeyBinding(secret: $0.secret, envVar: $0.envVar) },
            url: u.url, auth: u.auth, confirm: u.confirm, enabled: u.enabled))
    }

    private func deleteUpstream(_ arg: JSONValue?) async throws {
        guard let name = arg?.objectValue?["name"]?.stringValue else {
            throw Failure("upstreams.delete requires a name")
        }
        // Remove OAuth tokens with the server entry.
        try? await runtime.host?.upstreamManager.oauthDisconnect(upstream: name)
        _ = try await runtime.host?.upstreams.delete(name)
    }

    /// Process lifecycle is an outward effect: do it only after the inventory,
    /// generation, anchor and floor have all committed. A failed checkpoint
    /// quarantines without ever spawning the unanchored configuration.
    private func applyCommittedEffects(op: String, arg: JSONValue?, host: VaultHost) {
        guard op == "upstreams.set" || op == "upstreams.delete",
              let rawName = arg?.objectValue?["name"]?.stringValue else { return }
        let name = rawName.lowercased()
        host.upstreamManager.kill(name: name)
        if op == "upstreams.set", let entry = host.upstreams.get(name), entry.enabled {
            let manager = host.upstreamManager
            Task.detached { await manager.warmUp([entry]) }
        }
    }

    // MARK: - Settings / status

    private func encodePosture() throws -> JSONValue {
        guard let settings = runtime.host?.settings else {
            return try .encoding(PostureSettings())
        }
        let s = settings.snapshot()
        return try .encoding(PostureSettings(
            sessionAuth: settings.sessionAuth(),
            requireTouchIDForChanges: settings.requireTouchIDForChanges(),
            logBodies: s.logBodies,
            autoLockMinutes: s.autoLockMinutes ?? SettingsStore.defaultAutoLockMinutes,
            lockOnScreenLock: s.lockOnScreenLock ?? true))
    }

    private func applySettings(_ arg: JSONValue?) async throws {
        guard let host = runtime.host else { throw Failure("Create your vault first.") }
        guard let o = arg?.objectValue else { return }
        if let raw = o["sessionAuth"]?.stringValue,
           ![SettingsStore.sessionAuthOff, SettingsStore.sessionAuthClick,
             SettingsStore.sessionAuthTouchID].contains(raw) {
            throw Failure("unknown session authorization \"\(raw)\"; use off, click, or touchid")
        }
        try await host.settings.update { st in
            if let v = o["sessionAuth"]?.stringValue { st.sessionAuth = v }
            if case let .bool(v)? = o["requireTouchIDForChanges"] { st.requireTouchIDForChanges = v }
            if case let .bool(v)? = o["logBodies"] { st.logBodies = v }
            if let v = o["autoLockMinutes"]?.intValue { st.autoLockMinutes = max(0, v) }
            if case let .bool(v)? = o["lockOnScreenLock"] { st.lockOnScreenLock = v }
        }
        // Apply auto-lock changes to the current deadline.
        await host.store.setAutoLockTTL(host.settings.autoLockTTL())
    }

    private func encodeStatus() async throws -> JSONValue {
        let vs = await runtime.vaultState()
        // Do not expose inventory counts while locked.
        var secretCount = 0
        var hostCount = 0
        if !vs.locked, let store = runtime.host?.store {
            secretCount = (try? await store.list().count) ?? 0
            hostCount = runtime.host?.hosts.list().count ?? 0
        }
        let status = StatusInfo(
            vault: .init(locked: vs.locked, ttlSec: vs.ttlSec),
            daemon: .init(version: "1.0 (app)", uptimeSec: 0, home: runtime.paths.sallyportHome),
            counts: .init(secrets: secretCount, hosts: hostCount))
        return try .encoding(status)
    }

    // MARK: - Sessions

    // MARK: - Agent allowlist

    private func listAllowlist() throws -> JSONValue {
        let items = (runtime.host?.allowlist.list() ?? []).map(Self.toWire)
        return try .object(["allowlist": .array(items.map { try .encoding($0) })])
    }

    /// Captures a process or file identity for allowlist review.
    private func captureAllowlist(_ arg: JSONValue?) throws -> JSONValue {
        let o = arg?.objectValue
        let cap: AllowlistCapture?
        if let pid = o?["pid"]?.intValue {
            cap = SallyportVault.Provenance.captureIdentity(pid: pid)
        } else if let path = o?["path"]?.stringValue {
            cap = SallyportVault.Provenance.captureIdentity(path: path)
        } else {
            throw Failure("allowlist.capture needs a pid or a path")
        }
        guard let cap else { throw Failure("couldn't read the code signature of that process or file") }
        let preview = AllowlistCapturePreview(
            label: cap.label, cdhashes: cap.cdhashes, teamID: cap.teamID, bundleID: cap.bundleID,
            signed: cap.signed, authority: cap.authority, capturedFrom: cap.capturedFrom,
            publisherRequirement: cap.publisherRequirement)
        return try .object(["capture": .encoding(preview)])
    }

    private func addAllowlist(_ arg: JSONValue?) async throws {
        guard let host = runtime.host,
              let item = try? arg?.decoded(AllowlistItem.self) else {
            throw Failure("allowlist.add needs an entry")
        }
        let kind: AllowlistEntry.Kind = item.kind == "publisher" ? .publisher : .cdhash
        let entry = AllowlistEntry(
            id: item.id.isEmpty ? UUID().uuidString : item.id,
            label: item.label.isEmpty ? "agent" : item.label, kind: kind,
            cdhashes: item.cdhashes, requirement: item.requirement,
            teamID: item.teamID, bundleID: item.bundleID,
            capturedFrom: item.capturedFrom, scopeHosts: item.scopeHosts)
        guard entry.isUsable else { throw Failure("that entry has no usable matcher (empty hash / requirement)") }
        try await host.allowlist.set(entry)
    }

    private func deleteAllowlist(_ arg: JSONValue?) async throws {
        guard let host = runtime.host, let id = arg?.objectValue?["id"]?.stringValue else {
            throw Failure("allowlist.delete needs an id")
        }
        _ = try await host.allowlist.delete(id)
    }

    private static func toWire(_ e: AllowlistEntry) -> AllowlistItem {
        AllowlistItem(id: e.id, label: e.label, kind: e.kind.rawValue,
                      teamID: e.teamID, bundleID: e.bundleID, cdhashes: e.cdhashes,
                      requirement: e.requirement, scopeHosts: e.scopeHosts, capturedFrom: e.capturedFrom)
    }

    private func sessionList(_ sessions: [SallyportVault.SessionInfo]) throws -> JSONValue {
        let wire = sessions.map { s in
            SessionInfo(key: s.key, pid: s.pid, name: s.name,
                        app: s.app.isEmpty ? nil : s.app, signed: s.signed,
                        signedBy: s.signedBy.isEmpty ? nil : s.signedBy,
                        status: s.status.rawValue, calls: s.calls,
                        approvedAt: iso(s.approvedAt),
                        endedAt: s.endedAt.map(iso), reason: s.reason?.rawValue)
        }
        return try .object(["sessions": .array(wire.map { try .encoding($0) })])
    }

    // MARK: - Helpers

    private static let isoFormatter: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter(); f.formatOptions = [.withInternetDateTime]; return f
    }()
    private static func iso(_ date: Date) -> String { Self.isoFormatter.string(from: date) }
    private func iso(_ date: Date) -> String { Self.iso(date) }
}
