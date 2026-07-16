import Testing
import Foundation
import CryptoKit
@testable import SallyportVault
import SallyportKit

/// A fake HTTP executor: no network — asserts a credential resolved and returns
/// canned output, so the ladder is tested in isolation.
private struct FakeHTTP: ChannelExecutor {
    let requireCred: Bool
    func execute(_ action: Action, resolve: CredResolver) async throws -> ExecOutput {
        // Mimic the real executor's contract: it parses the URL itself and asks
        // the resolver for THAT host (the engine's anti-divergence check).
        let host = URL(string: action.args["url"]?.stringValue ?? "")?.host ?? ""
        let cred = try await resolve(host, "/")
        if requireCred { #expect(cred != nil, "engine must resolve the bound credential") }
        return ExecOutput(output: ["status": .double(200), "json": .object(["ok": .bool(true)])], bytesOut: 11)
    }
}

/// A scripted approver: replies with a fixed verdict and records the modes asked.
private final class FakeApprover: Approver, @unchecked Sendable {
    let verdict: ApprovalOutcome.Verdict
    private let lock = NSLock()
    private(set) var modes: [String] = []
    private var previewStorage: [String?] = []
    private var byteCountStorage: [Int?] = []
    private var truncatedStorage: [Bool] = []
    init(_ v: ApprovalOutcome.Verdict) { verdict = v }
    func requestApproval(_ req: EngineApproval) async -> ApprovalOutcome {
        lock.withLock {
            modes.append(req.mode)
            previewStorage.append(req.bodyPreview)
            byteCountStorage.append(req.bodyByteCount)
            truncatedStorage.append(req.bodyPreviewTruncated)
        }
        return ApprovalOutcome(verdict)
    }
    var askCount: Int { lock.withLock { modes.count } }
    var bodyPreviews: [String?] { lock.withLock { previewStorage } }
    var bodyByteCounts: [Int?] { lock.withLock { byteCountStorage } }
    var bodyPreviewTruncations: [Bool] { lock.withLock { truncatedStorage } }
}

private final class AuditEventSink: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [AuditEvent] = []

    func append(_ event: AuditEvent) {
        lock.withLock { storage.append(event) }
    }

    var events: [AuditEvent] { lock.withLock { storage } }
}

@Suite("Engine — the decision ladder")
struct EngineTests {
    // A live process the session gate can pin.
    let origin = SallyportVault.Origin(pid: 4242, startedAt: 1_000_000, name: "claude",
                        path: "/usr/local/bin/claude", appName: "",
                        signedBy: "Developer ID Application: Anthropic PBC", validSignature: true)
    var prov: SallyportVault.Provenance { SallyportVault.Provenance(origin: origin, chain: [SallyportVault.Hop(pid: 4242, name: "claude", path: origin.path, ppid: 1, startedAt: 1_000_000)], intact: true) }

    /// Build an engine with a temp vault (unlocked, one bound bearer key), fresh
    /// sessions/settings/audit, the given approver + http fake.
    private func build(_ approver: FakeApprover, perSessionAuth: Bool = true,
               sessionAuth: String? = nil,
               confirm: String = "",
               allowlistOverride: Allowlist? = nil) async throws -> (Engine, SessionStore, VaultStore) {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("spe-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let ks = FileAgeKeystore()
        let store = try VaultStore(creatingAt: dir.appendingPathComponent("vault.db"), keystore: ks)
        _ = try await store.set(SecretMeta(name: "cf_token", kind: "bearer", bindHosts: ["api.example.com"],
                                         inject: Inject(adapter: "bearer", header: "Authorization", format: "Bearer {secret}"),
                                         confirm: confirm), value: Data("sk_live_42".utf8))
        let settings = SettingsStore(initial: SettingsState(
            sessionAuth: sessionAuth ?? (perSessionAuth ? nil : SettingsStore.sessionAuthOff)))
        let recipient = await store.auditRecipient() ?? Data()
        let audit = try AuditLog(dir: dir.appendingPathComponent("audit"), recipientX963: recipient)
        let sessions = SessionStore()
        let engine = Engine(store: store, sessions: sessions, settings: settings, audit: audit,
                            http: FakeHTTP(requireCred: true), approver: approver, allowlist: allowlistOverride)
        return (engine, sessions, store)
    }

    private func get(_ url: String = "https://api.example.com/x") -> Action {
        Action(tool: "http.request", args: ["method": .string("GET"), "url": .string(url)])
    }

    @Test("locked vault denies everything (ladder step 1)")
    func lockedDenies() async throws {
        let (engine, _, store) = try await build(FakeApprover(.approved))
        await store.lock()
        let r = await engine.invoke(identity: "agent://test", action: get(), provenance: prov)
        #expect(!r.ok && r.errorCode == "SALLYPORT_LOCKED" && r.rule == "vault.locked")
    }

    @Test("the vault gate is ABSOLUTE: request_credential is denied while locked too")
    func lockedDeniesCredentialAsk() async throws {
        struct NeverPrompter: CredentialPrompter {
            func requestCredential(_ ask: CredentialAsk) async -> CredentialAnswer {
                Issue.record("a locked vault reached the add-key sheet")
                return .declined
            }
        }
        let approver = FakeApprover(.approved)
        let (engine, _, store) = try await build(approver)
        await engine.setCredentialPrompter(NeverPrompter())
        await store.lock()
        let action = Action(tool: "sallyport.request_credential", args: [
            "host": .string("api.x.com"), "purpose": .string("y"),
        ])
        let r = await engine.invoke(identity: "agent://test", action: action, provenance: prov)
        #expect(!r.ok && r.errorCode == "SALLYPORT_LOCKED" && r.rule == "vault.locked")
        #expect(approver.askCount == 0, "a locked vault never surfaces a card")
    }

    @Test("locked vault leaks nothing: ssh.exec denies LOCKED before any inventory lookup")
    func lockedHidesInventory() async throws {
        let approver = FakeApprover(.approved)
        let (engine, _, store) = try await build(approver)
        await store.lock()
        let action = Action(tool: "ssh.exec", args: ["host": .string("probe-me"), "cmd": .string("id")])
        let r = await engine.invoke(identity: "agent://test", action: action, provenance: prov)
        // NOT "unknown host" — that answer would let a locked-out caller probe
        // which names exist in the inventory.
        #expect(!r.ok && r.errorCode == "SALLYPORT_LOCKED")
    }

    @Test("new process → session card → approved; repeat → silent session-allow")
    func sessionApproveThenAllow() async throws {
        let approver = FakeApprover(.approved)
        let (engine, _, _) = try await build(approver)
        let r1 = await engine.invoke(identity: "agent://test", action: get(), provenance: prov)
        #expect(r1.ok && r1.decision == "session-approved")
        #expect(approver.modes == ["session"])
        let r2 = await engine.invoke(identity: "agent://test", action: get(), provenance: prov)
        #expect(r2.ok && r2.decision == "session-allow")
        #expect(approver.askCount == 1, "an approved session must not ask again")
    }

    @Test("a verdict that lands AFTER the vault locks does not admit a session (#4)")
    func lockDuringApprovalDenies() async throws {
        // An approver that locks the vault BEFORE returning approved — models a
        // card still on screen when the vault auto-locks, then clicked.
        final class LockThenApprove: Approver, @unchecked Sendable {
            let store: VaultStore
            init(_ s: VaultStore) { store = s }
            func requestApproval(_ req: EngineApproval) async -> ApprovalOutcome {
                await store.lock()
                return .approved
            }
        }
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("sple-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let store = try VaultStore(creatingAt: dir.appendingPathComponent("v.db"), keystore: FileAgeKeystore())
        _ = try await store.set(SecretMeta(name: "k", kind: "bearer", bindHosts: ["api.example.com"],
                                           inject: Inject(adapter: "bearer")), value: Data("v".utf8))
        let sessions = SessionStore()
        let engine = Engine(store: store, sessions: sessions, settings: SettingsStore(),
                            audit: try AuditLog(dir: dir.appendingPathComponent("a"),
                                                recipientX963: (await store.auditRecipient()) ?? Data()),
                            http: FakeHTTP(requireCred: true), approver: LockThenApprove(store))
        let r = await engine.invoke(identity: "agent://t", action: get(), provenance: prov)
        #expect(!r.ok && r.errorCode == "SALLYPORT_LOCKED",
                "a stale approval must not run against a locked vault")
        #expect(!sessions.approved(origin), "and it must NOT admit a session that would survive unlock")
    }

    @Test("a lock AND re-unlock while the card is up is caught by the gate epoch (#12)")
    func lockUnlockDuringApprovalDenies() async throws {
        // The vault locks AND unlocks again while the card is on screen: phase is
        // back to .ready, so a phase-only check would pass — but the epoch moved,
        // so the approval was made against a world that no longer exists.
        final class LockUnlockThenApprove: Approver, @unchecked Sendable {
            let store: VaultStore
            init(_ s: VaultStore) { store = s }
            func requestApproval(_ req: EngineApproval) async -> ApprovalOutcome {
                await store.lock()
                _ = try? await store.unlock()   // fresh DEK, phase .ready, epoch advanced
                return .approved
            }
        }
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("sple-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let store = try VaultStore(creatingAt: dir.appendingPathComponent("v.db"), keystore: FileAgeKeystore())
        _ = try await store.set(SecretMeta(name: "k", kind: "bearer", bindHosts: ["api.example.com"],
                                           inject: Inject(adapter: "bearer")), value: Data("v".utf8))
        let sessions = SessionStore()
        let engine = Engine(store: store, sessions: sessions, settings: SettingsStore(),
                            audit: try AuditLog(dir: dir.appendingPathComponent("a"),
                                                recipientX963: (await store.auditRecipient()) ?? Data()),
                            http: FakeHTTP(requireCred: true), approver: LockUnlockThenApprove(store))
        let r = await engine.invoke(identity: "agent://t", action: get(), provenance: prov)
        #expect(!r.ok && r.errorCode == "SALLYPORT_LOCKED",
                "a card approved across a lock+unlock must not run — the epoch changed")
        #expect(!sessions.approved(origin), "and it must NOT admit a session in the new epoch")
    }

    @Test("session gate set to Touch ID → the session card takes a fingerprint")
    func sessionTouchIDCeremony() async throws {
        let approver = FakeApprover(.approved)
        let (engine, _, _) = try await build(approver, sessionAuth: "touchid")
        let r = await engine.invoke(identity: "agent://test", action: get(), provenance: prov)
        #expect(r.ok && r.decision == "session-approved")
        #expect(approver.modes == ["session-touchid"],
                "the session ceremony must be the biometric one, not a plain click")

        // And it is remembered like any session: no second prompt.
        let r2 = await engine.invoke(identity: "agent://test", action: get(), provenance: prov)
        #expect(r2.ok && r2.decision == "session-allow")
        #expect(approver.askCount == 1)
    }

    @Test("a per-call CLICK key cannot admit a Touch-ID-gated session (#6 strongest ceremony)")
    func perCallClickCannotDowngradeSession() async throws {
        // Session gate = Touch ID, key = per-call CLICK. A new process must be
        // asked at the STRONGEST bar (Touch ID), not a plain click.
        let approver = FakeApprover(.approved)
        let (engine, _, _) = try await build(approver, sessionAuth: SettingsStore.sessionAuthTouchID,
                                             confirm: "click")
        let r = await engine.invoke(identity: "agent://t", action: get(), provenance: prov)
        #expect(r.ok)
        #expect(approver.modes == ["per-call-touchid"], "the card must escalate to Touch ID, not click")
    }

    @Test("HTTP bodies are disclosed only when the decision authorizes this call")
    func httpBodyDisclosureMatchesApprovalScope() async throws {
        let body = #"{"operation":"delete","id":42}"#
        let action = Action(tool: "http.request", args: [
            "method": .string("POST"),
            "url": .string("https://api.example.com/x"),
            "body": .string(body),
        ])

        let sessionApprover = FakeApprover(.approved)
        let (sessionEngine, _, _) = try await build(sessionApprover)
        let sessionResult = await sessionEngine.invoke(
            identity: "agent://session", action: action, provenance: prov)
        #expect(sessionResult.ok)
        #expect(sessionApprover.modes == ["session"])
        #expect(sessionApprover.bodyPreviews == [nil],
                "a process-session grant must not masquerade as approval of one HTTP body")

        let perCallApprover = FakeApprover(.approved)
        let (perCallEngine, _, _) = try await build(perCallApprover, confirm: "click")
        let perCallResult = await perCallEngine.invoke(
            identity: "agent://per-call", action: action, provenance: prov)
        #expect(perCallResult.ok)
        #expect(perCallApprover.modes == ["per-call"])
        let preview = try #require(perCallApprover.bodyPreviews.first ?? nil)
        #expect(preview.contains("\"operation\": \"delete\""))
        #expect(!preview.contains("sk_live_42"),
                "the display preview is created before vault credential injection")
        #expect(perCallApprover.bodyByteCounts == [body.utf8.count])
        #expect(perCallApprover.bodyPreviewTruncations == [false])
    }

    @Test("an unidentifiable caller with a per-call key is still DENIED (#6, not asked)")
    func unidentifiablePerCallStillDenied() async throws {
        let approver = FakeApprover(.approved)
        let (engine, _, _) = try await build(approver, confirm: "click")   // per-call key
        let ghost = SallyportVault.Origin(pid: 0, startedAt: 0, name: "?", path: "",
                                          appName: "", signedBy: "", validSignature: false)
        let gprov = SallyportVault.Provenance(origin: ghost, chain: [], intact: false)
        let r = await engine.invoke(identity: "agent://ghost", action: get(), provenance: gprov)
        #expect(!r.ok && r.errorCode == "SALLYPORT_UNIDENTIFIABLE")
        #expect(approver.askCount == 0, "a per-call key must NOT wave an unidentifiable caller to a card")
    }

    @Test("a lock that lands WHILE a call is in flight discards the result (#5 epoch)")
    func lockDuringExecutionDiscardsResult() async throws {
        // An HTTP fake that locks the vault mid-execute — models the vault
        // locking after the credential was materialized but before the reply.
        final class LockMidCall: ChannelExecutor, @unchecked Sendable {
            let store: VaultStore
            let epoch: Int64
            init(_ s: VaultStore, epoch: Int64) { store = s; self.epoch = epoch }
            func execute(_ action: Action, resolve: CredResolver) async throws -> ExecOutput {
                _ = try await resolve(
                    URL(string: action.args["url"]?.stringValue ?? "")?.host ?? "", "/")
                _ = await store.beginLock(expectedEpoch: epoch)
                return ExecOutput(
                    output: [
                        "status": .double(200),
                        "sensitive_output": .string("leaked"),
                        "host_key_fingerprint": .string("SHA256:test"),
                    ],
                    bytesOut: 6,
                    recording: "/tmp/recordings/partial.age")
            }
        }
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("sple2-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let store = try VaultStore(creatingAt: dir.appendingPathComponent("v.db"), keystore: FileAgeKeystore())
        _ = try await store.set(SecretMeta(name: "k", kind: "bearer", bindHosts: ["api.example.com"],
                                           inject: Inject(adapter: "bearer")), value: Data("v".utf8))
        let sessions = SessionStore()
        let activity = AuditEventSink()
        let executionEpoch = await store.epoch()
        let engine = Engine(store: store, sessions: sessions,
                            settings: SettingsStore(initial: SettingsState(sessionAuth: SettingsStore.sessionAuthOff)),
                            audit: try AuditLog(dir: dir.appendingPathComponent("a"),
                                                recipientX963: (await store.auditRecipient()) ?? Data()),
                            http: LockMidCall(store, epoch: executionEpoch), approver: FakeApprover(.approved))
        await engine.setActivitySink { activity.append($0) }
        let r = await engine.invoke(identity: "agent://t", action: get(), provenance: prov)
        #expect(!r.ok && r.errorCode == "SALLYPORT_LOCKED", "a result produced after a mid-flight lock must be discarded")
        #expect(!"\(r.output)".contains("leaked"))
        let event = try #require(activity.events.last)
        #expect(event.decision == "deny")
        #expect(event.rule == "vault.locked")
        #expect(event.isError)
        #expect(event.bytesOut == 6)
        #expect(event.hostKeyFp == "SHA256:test")
        #expect(event.recording == "/tmp/recordings/partial.age")
    }

    @Test("a lifecycle change after intent records an admission outcome")
    func lifecycleChangeDuringAdmissionRecordsOutcome() async throws {
        let (engine, sessions, store) = try await build(FakeApprover(.approved))
        let activity = AuditEventSink()
        let admissionEpoch = await store.epoch()
        await engine.setActivitySink { activity.append($0) }
        sessions.watch = { _, _, _ in
            let finished = DispatchSemaphore(value: 0)
            Task {
                _ = await store.beginLock(expectedEpoch: admissionEpoch)
                finished.signal()
            }
            // This wait blocks a cooperative-pool thread while beginLock needs
            // another one. A parallel full-suite run can starve the pool for
            // seconds, so the budget must absorb load spikes: a short budget
            // times out, the hook returns, admission wins the race, and the
            // test fails without exercising the scenario at all.
            #expect(finished.wait(timeout: .now() + 30) == .success)
        }

        let result = await engine.invoke(identity: "agent://t", action: get(), provenance: prov)

        #expect(!result.ok && result.errorCode == "SALLYPORT_LOCKED")
        #expect(sessions.list().isEmpty)
        let event = try #require(activity.events.last)
        #expect(event.decision == "deny")
        #expect(event.rule == "vault.locked")
        #expect(event.isError)
    }

    @Test("Engine.strongest picks the stronger ceremony: \"\" < click < touchid (#6)")
    func strongestCeremony() {
        #expect(Engine.strongest("", "click") == "click")
        #expect(Engine.strongest("click", "") == "click")
        #expect(Engine.strongest("click", "touchid") == "touchid")
        #expect(Engine.strongest("touchid", "click") == "touchid")
        #expect(Engine.strongest("touchid", "touchid") == "touchid")
        #expect(Engine.strongest("", "") == "")
    }

    @Test("an allowlisted agent is auto-approved without a card (#allowlist)")
    func allowlistAutoApproves() async throws {
        let approver = FakeApprover(.denied)   // no human — would DENY any card
        let entry = AllowlistEntry(id: "e1", label: "Claude", kind: .cdhash, cdhashes: ["abc"])
        // A matcher that approves our origin pid for the entry.
        let allow = Allowlist(matcher: { pid, _, cands in pid == 4242 ? cands.first : nil })
        allow.hydrate([entry])
        let (engine, _, _) = try await build(approver, allowlistOverride: allow)
        let r = await engine.invoke(identity: "agent://t", action: get(), provenance: prov)
        #expect(r.ok && r.decision == "allowlist-allow", "a matching agent runs with no card")
        #expect(approver.askCount == 0, "no human was asked")
    }

    @Test("a per-call key STILL stops for an allowlisted agent (auto-approval never bypasses per-call)")
    func allowlistDoesNotBypassPerCall() async throws {
        let approver = FakeApprover(.denied)
        let entry = AllowlistEntry(id: "e1", label: "Claude", kind: .cdhash, cdhashes: ["abc"])
        let allow = Allowlist(matcher: { _, _, cands in cands.first })
        allow.hydrate([entry])
        let (engine, _, _) = try await build(approver, confirm: "touchid", allowlistOverride: allow)
        let r = await engine.invoke(identity: "agent://t", action: get(), provenance: prov)
        #expect(!r.ok, "the per-call key must still require confirmation, allowlist or not")
        #expect(approver.modes == ["per-call-touchid"])
    }

    @Test("allowlist scope: an entry bound to other hosts does NOT cover this target")
    func allowlistScopeBounds() {
        let entry = AllowlistEntry(id: "e", label: "x", kind: .cdhash, cdhashes: ["h"],
                                   scopeHosts: ["api.other.com"])
        #expect(entry.covers("api.other.com"))
        #expect(!entry.covers("api.example.com"))
        #expect(AllowlistEntry(id: "e", label: "x", kind: .cdhash, cdhashes: ["h"]).covers("anything"))
    }

    @Test("a QUARANTINED vault denies every call — integrity is enforced, not advisory (#2)")
    func quarantineFreezesEngine() async throws {
        let approver = FakeApprover(.approved)
        let (engine, _, store) = try await build(approver)
        // A clean call first (store is born ready).
        #expect(await engine.invoke(identity: "agent://t", action: get(), provenance: prov).ok)
        // Tampering detected → the host quarantines the store.
        await store.quarantine()
        #expect(await store.operational() == false)
        let r = await engine.invoke(identity: "agent://t", action: get(), provenance: prov)
        #expect(!r.ok && r.errorCode == "SALLYPORT_QUARANTINED",
                "a tampered vault must freeze, not merely warn")
        // Re-adopt (verified) lifts it.
        await store.clearQuarantine()
        #expect(await engine.invoke(identity: "agent://t", action: get(), provenance: prov).ok)
    }

    @Test("a still-hydrating vault (unlocking) is not operational — closes the pre-hydration window (#5)")
    func unlockingIsNotOperational() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("spq-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let store = try VaultStore(creatingAt: dir.appendingPathComponent("v.db"), keystore: FileAgeKeystore())
        await store.lock()
        try await store.unlock(deferReady: true)          // DEK armed, not published
        #expect(await store.locked() == false)             // has a DEK…
        #expect(await store.operational() == false)        // …but not usable yet
        #expect(await store.phaseNow() == .unlocking)
        await store.markReady()
        #expect(await store.operational())
        await store.close()
    }

    @Test("an unidentifiable caller is DENIED when session auth is on (#19 fail-closed)")
    func unidentifiableDenied() async throws {
        let approver = FakeApprover(.approved)
        let (engine, _, _) = try await build(approver)
        // pid 0 / startedAt 0 → the session store can't pin it.
        let ghost = SallyportVault.Origin(pid: 0, startedAt: 0, name: "?", path: "",
                                          appName: "", signedBy: "", validSignature: false)
        let gprov = SallyportVault.Provenance(origin: ghost, chain: [], intact: false)
        let r = await engine.invoke(identity: "agent://ghost", action: get(), provenance: gprov)
        #expect(!r.ok && r.errorCode == "SALLYPORT_UNIDENTIFIABLE")
        #expect(approver.askCount == 0, "an unidentifiable caller is denied, not asked")
    }

    @Test("audit is written BEFORE the side effect; an unwritable audit denies (#8)")
    func auditGatesSideEffect() async throws {
        // Build with a real vault, then close the audit log so appends fail.
        let approver = FakeApprover(.approved)
        let (engine, _, _) = try await build(approver)
        // Admit the session first (so we reach the execute path), then break audit.
        _ = await engine.invoke(identity: "agent://t", action: get(), provenance: prov)
        await engine.closeAuditForTesting()
        let r = await engine.invoke(identity: "agent://t", action: get(), provenance: prov)
        #expect(!r.ok && r.errorCode == "SALLYPORT_UNAVAILABLE",
                "an action must not run when its intent can't be journaled")
    }

    @Test("observe mode does not create a session when intent cannot be written")
    func observeWaitsForAuditIntent() async throws {
        let (engine, sessions, _) = try await build(FakeApprover(.approved), perSessionAuth: false)
        await engine.closeAuditForTesting()

        let result = await engine.invoke(identity: "agent://t", action: get(), provenance: prov)

        #expect(!result.ok && result.errorCode == "SALLYPORT_UNAVAILABLE")
        #expect(sessions.list().isEmpty)
    }

    @Test("a failed completion append cannot return success")
    func completionAuditFailureOverridesSuccess() async throws {
        struct CloseAuditHTTP: ChannelExecutor {
            let audit: AuditLog

            func execute(_ action: Action, resolve: CredResolver) async throws -> ExecOutput {
                let host = URL(string: action.args["url"]?.stringValue ?? "")?.host ?? ""
                _ = try await resolve(host, "/")
                try audit.close()
                return ExecOutput(output: ["status": .double(200)], bytesOut: 3)
            }
        }

        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("spc-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let store = try VaultStore(creatingAt: dir.appendingPathComponent("v.db"), keystore: FileAgeKeystore())
        _ = try await store.set(SecretMeta(name: "k", kind: "bearer", bindHosts: ["api.example.com"],
                                           inject: Inject(adapter: "bearer")), value: Data("v".utf8))
        let audit = try AuditLog(dir: dir.appendingPathComponent("a"),
                                 recipientX963: (await store.auditRecipient()) ?? Data())
        let engine = Engine(
            store: store,
            sessions: SessionStore(),
            settings: SettingsStore(initial: SettingsState(sessionAuth: SettingsStore.sessionAuthOff)),
            audit: audit,
            http: CloseAuditHTTP(audit: audit),
            approver: FakeApprover(.approved))

        let result = await engine.invoke(identity: "agent://t", action: get(), provenance: prov)

        #expect(!result.ok)
        #expect(result.errorCode == "SALLYPORT_UNAVAILABLE")
        #expect(result.reason.contains("may have completed"))
        #expect(result.reason.contains("Do not retry automatically"))
        #expect(result.rule == "session.observe")
        #expect(result.decision == "allow")
        #expect(result.output.isEmpty)
    }

    @Test("a declined credential request still requires a completion row")
    func credentialDeclineAuditFailureOverridesSuccess() async throws {
        struct CloseAuditPrompter: CredentialPrompter {
            let audit: AuditLog

            func requestCredential(_ ask: CredentialAsk) async -> CredentialAnswer {
                try? audit.close()
                return .declined
            }
        }

        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("spc-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let store = try VaultStore(creatingAt: dir.appendingPathComponent("v.db"), keystore: FileAgeKeystore())
        let audit = try AuditLog(dir: dir.appendingPathComponent("a"),
                                 recipientX963: (await store.auditRecipient()) ?? Data())
        let engine = Engine(
            store: store,
            sessions: SessionStore(),
            settings: SettingsStore(initial: SettingsState(sessionAuth: SettingsStore.sessionAuthOff)),
            audit: audit,
            http: FakeHTTP(requireCred: false),
            approver: FakeApprover(.approved))
        await engine.setCredentialPrompter(CloseAuditPrompter(audit: audit))
        let action = Action(tool: "sallyport.request_credential", args: [
            "host": .string("api.example.com"),
            "purpose": .string("list projects"),
        ])

        let result = await engine.invoke(identity: "agent://t", action: action, provenance: prov)

        #expect(!result.ok)
        #expect(result.errorCode == "SALLYPORT_UNAVAILABLE")
        #expect(result.reason.contains("may have completed"))
        #expect(result.rule == "credential.request")
        #expect(result.decision == "credential-declined")
        #expect(result.output.isEmpty)
    }

    @Test("denied session card → fail closed, no execution")
    func deniedFailsClosed() async throws {
        let (engine, _, _) = try await build(FakeApprover(.denied))
        let r = await engine.invoke(identity: "agent://test", action: get(), provenance: prov)
        #expect(!r.ok && r.errorCode == "SALLYPORT_DENIED")
    }

    @Test("observe mode: no card, session journaled observed")
    func observeMode() async throws {
        let approver = FakeApprover(.denied) // an ask would fail — proves none happens
        let (engine, sessions, _) = try await build(approver, perSessionAuth: false)
        let r = await engine.invoke(identity: "agent://test", action: get(), provenance: prov)
        #expect(r.ok && r.decision == "allow")
        #expect(approver.askCount == 0)
        #expect(sessions.list().first?.status == .observed)
    }

    @Test("per-call key confirms EVERY call, even in an approved session")
    func perCallEveryCall() async throws {
        let approver = FakeApprover(.approved)
        let (engine, _, _) = try await build(approver, confirm: "click")
        let r1 = await engine.invoke(identity: "agent://test", action: get(), provenance: prov)
        #expect(r1.ok && r1.decision == "call-approved")
        let r2 = await engine.invoke(identity: "agent://test", action: get(), provenance: prov)
        #expect(r2.ok && r2.decision == "call-approved")
        #expect(approver.modes == ["per-call", "per-call"], "a per-call key never remembers")
    }

    @Test("an upstream response is returned without echo rewriting")
    func echoedSecretPreserved() async throws {
        /// An upstream that reflects the injected credential back (an echo
        /// endpoint / error page quoting the Authorization header).
        struct EchoHTTP: ChannelExecutor {
            func execute(_ action: Action, resolve: CredResolver) async throws -> ExecOutput {
                let host = URL(string: action.args["url"]?.stringValue ?? "")?.host ?? ""
                var cred = try await resolve(host, "/")
                defer { cred?.secret.zeroize() }
                let secret = cred?.secret ?? Data()
                return ExecOutput(output: [
                    "json": .object(["auth_echo": .string("Bearer " + String(decoding: secret, as: UTF8.self)),
                                     "nested": .array([.string("token=\(String(decoding: secret, as: UTF8.self))")])]),
                ], bytesOut: 0)
            }
        }
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("spr-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let store = try VaultStore(creatingAt: dir.appendingPathComponent("v.db"), keystore: FileAgeKeystore())
        _ = try await store.set(SecretMeta(name: "k", kind: "bearer", bindHosts: ["api.example.com"],
                                           inject: Inject(adapter: "bearer")), value: Data("sk_live_42".utf8))
        let engine = Engine(store: store, sessions: SessionStore(),
                            settings: SettingsStore(),
                            audit: try AuditLog(dir: dir.appendingPathComponent("a"),
                                                recipientX963: (await store.auditRecipient()) ?? Data()),
                            http: EchoHTTP(), approver: FakeApprover(.approved))
        let r = await engine.invoke(identity: "agent://t", action: get(), provenance: prov)
        #expect(r.ok)
        let text = String(describing: r.output)
        #expect(text.contains("sk_live_42"),
                "Sallyport must not rewrite a successful upstream response")
    }

    @Test("ssh.exec to a host that isn't in the inventory is denied WITHOUT asking a human")
    func sshUnknownHostFailsFast() async throws {
        let approver = FakeApprover(.approved)   // an ask here would be a waste
        let (engine, _, _) = try await build(approver)
        let action = Action(tool: "ssh.exec", args: ["host": .string("claude1"), "cmd": .string("hostname")])
        let r = await engine.invoke(identity: "agent://t", action: action, provenance: prov)
        #expect(!r.ok)
        #expect(r.errorCode == "SALLYPORT_UNKNOWN_HOST")
        #expect(r.reason.contains("SSH Hosts"))          // tells the human what to do
        #expect(approver.askCount == 0, "never spend an approval on a call that can't run")
    }

    @Test("an SSH recording path reaches the audit activity event")
    func sshRecordingIsAudited() async throws {
        struct RecordingSSH: SSHExecuting {
            func host(_ name: String) -> HostRef? {
                name == "box" ? HostRef(name: name, addr: "box.example") : nil
            }

            func execute(host: HostRef, command: String, timeoutS: Int, keyPEM: Data) async throws -> ExecOutput {
                ExecOutput(output: ["stdout": .string("ok")], bytesOut: 2,
                           recording: "/tmp/recordings/ssh-cast.age")
            }
        }

        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("spr-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let store = try VaultStore(creatingAt: dir.appendingPathComponent("v.db"), keystore: FileAgeKeystore())
        let audit = try AuditLog(dir: dir.appendingPathComponent("a"),
                                 recipientX963: (await store.auditRecipient()) ?? Data())
        let engine = Engine(
            store: store,
            sessions: SessionStore(),
            settings: SettingsStore(initial: SettingsState(sessionAuth: SettingsStore.sessionAuthOff)),
            audit: audit,
            http: FakeHTTP(requireCred: false),
            ssh: RecordingSSH(),
            approver: FakeApprover(.approved))
        let activity = AuditEventSink()
        await engine.setActivitySink { activity.append($0) }
        let action = Action(tool: "ssh.exec", args: [
            "host": .string("box"),
            "cmd": .string("true"),
        ])

        let result = await engine.invoke(identity: "agent://t", action: action, provenance: prov)

        #expect(result.ok)
        #expect(result.output["recording"] == .string("/tmp/recordings/ssh-cast.age"))
        let event = try #require(activity.events.last)
        #expect(event.recording == "/tmp/recordings/ssh-cast.age")
    }

    @Test("an SSH failure audits its sealed recording and presented host fingerprint")
    func sshFailureEvidenceIsAudited() async throws {
        struct FailedSSH: SSHExecuting {
            func host(_ name: String) -> HostRef? {
                name == "box" ? HostRef(name: name, addr: "box.example") : nil
            }

            func execute(host: HostRef, command: String, timeoutS: Int,
                         keyPEM: Data) async throws -> ExecOutput {
                throw SSHExecutionError(
                    message: "sshexec: handshake rejected Bearer sk_live_abcdefghij1234567890",
                    bytesOut: 17,
                    recording: "/tmp/recordings/failed-ssh-cast.age",
                    hostKeyFingerprint: "SHA256:presented-host-key")
            }
        }

        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("spf-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let store = try VaultStore(creatingAt: dir.appendingPathComponent("v.db"),
                                   keystore: FileAgeKeystore())
        let engine = Engine(
            store: store,
            sessions: SessionStore(),
            settings: SettingsStore(initial: SettingsState(sessionAuth: SettingsStore.sessionAuthOff)),
            audit: try AuditLog(dir: dir.appendingPathComponent("a"),
                                recipientX963: (await store.auditRecipient()) ?? Data()),
            http: FakeHTTP(requireCred: false),
            ssh: FailedSSH(),
            approver: FakeApprover(.approved))
        let activity = AuditEventSink()
        await engine.setActivitySink { activity.append($0) }

        let result = await engine.invoke(identity: "agent://t", action: Action(
            tool: "ssh.exec", args: ["host": .string("box"), "cmd": .string("true")]),
            provenance: prov)

        #expect(!result.ok)
        #expect(result.errorCode == "SALLYPORT_UPSTREAM_DOWN")
        #expect(result.reason.contains("handshake rejected"))
        #expect(result.reason.contains("sk_live_abcdefghij1234567890"),
                "token-shaped remote output is not treated as proof of a credential leak")
        let event = try #require(activity.events.last)
        #expect(event.isError)
        #expect(event.bytesOut == 17)
        #expect(event.recording == "/tmp/recordings/failed-ssh-cast.age")
        #expect(event.hostKeyFp == "SHA256:presented-host-key")
    }

    @Test("request_credential routes to the prompter and returns the human's answer")
    func credentialRequest() async throws {
        struct FakePrompter: CredentialPrompter {
            func requestCredential(_ ask: CredentialAsk) async -> CredentialAnswer {
                #expect(ask.host == "api.new-service.com")
                #expect(ask.hosts == ["api.new-service.com", "cdn.new-service.com"])
                #expect(ask.purpose == "list projects")
                return CredentialAnswer(provisioned: true, name: "ns_token")
            }
        }
        // The agent must be admitted first (session card), then it may ask.
        let (engine, _, _) = try await build(FakeApprover(.approved))
        await engine.setCredentialPrompter(FakePrompter())
        let action = Action(tool: "sallyport.request_credential", args: [
            "host": .string("api.new-service.com"),
            "hosts": .array([.string("api.new-service.com"), .string("cdn.new-service.com")]),
            "purpose": .string("list projects"),
        ])
        let r = await engine.invoke(identity: "agent://test", action: action, provenance: prov)
        #expect(r.ok && r.decision == "credential-provisioned")
        #expect(r.output["provisioned"] == .bool(true))
        #expect(r.output["name"] == .string("ns_token"))
    }

    @Test("request_credential with no prompter fails closed")
    func credentialRequestNoPrompter() async throws {
        let (engine, _, _) = try await build(FakeApprover(.approved))
        let action = Action(tool: "sallyport.request_credential", args: [
            "host": .string("api.x.com"), "purpose": .string("y"),
        ])
        let r = await engine.invoke(identity: "agent://test", action: action, provenance: prov)
        #expect(!r.ok)
        #expect(r.errorCode == "SALLYPORT_NO_APPROVER")
    }

    @Test("an UNAPPROVED agent cannot put a credential sheet in front of the human")
    func credentialAskIsSessionGated() async throws {
        // The phishing case: a process the human never admitted asks for a key.
        // The session card must fire FIRST, and a denial must stop the ask dead —
        // the prompter is never reached.
        struct NeverPrompter: CredentialPrompter {
            func requestCredential(_ ask: CredentialAsk) async -> CredentialAnswer {
                Issue.record("an unapproved agent reached the add-key sheet")
                return .declined
            }
        }
        let approver = FakeApprover(.denied)
        let (engine, _, _) = try await build(approver)
        await engine.setCredentialPrompter(NeverPrompter())
        let action = Action(tool: "sallyport.request_credential", args: [
            "host": .string("api.cloudflare.com"), "purpose": .string("give me your token"),
        ])
        let r = await engine.invoke(identity: "agent://evil", action: action, provenance: prov)
        #expect(!r.ok)
        #expect(r.errorCode == "SALLYPORT_DENIED")
        #expect(approver.modes == ["session"], "the session gate fires FIRST — a denial stops the ask before any add-key sheet")
    }

    @Test("a new agent's credential ask opens the session (the first-contact grant), then provisions")
    func credentialAskOpensSession() async throws {
        struct Yes: CredentialPrompter {
            func requestCredential(_ ask: CredentialAsk) async -> CredentialAnswer {
                CredentialAnswer(provisioned: true, name: "cf_token")
            }
        }
        let approver = FakeApprover(.approved)
        let (engine, sessions, _) = try await build(approver)
        await engine.setCredentialPrompter(Yes())
        let ask = Action(tool: "sallyport.request_credential", args: [
            "host": .string("api.cloudflare.com"), "purpose": .string("manage DNS"),
        ])
        let r = await engine.invoke(identity: "agent://t", action: ask, provenance: prov)
        #expect(r.ok && r.decision == "credential-provisioned")

        // The first contact is a SESSION grant: approving "open a session" admits
        // the agent, THEN the add-key sheet provisions the key. One access decision,
        // not a credential-shaped permission that grants nothing.
        #expect(sessions.approved(origin), "the credential ask goes through the session gate and admits the agent")

        // So a real call from the same process needs NO second card.
        let r2 = await engine.invoke(identity: "agent://t", action: get(), provenance: prov)
        #expect(r2.ok)
        #expect(approver.modes == ["session"], "one session card admits the agent; the credential and the later call need no more gates")
    }

    @Test("an ALREADY-admitted agent asks without a second card")
    func admittedAgentAsksDirectly() async throws {
        struct Yes: CredentialPrompter {
            func requestCredential(_ ask: CredentialAsk) async -> CredentialAnswer {
                CredentialAnswer(provisioned: true, name: "k")
            }
        }
        let approver = FakeApprover(.approved)
        let (engine, _, _) = try await build(approver)
        await engine.setCredentialPrompter(Yes())

        // Admit the session the normal way (a real call).
        _ = await engine.invoke(identity: "agent://t", action: get(), provenance: prov)
        #expect(approver.modes == ["session"])

        // Now its credential ask goes straight to the sheet — the human already
        // trusts this process; the sheet itself is the decision.
        let ask = Action(tool: "sallyport.request_credential", args: [
            "host": .string("api.x.com"), "purpose": .string("y"),
        ])
        let r = await engine.invoke(identity: "agent://t", action: ask, provenance: prov)
        #expect(r.ok && r.decision == "credential-provisioned")
        #expect(approver.askCount == 1, "an admitted agent is not re-gated to ask")
    }
}

/// The helper is the only other process that ever holds a decrypted private key,
/// so its identity is checked BEFORE the key is written to its stdin.
@Suite("SSH helper trust")
struct SSHHelperTrustTests {

    @Test("an unsigned/tampered helper is refused — the key is never handed over")
    func unsignedHelperRefused() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("sph-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        // A plain executable script standing in for a swapped-out helper: it is a
        // real executable file, but it carries no valid code signature.
        let fake = dir.appendingPathComponent("sp-ssh")
        try "#!/bin/sh\ncat > /dev/null\n".write(to: fake, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: fake.path)

        #expect(throws: (any Error).self) { try SSHSpawner.verifyHelper(fake.path) }
    }

    @Test("a missing helper is refused rather than silently skipped")
    func missingHelperRefused() throws {
        #expect(throws: (any Error).self) { try SSHSpawner.verifyHelper("/nonexistent/sp-ssh") }
        #expect(throws: (any Error).self) { try SSHSpawner.verifyHelper("") }
    }

    @Test("the real, Apple-signed system binary passes the validity check",
          .enabled(if: Provenance.ourTeam() == nil,
                   "meaningful only under a team-less (ad-hoc) test runner: CLT's swiftpm-testing-helper is Apple-signed WITH a team, so the team-pin engages and correctly refuses /bin/ls"))
    func signedBinaryPasses() throws {
        // Proves the check accepts a properly signed Mach-O (in `swift test` our own
        // binary is ad-hoc, so the team-pin is skipped and only validity is asserted).
        try SSHSpawner.verifyHelper("/bin/ls")
    }
}
