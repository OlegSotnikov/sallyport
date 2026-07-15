import Foundation
import LocalAuthentication
import Testing
@testable import SallyportKit
@testable import SallyportApp
import SallyportVault

@MainActor
@Suite("AppModel fail-closed lifecycle", .serialized)
struct AppModelSafetyTests {
    private final class SwitchAuthenticator: Authenticator {
        let lastAuthenticatedContext: LAContext? = nil
        let isBiometric = true
        var outcome: AuthOutcome
        private(set) var prompts: [String] = []

        init(_ outcome: AuthOutcome) { self.outcome = outcome }

        func authenticate(reason: String) async -> AuthOutcome {
            prompts.append(reason)
            return outcome
        }
    }

    private final class SuspendedAuthenticator: Authenticator {
        let lastAuthenticatedContext: LAContext? = nil
        let isBiometric = true
        private(set) var started = false
        private var continuation: CheckedContinuation<AuthOutcome, Never>?

        func authenticate(reason: String) async -> AuthOutcome {
            started = true
            return await withCheckedContinuation { continuation = $0 }
        }

        func finish(_ outcome: AuthOutcome) {
            let current = continuation
            continuation = nil
            current?.resume(returning: outcome)
        }
    }

    private struct AllowApprover: Approver {
        func requestApproval(_ req: EngineApproval) async -> ApprovalOutcome { .approved }
    }

    private func model(authenticator: any Authenticator) -> AppModel {
        let model = AppModel(signer: SoftwareKeyCustodian(), authenticator: authenticator)
        model.isDemo = true // keep OS notification/panel surfaces inert
        return model
    }

    private func approval(id: String, mode: String = "session") -> EngineApproval {
        EngineApproval(
            id: id, mode: mode, rule: "test", reason: "security regression",
            channel: "ssh", tool: "ssh.exec", summary: "restart nginx", host: "prod",
            origin: Origin(pid: 42, startedAt: 1, name: "agent", path: "/usr/bin/agent",
                           appName: "Agent", signedBy: "Test signer", validSignature: true),
            chain: [])
    }

    private func credential(id: String) -> CredentialAsk {
        CredentialAsk(
            id: id, host: "api.example.com", hosts: ["api.example.com"], purpose: "deploy",
            suggestedName: "deploy_token",
            origin: Origin(pid: 42, startedAt: 1, name: "agent", path: "/usr/bin/agent"))
    }

    private func waitUntil(_ condition: @MainActor () -> Bool) async {
        for _ in 0..<1_000 {
            if condition() { return }
            await Task.yield()
        }
    }

    private func liveModel(authenticator: any Authenticator) async throws -> (AppModel, URL) {
        let root = URL(fileURLWithPath: "/tmp/spsafe-\(UUID().uuidString.prefix(8))", isDirectory: true)
        let paths = OnboardingPaths(home: root.appendingPathComponent("h").path)
        try FileManager.default.createDirectory(
            atPath: paths.sallyportHome, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o700],
                                              ofItemAtPath: paths.sallyportHome)
        let signer = SoftwareKeyCustodian()
        let model = AppModel(
            signer: signer, authenticator: authenticator,
            setup: SallyportSetup(paths: paths),
            identityGate: IdentityGate(blobURL: root.appendingPathComponent("identity.sealed")))
        try await model.runtime.createVault(hardwareGate: false, signer: signer, gate: nil)
        await model.refreshVaultFromStatus()
        return (model, root)
    }

    @Test("a denied per-call biometric leaves the operation pending until a real approval")
    func biometricDenialStaysClosed() async throws {
        let auth = SwitchAuthenticator(.denied)
        let model = model(authenticator: auth)
        let verdict = Task { await model.requestApproval(
            approval(id: "touch", mode: "per-call-touchid")) }
        await waitUntil { model.pending.contains { $0.id == "touch" } }
        let card = try #require(model.pending.first { $0.id == "touch" })

        await model.approve(card)
        #expect(model.pending.contains { $0.id == "touch" })
        #expect(auth.prompts.count == 1)
        #expect(auth.prompts[0].contains("restart nginx"))

        auth.outcome = .approved
        await model.approve(card)
        #expect(await verdict.value.verdict == .approved)
        #expect(model.pending.isEmpty)
    }

    @Test("lock wins against an in-flight biometric and cancels every parked human request")
    func lockCancelsInflightHumanWork() async throws {
        let auth = SuspendedAuthenticator()
        let model = model(authenticator: auth)
        model.vault = VaultState(locked: false, ttlSec: 600)

        let verdict = Task { await model.requestApproval(
            approval(id: "race", mode: "per-call-touchid")) }
        let credentialAnswer = Task { await model.requestCredential(credential(id: "credential")) }
        await waitUntil {
            model.pending.contains { $0.id == "race" } &&
            model.credentialRequest?.id == "credential"
        }
        let card = try #require(model.pending.first { $0.id == "race" })

        // The card was enqueued while demo mode suppressed AppKit. Exercise the
        // real lock path from this point onward.
        model.isDemo = false
        let approving = Task { await model.approve(card) }
        await waitUntil { auth.started }
        model.lockNow()
        auth.finish(.approved) // a late successful Touch ID must not resurrect it
        await approving.value

        #expect(await verdict.value.verdict == .denied)
        #expect(await credentialAnswer.value.provisioned == false)
        #expect(model.pending.isEmpty)
        #expect(model.credentialRequest == nil)
        #expect(model.vault.locked)
    }

    @Test("concurrent credential requests queue FIFO and every continuation resolves once")
    func credentialRequestsQueue() async throws {
        let model = model(authenticator: SwitchAuthenticator(.approved))
        let initialSecretsRevision = model.secretsRevision
        let first = Task { await model.requestCredential(credential(id: "first")) }
        await waitUntil { model.credentialRequest?.id == "first" }
        let second = Task { await model.requestCredential(credential(id: "second")) }
        // Let the second MainActor registration run before resolving the first.
        for _ in 0..<20 { await Task.yield() }

        let firstRequest = try #require(model.credentialRequest)
        model.respondCredential(firstRequest, provisioned: true, name: "first_key")
        await waitUntil { model.credentialRequest?.id == "second" }
        let secondRequest = try #require(model.credentialRequest)
        model.respondCredential(secondRequest, provisioned: false, name: nil)

        let firstAnswer = await first.value
        let secondAnswer = await second.value
        #expect(firstAnswer.provisioned && firstAnswer.name == "first_key")
        #expect(!secondAnswer.provisioned && secondAnswer.name == nil)
        #expect(model.credentialRequest == nil)
        #expect(model.secretsRevision != initialSecretsRevision)
    }

    @Test("duplicate in-flight IDs fail closed without replacing a card or continuation")
    func duplicateIDsDoNotConfuseRequests() async throws {
        let model = model(authenticator: SwitchAuthenticator(.approved))

        let firstApproval = Task { await model.requestApproval(approval(id: "duplicate")) }
        await waitUntil { model.pending.contains { $0.id == "duplicate" } }
        let duplicateApproval = await model.requestApproval(approval(id: "duplicate"))
        #expect(duplicateApproval.verdict == .denied)
        #expect(model.pending.filter { $0.id == "duplicate" }.count == 1)
        let card = try #require(model.pending.first { $0.id == "duplicate" })
        await model.approve(card)
        #expect(await firstApproval.value.verdict == .approved)

        let firstCredential = Task { await model.requestCredential(credential(id: "same-credential")) }
        await waitUntil { model.credentialRequest?.id == "same-credential" }
        let duplicateCredential = await model.requestCredential(credential(id: "same-credential"))
        #expect(!duplicateCredential.provisioned)
        let request = try #require(model.credentialRequest)
        model.respondCredential(request, provisioned: true, name: "retained")
        let firstAnswer = await firstCredential.value
        #expect(firstAnswer.provisioned && firstAnswer.name == "retained")
        #expect(model.credentialRequest == nil)
    }

    @Test("task cancellation removes approval cards and credential sheets without poisoning reused IDs")
    func cancellationOwnsOnlyItsRequestInstance() async throws {
        let model = model(authenticator: SwitchAuthenticator(.approved))

        let approvalTask = Task { await model.requestApproval(approval(id: "cancel-reuse")) }
        await waitUntil { model.pending.contains { $0.id == "cancel-reuse" } }
        approvalTask.cancel()
        #expect((await approvalTask.value).verdict == .denied)
        await waitUntil { model.pending.allSatisfy { $0.id != "cancel-reuse" } }

        // A delayed cancellation for the old instance may not resolve a later
        // request that reuses the same hostile caller-controlled ID.
        let replacement = Task { await model.requestApproval(approval(id: "cancel-reuse")) }
        await waitUntil { model.pending.contains { $0.id == "cancel-reuse" } }
        let replacementCard = try #require(model.pending.first { $0.id == "cancel-reuse" })
        await model.deny(replacementCard)
        #expect((await replacement.value).verdict == .denied)

        let visibleTask = Task { await model.requestCredential(credential(id: "visible")) }
        await waitUntil { model.credentialRequest?.id == "visible" }
        let queuedTask = Task { await model.requestCredential(credential(id: "queued")) }
        for _ in 0..<20 { await Task.yield() }
        queuedTask.cancel()
        #expect(!(await queuedTask.value).provisioned)

        let visible = try #require(model.credentialRequest)
        model.respondCredential(visible, provisioned: false, name: nil)
        #expect(!(await visibleTask.value).provisioned)
        #expect(model.credentialRequest == nil,
                "a cancelled queued ask must not surface later")

        let immediate = Task {
            await model.requestCredential(credential(id: "pre-cancelled"))
        }
        immediate.cancel()
        #expect(!(await immediate.value).provisioned)
        #expect(model.credentialRequest == nil)
    }

    @Test("locked management status leaks zero inventory and the gate runs before biometrics")
    func lockedManagementIsAbsolute() async throws {
        let auth = SwitchAuthenticator(.approved)
        let (model, root) = try await liveModel(authenticator: auth)
        defer { model.runtime.host?.stop(); try? FileManager.default.removeItem(at: root) }

        try await model.mgmt.setSecret(SecretInput(
            name: "hidden", kind: "bearer", value: "super-secret", bind: ["api.example.com"]))
        try await model.mgmt.setHost(Host(name: "prod", addr: "10.0.0.2", user: "root"))
        #expect(try await model.mgmt.status().counts?.secrets == 1)
        #expect(try await model.mgmt.status().counts?.hosts == 1)

        await model.runtime.lock()
        await model.refreshVaultFromStatus()
        let promptsBeforeLockedCalls = auth.prompts.count
        let status = try await model.mgmt.status()
        #expect(status.vault?.locked == true)
        #expect(status.counts?.secrets == 0)
        #expect(status.counts?.hosts == 0)

        do {
            _ = try await model.mgmt.listSecrets()
            Issue.record("locked metadata read unexpectedly succeeded")
        } catch let error as MgmtError {
            #expect(error.code == "locked")
        }
        do {
            try await model.mgmt.setSecret(SecretInput(
                name: "blocked", kind: "bearer", value: "must-not-land"))
            Issue.record("locked mutation unexpectedly succeeded")
        } catch let error as MgmtError {
            #expect(error.code == "locked")
        }
        #expect(auth.prompts.count == promptsBeforeLockedCalls,
                "the absolute vault gate must reject before showing any approval surface")
    }

    @Test("every configuration mutation fails closed when biometric wiring is absent")
    func missingBiometricWiringDeniesMutationMatrix() async throws {
        let root = URL(fileURLWithPath: "/tmp/spdaemon-\(UUID().uuidString.prefix(8))", isDirectory: true)
        let paths = OnboardingPaths(home: root.appendingPathComponent("h").path)
        try FileManager.default.createDirectory(
            atPath: paths.sallyportHome, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o700],
                                              ofItemAtPath: paths.sallyportHome)
        let runtime = VaultRuntime(paths: paths)
        runtime.approver = AllowApprover()
        let signer = SoftwareKeyCustodian()
        try await runtime.createVault(hardwareGate: false, signer: signer, gate: nil)
        defer { runtime.host?.stop(); try? FileManager.default.removeItem(at: root) }
        let daemon = VaultMgmtDaemon(runtime: runtime) // deliberately no confirmChange

        let mutationOps = [
            "secrets.set", "secrets.update", "secrets.rotate", "secrets.delete",
            "hosts.set", "hosts.delete",
            "upstreams.set", "upstreams.delete", "upstreams.authorize", "upstreams.disconnect",
            "settings.set", "allowlist.add", "allowlist.delete",
        ]
        for op in mutationOps {
            let reply = await daemon.handle(.mgmt(id: op, op: op, arg: .object([:])))
            guard case let .mgmtReply(id, ok, _, error, _, code) = reply else {
                Issue.record("\(op) returned no management reply")
                continue
            }
            #expect(id == op)
            #expect(!ok)
            #expect(code == "touchid_required")
            #expect(error?.contains("Change not applied") == true)
        }
        #expect(try await runtime.host?.store.list().isEmpty == true)
        #expect(runtime.host?.hosts.list().isEmpty == true)
        #expect(runtime.host?.upstreams.list().isEmpty == true)
        #expect(runtime.host?.allowlist.list().isEmpty == true)
    }

    @Test("the exact reset phrase still cannot erase data after biometric denial")
    func resetNeedsBothFactors() async throws {
        let auth = SwitchAuthenticator(.approved)
        let (model, root) = try await liveModel(authenticator: auth)
        defer { model.runtime.host?.stop(); try? FileManager.default.removeItem(at: root) }
        try await model.mgmt.setSecret(SecretInput(name: "keep", kind: "bearer", value: "value"))

        auth.outcome = .denied
        await #expect(throws: (any Error).self) {
            try await model.resetVault(confirmation: AppModel.resetConfirmationPhrase)
        }

        #expect(FileManager.default.fileExists(atPath: model.setup.paths.vaultDB))
        #expect(try await model.mgmt.listSecrets().map(\.name) == ["keep"])
        #expect(auth.prompts.last?.contains("Erase all Sallyport data") == true)
    }
}
