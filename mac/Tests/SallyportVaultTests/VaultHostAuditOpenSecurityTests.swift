import Foundation
import Testing
@testable import SallyportVault

@Suite("VaultHost — audit ownership cannot trigger evidence replacement", .serialized)
struct VaultHostAuditOpenSecurityTests {
    private struct Approve: Approver {
        func requestApproval(_ request: EngineApproval) async -> ApprovalOutcome { .approved }
    }

    @Test("async construction fails closed before side effects when the audit recipient is missing")
    func missingRecipientRefusesConstruction() async throws {
        let home = URL(fileURLWithPath: "/tmp/sp-audit-missing-\(UUID().uuidString.prefix(8))",
                       isDirectory: true)
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: home) }

        let store = try VaultStore(creatingAt: home.appendingPathComponent("vault.db"),
                                   keystore: FileAgeKeystore())
        try await store._removeAuditRecipientForTesting()
        let auditDir = home.appendingPathComponent("audit", isDirectory: true)
        let paths = VaultHost.Paths(
            socket: home.appendingPathComponent("control.sock").path,
            auditDir: auditDir.path,
            knownHosts: home.appendingPathComponent("known_hosts").path,
            recordDir: home.appendingPathComponent("records").path,
            sshHelper: "")

        await #expect(throws: AuditError.self) {
            _ = try await VaultHost(store: store, hosts: HostsStore(), paths: paths,
                                    approver: Approve())
        }
        #expect(!FileManager.default.fileExists(atPath: auditDir.path),
                "a host without a recipient must not create or rotate audit evidence")
        await store.close()
    }

    @Test("a second writer fails without archiving or replacing the live journal")
    func writerContentionPreservesEvidence() async throws {
        let home = URL(fileURLWithPath: "/tmp/sp-audit-own-\(UUID().uuidString.prefix(8))",
                       isDirectory: true)
        try FileManager.default.createDirectory(
            at: home, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: home) }

        let store = try VaultStore(creatingAt: home.appendingPathComponent("vault.db"),
                                   keystore: FileAgeKeystore())
        let auditDir = home.appendingPathComponent("audit", isDirectory: true)
        let paths = VaultHost.Paths(
            socket: home.appendingPathComponent("control.sock").path,
            auditDir: auditDir.path,
            knownHosts: home.appendingPathComponent("known_hosts").path,
            recordDir: home.appendingPathComponent("records").path,
            sshHelper: "")
        let first = try await VaultHost(store: store, hosts: HostsStore(), paths: paths,
                                        approver: Approve())
        let sentinel = auditDir.appendingPathComponent("ownership-sentinel")
        try Data("original evidence directory".utf8).write(to: sentinel)

        await #expect(throws: AuditError.self) {
            _ = try await VaultHost(store: store, hosts: HostsStore(), paths: paths,
                                    approver: Approve())
        }

        withExtendedLifetime(first) {}
        #expect(try Data(contentsOf: sentinel) == Data("original evidence directory".utf8))
        let siblings = try FileManager.default.contentsOfDirectory(atPath: home.path)
        #expect(!siblings.contains { $0.hasPrefix("audit.corrupt-") },
                "writer contention is not row corruption and must never rotate evidence")
        await store.close()
    }
}
