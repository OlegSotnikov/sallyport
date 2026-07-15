import Testing
import Foundation
import CryptoKit
@testable import SallyportVault

/// Creates a unique scratch directory for one test and removes it afterwards.
private func withTempDir(_ body: (URL) throws -> Void) throws {
    let dir = FileManager.default.temporaryDirectory
        .appendingPathComponent("sallyport-audit-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: dir) }
    try body(dir)
}

/// A fresh audit keypair: the RECIPIENT (public — all the writer ever holds)
/// and the IDENTITY (private — what the unlocked vault hands the reader).
private func newAuditKeys() -> (recipient: Data, identity: Data) {
    let id = P256.KeyAgreement.PrivateKey()
    return (id.publicKey.x963Representation, id.rawRepresentation)
}

private func appendN(_ log: AuditLog, _ n: Int) throws {
    for i in 0..<n {
        try log.append(AuditEvent(
            identity: "agent://mac.cli",
            channel: "http",
            tool: "http.request",
            target: "api.cloudflare.com",
            decision: "allow",
            rule: "http-get-bound",
            bytesOut: 100 + i))
    }
}

private struct Boom: Error {}

@Suite("AuditLog — write-blind encrypted, tamper-evident chain")
struct AuditLogTests {

    @Test("chain builds and verifies WITHOUT any key (over the ciphertext)")
    func chainBuildsAndVerifies() throws {
        try withTempDir { dir in
            let keys = newAuditKeys()
            let log = try AuditLog(dir: dir, recipientX963: keys.recipient)
            try appendN(log, 5)
            try log.close()

            let res = AuditLog.verify(dir: dir)
            #expect(res.ok)
            #expect(res.count == 5)
        }
    }

    @Test("first row links to genesis; the returned event mirrors the outer chain")
    func firstRowLinksToGenesis() throws {
        try withTempDir { dir in
            let keys = newAuditKeys()
            let log = try AuditLog(dir: dir, recipientX963: keys.recipient)
            let e = try log.append(AuditEvent(tool: "http.request", decision: "allow"))
            try log.close()
            #expect(e.seq == 1)
            #expect(e.prevHash == AuditLog.genesisPrev)
            #expect(!e.thisHash.isEmpty)
        }
    }

    @Test("the file is ciphertext: no tool, target, identity or origin in the clear")
    func rowsAreSealedAtRest() throws {
        try withTempDir { dir in
            let keys = newAuditKeys()
            let log = try AuditLog(dir: dir, recipientX963: keys.recipient)
            try log.append(AuditEvent(
                identity: "agent://mac.cli", channel: "http", tool: "http.request",
                target: "api.supersecret-project.com", argsPreview: "GET /zones",
                decision: "allow", rule: "session.approved",
                origin: AuditEvent.Origin(name: "claude", path: "/usr/local/bin/claude",
                                          signedBy: "Developer ID Application: Anthropic PBC")))
            try log.close()

            let raw = try String(contentsOf: dir.appendingPathComponent(AuditLog.fileName),
                                 encoding: .utf8)
            #expect(!raw.contains("supersecret-project"))
            #expect(!raw.contains("http.request"))
            #expect(!raw.contains("agent://mac.cli"))
            #expect(!raw.contains("Anthropic"))
            #expect(!raw.contains("claude"))
            // The chain skeleton IS visible — that is the design.
            #expect(raw.contains("\"seq\""))
            #expect(raw.contains("\"sealed\""))
        }
    }

    @Test("read decrypts with the identity; a wrong identity fails closed")
    func readRequiresIdentity() throws {
        try withTempDir { dir in
            let keys = newAuditKeys()
            let log = try AuditLog(dir: dir, recipientX963: keys.recipient)
            try log.append(AuditEvent(identity: "agent://mac.cli", tool: "http.request",
                                      target: "api.cloudflare.com", decision: "allow"))
            try log.append(AuditEvent(tool: "ssh.exec", target: "prod-1", decision: "deny",
                                      isError: true))
            try log.close()

            let events = try AuditLog.read(dir: dir, identityRaw: keys.identity)
            #expect(events.count == 2)
            #expect(events[0].seq == 1)
            #expect(events[0].tool == "http.request")
            #expect(events[0].target == "api.cloudflare.com")
            #expect(events[0].prevHash == AuditLog.genesisPrev)
            #expect(events[1].seq == 2)
            #expect(events[1].decision == "deny")
            #expect(events[1].isError)
            #expect(events[1].prevHash == events[0].thisHash)

            let stranger = newAuditKeys()
            #expect(throws: AuditError.unreadable(seq: 1)) {
                _ = try AuditLog.read(dir: dir, identityRaw: stranger.identity)
            }
        }
    }

    @Test("an edited (re-sealed) row is detected without any key")
    func tamperDetected() throws {
        try withTempDir { dir in
            let keys = newAuditKeys()
            let log = try AuditLog(dir: dir, recipientX963: keys.recipient)
            try appendN(log, 4)
            try log.close()

            // Tamper with row 2's ciphertext, keeping the row's own hashes —
            // the chain hash over (seq, sealed) must catch it.
            let path = dir.appendingPathComponent(AuditLog.fileName)
            var lines = try String(contentsOf: path, encoding: .utf8)
                .split(separator: "\n").map(String.init)
            var row = try JSONSerialization.jsonObject(with: Data(lines[1].utf8)) as! [String: Any]
            let sealed = row["sealed"] as! String
            row["sealed"] = String(sealed.dropFirst(8)) + String(sealed.prefix(8))
            lines[1] = String(decoding: try JSONSerialization.data(withJSONObject: row), as: UTF8.self)
            try (lines.joined(separator: "\n") + "\n").write(to: path, atomically: true, encoding: .utf8)

            let res = AuditLog.verify(dir: dir)
            #expect(!res.ok)
            #expect(AuditLog.verifyDetailed(dir: dir).failure == .tampered(seq: 2))
        }
    }

    @Test("a deleted row is detected")
    func deletionDetected() throws {
        try withTempDir { dir in
            let keys = newAuditKeys()
            let log = try AuditLog(dir: dir, recipientX963: keys.recipient)
            try appendN(log, 4)
            try log.close()

            let path = dir.appendingPathComponent(AuditLog.fileName)
            let original = try String(contentsOf: path, encoding: .utf8)
            var lines = original.split(separator: "\n").map(String.init)
            #expect(lines.count == 4)
            lines.remove(at: 1)
            try (lines.joined(separator: "\n") + "\n")
                .write(to: path, atomically: true, encoding: .utf8)

            #expect(!AuditLog.verify(dir: dir).ok)
        }
    }

    @Test("a failed durability barrier rolls back seq and prev")
    func syncFailureRollsBackSeqAndPrev() throws {
        try withTempDir { dir in
            let keys = newAuditKeys()
            let log = try AuditLog(dir: dir, recipientX963: keys.recipient)
            try log.append(AuditEvent(tool: "http.request", decision: "allow"))
            let before = log._chainStateForTesting

            // Inject a failing sync (e.g. ENOSPC on the durability barrier).
            log._setSyncForTesting { throw Boom() }
            #expect(throws: (any Error).self) {
                try log.append(AuditEvent(tool: "http.request", decision: "ask"))
            }
            let after = log._chainStateForTesting
            #expect(after.seq == before.seq, "seq not rolled back after sync failure")
            #expect(after.prev == before.prev, "prev advanced despite sync failure")

            // The NEXT append continues from the last committed row.
            log._setSyncForTesting(nil)
            let e = try log.append(AuditEvent(tool: "http.request", decision: "ask"))
            try log.close()
            #expect(e.seq == before.seq + 1)
            let res = AuditLog.verify(dir: dir)
            #expect(res.ok)
            #expect(res.count == 2)
        }
    }

    @Test("reopen continues the chain, and read spans the boundary")
    func reopenContinuesChain() throws {
        try withTempDir { dir in
            let keys = newAuditKeys()
            let log = try AuditLog(dir: dir, recipientX963: keys.recipient)
            try appendN(log, 3)
            try log.close()

            let log2 = try AuditLog(dir: dir, recipientX963: keys.recipient)
            let e = try log2.append(AuditEvent(tool: "http.request", decision: "ask"))
            try log2.close()
            #expect(e.seq == 4)

            let res = AuditLog.verify(dir: dir)
            #expect(res.ok)
            #expect(res.count == 4)

            let events = try AuditLog.read(dir: dir, identityRaw: keys.identity)
            #expect(events.count == 4)
            #expect(events.last?.decision == "ask")
        }
    }

    @Test("an unwritable log surfaces an error (fail-closed)")
    func appendAfterCloseFailsClosed() throws {
        try withTempDir { dir in
            let keys = newAuditKeys()
            let log = try AuditLog(dir: dir, recipientX963: keys.recipient)
            try log.append(AuditEvent(tool: "http.request", decision: "allow"))
            try log.close()
            #expect(throws: (any Error).self) {
                try log.append(AuditEvent(tool: "http.request", decision: "allow"))
            }
            // The committed prefix is still intact.
            let res = AuditLog.verify(dir: dir)
            #expect(res.ok)
            #expect(res.count == 1)
        }
    }

    @Test("a missing log is an empty, trivially valid chain")
    func missingLogIsEmptyValidChain() throws {
        try withTempDir { dir in
            let res = AuditLog.verify(dir: dir)
            #expect(res.ok)
            #expect(res.count == 0)
            let events = try AuditLog.read(dir: dir, identityRaw: newAuditKeys().identity)
            #expect(events.isEmpty)
        }
    }

    @Test("a garbage recipient is refused at open")
    func badRecipientRefused() throws {
        try withTempDir { dir in
            #expect(throws: (any Error).self) {
                _ = try AuditLog(dir: dir, recipientX963: Data("not-a-key".utf8))
            }
        }
    }
}
