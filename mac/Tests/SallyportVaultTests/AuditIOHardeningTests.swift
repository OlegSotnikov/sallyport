import Testing
import Foundation
import CryptoKit
import Darwin
@testable import SallyportVault

private func withHardenedAuditDirectory(_ body: (URL) throws -> Void) throws {
    let dir = FileManager.default.temporaryDirectory
        .appendingPathComponent("sallyport-audit-io-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(
        at: dir, withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700])
    guard Darwin.chmod(dir.path, 0o700) == 0 else {
        throw AuditError.io("test chmod failed")
    }
    defer { try? FileManager.default.removeItem(at: dir) }
    try body(dir)
}

private func hardenedAuditKeys() -> (recipient: Data, identity: Data) {
    let identity = P256.KeyAgreement.PrivateKey()
    return (identity.publicKey.x963Representation, identity.rawRepresentation)
}

private func isIOFailure(_ error: AuditError?) -> Bool {
    if case .io = error { return true }
    return false
}

@Suite("AuditLog — bounded streaming and filesystem confinement")
struct AuditIOHardeningTests {
    @Test("a legitimate row spanning several read chunks verifies, decrypts, and recovers")
    func chunkSplitRowRoundTrips() throws {
        try withHardenedAuditDirectory { dir in
            let keys = hardenedAuditKeys()
            let preview = String(repeating: "x", count: 160 * 1024)
            let log = try AuditLog(dir: dir, recipientX963: keys.recipient)
            try log.append(AuditEvent(tool: "http.request", argsPreview: preview,
                                      decision: "allow"))
            try log.close()

            #expect(AuditLog.verify(dir: dir) == (count: 1, ok: true))
            let events = try AuditLog.read(dir: dir, identityRaw: keys.identity)
            #expect(events.count == 1)
            #expect(events[0].argsPreview == preview)

            // Recovery uses the same streaming reader and must resume at seq 2.
            let reopened = try AuditLog(dir: dir, recipientX963: keys.recipient)
            let second = try reopened.append(AuditEvent(tool: "ssh.exec", decision: "deny"))
            try reopened.close()
            #expect(second.seq == 2)
            #expect(AuditLog.verify(dir: dir) == (count: 2, ok: true))
        }
    }

    @Test("oversized and unterminated rows are rejected without reopening for append")
    func malformedRowBounds() throws {
        try withHardenedAuditDirectory { dir in
            let path = dir.appendingPathComponent(AuditLog.fileName)
            var oversized = Data(repeating: 0x61, count: AuditLog.maximumRowBytes + 1)
            oversized.append(0x0A)
            try oversized.write(to: path)
            guard Darwin.chmod(path.path, 0o600) == 0 else {
                throw AuditError.io("test chmod failed")
            }

            let oversizedResult = AuditLog.verifyDetailed(dir: dir)
            #expect(oversizedResult.count == 0)
            if case .corruptRow(let row, let detail) = oversizedResult.failure {
                #expect(row == 1)
                #expect(detail.contains("exceeds"))
            } else {
                Issue.record("oversized row was not reported as corrupt")
            }
            let keys = hardenedAuditKeys()
            #expect(throws: AuditError.self) {
                _ = try AuditLog(dir: dir, recipientX963: keys.recipient)
            }

            try Data("{}".utf8).write(to: path)
            let tornResult = AuditLog.verifyDetailed(dir: dir)
            if case .corruptRow(let row, let detail) = tornResult.failure {
                #expect(row == 1)
                #expect(detail.contains("unterminated"))
            } else {
                Issue.record("unterminated row was not reported as corrupt")
            }
        }
    }

    @Test("hostile sequence extremes and out-of-range integers fail without arithmetic traps")
    func hostileSequenceExtremes() throws {
        try withHardenedAuditDirectory { dir in
            let path = dir.appendingPathComponent(AuditLog.fileName)
            let keys = hardenedAuditKeys()

            for hostileSeq in [Int64.max, Int64.min] {
                let row = SealedAuditRow(
                    seq: hostileSeq,
                    sealed: "",
                    prevHash: AuditLog.genesisPrev,
                    thisHash: String(repeating: "0", count: 64))
                var bytes = try JSONEncoder().encode(row)
                bytes.append(0x0A)
                try bytes.write(to: path)
                guard Darwin.chmod(path.path, 0o600) == 0 else {
                    throw AuditError.io("test chmod failed")
                }

                let before = try Data(contentsOf: path)
                let result = AuditLog.verifyDetailed(dir: dir)
                if case .seqGap(let row, let got) = result.failure {
                    #expect(row == 1)
                    #expect(got == hostileSeq)
                } else {
                    Issue.record("sequence extreme was not rejected as a gap")
                }
                #expect(throws: AuditError.self) {
                    _ = try AuditLog(dir: dir, recipientX963: keys.recipient)
                }
                #expect(try Data(contentsOf: path) == before)
            }

            let beyondInt64 = "{\"seq\":9223372036854775808,\"sealed\":\"\",\"prev_hash\":\"x\",\"this_hash\":\"y\"}\n"
            try Data(beyondInt64.utf8).write(to: path)
            guard Darwin.chmod(path.path, 0o600) == 0 else {
                throw AuditError.io("test chmod failed")
            }
            let result = AuditLog.verifyDetailed(dir: dir)
            if case .corruptRow(let row, _) = result.failure {
                #expect(row == 1)
            } else {
                Issue.record("out-of-range sequence was not rejected as corrupt")
            }
            #expect(throws: AuditError.self) {
                _ = try AuditLog(dir: dir, recipientX963: keys.recipient)
            }
        }
    }

    @Test("append refuses to create a row that its reader would reject")
    func appendEnforcesRowBound() throws {
        try withHardenedAuditDirectory { dir in
            let keys = hardenedAuditKeys()
            let log = try AuditLog(dir: dir, recipientX963: keys.recipient)
            let hostile = String(repeating: "z", count: AuditLog.maximumRowBytes)
            #expect(throws: AuditError.self) {
                try log.append(AuditEvent(tool: "http.request", argsPreview: hostile))
            }
            try log.close()
            #expect(AuditLog.verify(dir: dir) == (count: 0, ok: true))
        }
    }

    @Test("read retains only an explicit tail but still verifies every older row")
    func boundedReadStillVerifiesPrefix() throws {
        try withHardenedAuditDirectory { dir in
            let keys = hardenedAuditKeys()
            let log = try AuditLog(dir: dir, recipientX963: keys.recipient)
            for i in 1...6 {
                try log.append(AuditEvent(tool: "http.request", target: "host-\(i)"))
            }
            try log.close()

            let tail = try AuditLog.read(
                dir: dir, identityRaw: keys.identity, retainingLast: 2)
            #expect(tail.map(\.seq) == [5, 6])
            #expect(tail.map(\.target) == ["host-5", "host-6"])
            #expect(try AuditLog.read(
                dir: dir, identityRaw: keys.identity, retainingLast: 0).isEmpty)
            #expect(try AuditLog.read(
                dir: dir, identityRaw: keys.identity,
                retainingLast: 6, retainingAtMostBytes: 1).isEmpty)
            #expect(throws: AuditError.self) {
                _ = try AuditLog.read(
                    dir: dir, identityRaw: keys.identity, retainingLast: -1)
            }

            // Damage row 1. A tail-only implementation could miss this; the
            // bounded reader must authenticate the complete prefix first.
            let path = dir.appendingPathComponent(AuditLog.fileName)
            var lines = try String(contentsOf: path, encoding: .utf8)
                .split(separator: "\n").map(String.init)
            var first = try JSONDecoder().decode(SealedAuditRow.self, from: Data(lines[0].utf8))
            let replacement = first.sealed.first == "A" ? "B" : "A"
            first.sealed = replacement + first.sealed.dropFirst()
            lines[0] = String(decoding: try JSONEncoder().encode(first), as: UTF8.self)
            try Data((lines.joined(separator: "\n") + "\n").utf8).write(to: path)

            #expect(throws: AuditError.tampered(seq: 1)) {
                _ = try AuditLog.read(
                    dir: dir, identityRaw: keys.identity, retainingLast: 2)
            }
        }
    }

    @Test("journal path refuses symlinks without modifying their target")
    func symlinkRefused() throws {
        try withHardenedAuditDirectory { dir in
            let target = dir.appendingPathComponent("outside-target")
            let original = Data("do-not-touch".utf8)
            try original.write(to: target)
            let path = dir.appendingPathComponent(AuditLog.fileName)
            try FileManager.default.createSymbolicLink(at: path, withDestinationURL: target)

            let result = AuditLog.verifyDetailed(dir: dir)
            #expect(isIOFailure(result.failure))
            let keys = hardenedAuditKeys()
            #expect(throws: AuditError.self) {
                _ = try AuditLog(dir: dir, recipientX963: keys.recipient)
            }
            #expect(try Data(contentsOf: target) == original)
        }
    }

    @Test("journal path refuses FIFOs immediately")
    func fifoRefused() throws {
        try withHardenedAuditDirectory { dir in
            let path = dir.appendingPathComponent(AuditLog.fileName)
            guard Darwin.mkfifo(path.path, 0o600) == 0 else {
                throw AuditError.io("test mkfifo failed")
            }
            #expect(isIOFailure(AuditLog.verifyDetailed(dir: dir).failure))
            let keys = hardenedAuditKeys()
            #expect(throws: AuditError.self) {
                _ = try AuditLog(dir: dir, recipientX963: keys.recipient)
            }
        }
    }

    @Test("journal path refuses hardlinks")
    func hardlinkRefused() throws {
        try withHardenedAuditDirectory { dir in
            let source = dir.appendingPathComponent("aliased-file")
            try Data().write(to: source)
            guard Darwin.chmod(source.path, 0o600) == 0 else {
                throw AuditError.io("test chmod failed")
            }
            let path = dir.appendingPathComponent(AuditLog.fileName)
            guard Darwin.link(source.path, path.path) == 0 else {
                throw AuditError.io("test link failed")
            }

            #expect(isIOFailure(AuditLog.verifyDetailed(dir: dir).failure))
            let keys = hardenedAuditKeys()
            #expect(throws: AuditError.self) {
                _ = try AuditLog(dir: dir, recipientX963: keys.recipient)
            }
        }
    }

    @Test("writer repairs private directory and journal permissions")
    func permissionsAreTightened() throws {
        try withHardenedAuditDirectory { dir in
            let path = dir.appendingPathComponent(AuditLog.fileName)
            try Data().write(to: path)
            guard Darwin.chmod(dir.path, 0o777) == 0,
                  Darwin.chmod(path.path, 0o666) == 0 else {
                throw AuditError.io("test chmod failed")
            }

            let keys = hardenedAuditKeys()
            let log = try AuditLog(dir: dir, recipientX963: keys.recipient)
            try log.close()

            var dirInfo = stat()
            var fileInfo = stat()
            #expect(lstat(dir.path, &dirInfo) == 0)
            #expect(lstat(path.path, &fileInfo) == 0)
            #expect((dirInfo.st_mode & 0o777) == 0o700)
            #expect((fileInfo.st_mode & 0o777) == 0o600)
        }
    }

    @Test("only one writer may recover and append a chain at a time")
    func concurrentWriterRefused() throws {
        try withHardenedAuditDirectory { dir in
            let keys = hardenedAuditKeys()
            let first = try AuditLog(dir: dir, recipientX963: keys.recipient)
            #expect(throws: AuditError.self) {
                _ = try AuditLog(dir: dir, recipientX963: keys.recipient)
            }
            try first.close()

            let next = try AuditLog(dir: dir, recipientX963: keys.recipient)
            try next.close()
        }
    }

    @Test("unlink and replacement after open invalidates the pinned writer")
    func postOpenReplacementRefused() throws {
        try withHardenedAuditDirectory { dir in
            let keys = hardenedAuditKeys()
            let log = try AuditLog(dir: dir, recipientX963: keys.recipient)
            let path = dir.appendingPathComponent(AuditLog.fileName)
            let target = dir.appendingPathComponent("replacement-target")
            let original = Data("untouched".utf8)
            try original.write(to: target)
            try FileManager.default.removeItem(at: path)
            try FileManager.default.createSymbolicLink(at: path, withDestinationURL: target)

            #expect(throws: AuditError.self) {
                try log.append(AuditEvent(tool: "http.request"))
            }
            try log.close()
            #expect(try Data(contentsOf: target) == original)
        }
    }
}
