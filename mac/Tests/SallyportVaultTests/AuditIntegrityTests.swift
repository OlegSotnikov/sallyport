import Testing
import Foundation
import CryptoKit
import SallyportKit
@testable import SallyportVault

/// The forgery-resistance + freshness layer (docs/06): per-row signatures,
/// the signed anchor, and the crash-orphan session reconciler.

private func freshDir() throws -> URL {
    let dir = FileManager.default.temporaryDirectory
        .appendingPathComponent("sp-integ-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    return dir
}

private func newRecipient() -> Data {
    P256.KeyAgreement.PrivateKey().publicKey.x963Representation
}

private func row(_ tool: String, session: String = "", target: String = "") -> AuditEvent {
    AuditEvent(identity: "agent://t", session: session, channel: "http",
               tool: tool, target: target, decision: "allow", rule: "test")
}

@Suite("Audit — signed rows (forgery resistance)")
struct AuditSignedRowTests {

    @Test("rows are signed; verification against the right key passes, a foreign key fails")
    func signAndVerify() throws {
        let dir = try freshDir()
        let signer = SoftwareAuditSigner()
        let log = try AuditLog(dir: dir, recipientX963: newRecipient(), signer: signer)
        for i in 1...3 { try log.append(row("http.request", target: "h\(i)")) }
        try log.close()

        #expect(AuditLog.verifyDetailed(dir: dir, signerPublicKeyX963: signer.publicKeyX963).failure == nil)
        // A different keypair — e.g. an attacker re-signing with their own key.
        let foreign = SoftwareAuditSigner()
        let bad = AuditLog.verifyDetailed(dir: dir, signerPublicKeyX963: foreign.publicKeyX963).failure
        #expect(bad == .badSignature(seq: 1))
    }

    @Test("an ssh host-key fingerprint is bound into the SIGNED row; absent, it changes nothing (#13)")
    func hostKeyFingerprintSigned() throws {
        let dir = try freshDir()
        let signer = SoftwareAuditSigner()
        let log = try AuditLog(dir: dir, recipientX963: newRecipient(), signer: signer)
        var ev = AuditEvent(identity: "agent://t", channel: "ssh", tool: "ssh.exec",
                            target: "prod", decision: "allow", rule: "session.approved",
                            hostKeyFp: "SHA256:abc123")
        try log.append(ev)
        try log.close()
        // The whole (signed) chain verifies with the fingerprint in it.
        #expect(AuditLog.verifyDetailed(dir: dir, signerPublicKeyX963: signer.publicKeyX963).failure == nil)
        // The fingerprint IS part of the canonical, signed payload…
        #expect(ev.canonicalString.contains("host_key_fp"))
        #expect(ev.canonicalString.contains("SHA256:abc123"))
        // …but a row WITHOUT one omits the key entirely — so every pre-existing
        // (and every non-ssh) row signs byte-for-byte as before: no reinstall.
        ev.hostKeyFp = ""
        #expect(!ev.canonicalString.contains("host_key_fp"))
    }

    @Test("the classic offline attack — rewrite a row and re-chain the hashes — passes the bare chain but FAILS signature verification")
    func rechainedForgeryIsCaught() throws {
        let dir = try freshDir()
        let signer = SoftwareAuditSigner()
        let recipient = newRecipient()
        let log = try AuditLog(dir: dir, recipientX963: recipient, signer: signer)
        for i in 1...4 { try log.append(row("http.request", target: "h\(i)")) }
        try log.close()

        // The attacker has full file access and the (public) recipient key, so
        // they can seal a NEW payload and recompute every chain hash — the
        // exact attack the bare hash chain cannot see.
        let path = dir.appendingPathComponent(AuditLog.fileName)
        let lines = try String(contentsOf: path, encoding: .utf8)
            .split(separator: "\n").map(String.init)
        var rows = try lines.map {
            try JSONDecoder().decode(SealedAuditRow.self, from: Data($0.utf8))
        }
        let forgedPayload = try ECIES.seal(Data("{\"forged\":true}".utf8),
                                           to: P256.KeyAgreement.PublicKey(x963Representation: recipient))
        rows[1].sealed = forgedPayload.base64EncodedString()
        var prev = AuditLog.genesisPrev
        for i in rows.indices {
            rows[i].prevHash = prev
            rows[i].thisHash = AuditLog.chainHash(prev: prev, seq: rows[i].seq, sealed: rows[i].sealed)
            prev = rows[i].thisHash
        }
        let enc = JSONEncoder()
        let rewritten = try rows.map { String(decoding: try enc.encode($0), as: UTF8.self) }
            .joined(separator: "\n") + "\n"
        try Data(rewritten.utf8).write(to: path)

        // The bare chain is internally consistent — the rewrite is invisible…
        #expect(AuditLog.verifyDetailed(dir: dir).failure == nil)
        // …but the signatures no longer match the rewritten hashes.
        let failure = AuditLog.verifyDetailed(dir: dir, signerPublicKeyX963: signer.publicKeyX963).failure
        #expect(failure == .badSignature(seq: 2))
    }

    @Test("splicing unsigned rows into the middle, then a signed head on top, is CAUGHT (#4)")
    func splicedMiddleIsCaught() throws {
        let dir = try freshDir()
        let signer = SoftwareAuditSigner()
        let recipient = newRecipient()
        let log = try AuditLog(dir: dir, recipientX963: recipient, signer: signer)
        for i in 1...3 { try log.append(row("http.request", target: "h\(i)")) }
        try log.close()

        // Attacker splices two UNSIGNED but correctly hash-linked rows after the
        // signed head (the public recipient lets them seal payloads + chain).
        let path = dir.appendingPathComponent(AuditLog.fileName)
        var rows = try String(contentsOf: path, encoding: .utf8)
            .split(separator: "\n").map { try JSONDecoder().decode(SealedAuditRow.self, from: Data($0.utf8)) }
        var prev = rows.last!.thisHash
        for k in 4...5 {
            let sealed = (try ECIES.seal(Data("{\"x\":\(k)}".utf8),
                                         to: P256.KeyAgreement.PublicKey(x963Representation: recipient))).base64EncodedString()
            let h = AuditLog.chainHash(prev: prev, seq: Int64(k), sealed: sealed)
            rows.append(SealedAuditRow(seq: Int64(k), sealed: sealed, prevHash: prev, thisHash: h, sig: ""))
            prev = h
        }
        let enc = JSONEncoder()
        try Data((rows.map { String(decoding: try enc.encode($0), as: UTF8.self) }.joined(separator: "\n") + "\n").utf8).write(to: path)

        // Now a "locked deny" appends a LEGITIMATELY signed row on top.
        let reopened = try AuditLog(dir: dir, recipientX963: recipient, signer: signer)
        try reopened.append(row("http.request", target: "denied"))
        try reopened.close()

        // The head is validly signed, but the whole-journal sweep catches the
        // unsigned spliced rows.
        #expect(AuditLog.verifyDetailed(dir: dir, signerPublicKeyX963: signer.publicKeyX963).failure == .unsigned(seq: 4))
    }

    @Test("an unsigned journal fails verification the moment a signer key is required")
    func unsignedJournalFlagged() throws {
        let dir = try freshDir()
        let log = try AuditLog(dir: dir, recipientX963: newRecipient())   // no signer
        try log.append(row("http.request"))
        try log.close()
        let signer = SoftwareAuditSigner()
        #expect(AuditLog.verifyDetailed(dir: dir).failure == nil)
        #expect(AuditLog.verifyDetailed(dir: dir, signerPublicKeyX963: signer.publicKeyX963).failure
                == .unsigned(seq: 1))
    }

    @Test("a signer failure fails the append CLOSED — no row, chain state intact")
    func signFailureIsFailClosed() throws {
        struct BrokenSigner: AuditSigner {
            let backend = "test"
            var publicKeyX963: Data { Data() }
            func sign(_ message: Data) throws -> Data { throw AuditSignerError.unavailable("nope") }
        }
        let dir = try freshDir()
        let log = try AuditLog(dir: dir, recipientX963: newRecipient(), signer: BrokenSigner())
        #expect(throws: (any Error).self) { try log.append(row("http.request")) }
        #expect(log._chainStateForTesting.seq == 0, "a failed sign must not advance the chain")
        try log.close()
        #expect(AuditLog.verifyDetailed(dir: dir).count == 0)
    }
}

@Suite("Audit — the freshness anchor (rollback resistance)")
struct AuditAnchorTests {

    /// A journal of `n` signed rows + an anchor minted at the current head.
    private func world(_ n: Int, generation: Int64 = 5, stateDigest: String = "")
        throws -> (dir: URL, signer: SoftwareAuditSigner, anchor: AnchorState) {
        let dir = try freshDir()
        let signer = SoftwareAuditSigner()
        let log = try AuditLog(dir: dir, recipientX963: newRecipient(), signer: signer)
        for i in 1...n { try log.append(row("http.request", target: "h\(i)")) }
        try log.close()
        let anchor = try IntegrityCheck.mintAnchor(previous: nil, signer: signer,
                                                   auditDir: dir, dbGeneration: generation,
                                                   stateDigest: stateDigest)
        return (dir, signer, anchor)
    }

    @Test("a clean world verifies with no issues; the anchor counter is monotonic")
    func cleanWorld() throws {
        let (dir, signer, anchor) = try world(3)
        let issues = IntegrityCheck.run(anchor: anchor, anchorExpected: true,
                                        signerPub: signer.publicKeyX963,
                                        currentSignerPub: signer.publicKeyX963,
                                        auditDir: dir, dbGeneration: 5,
                                        currentStateDigest: "")
        #expect(issues.isEmpty)
        let next = try IntegrityCheck.mintAnchor(previous: anchor, signer: signer,
                                                 auditDir: dir, dbGeneration: 6, stateDigest: "")
        #expect(next.counter == anchor.counter + 1)
    }

    @Test("a partial content rollback (same generation, older sealed state) is caught by the digest (#1)")
    func partialRollbackCaughtByDigest() throws {
        // The anchor was minted when the content digest was "state-A".
        let (dir, signer, anchor) = try world(2, generation: 5, stateDigest: "state-A")
        // Nothing else moved — same generation, same journal head, valid signature —
        // but a sealed row was rolled back, so the recomputed digest differs.
        let issues = IntegrityCheck.run(anchor: anchor, anchorExpected: true,
                                        signerPub: signer.publicKeyX963,
                                        currentSignerPub: signer.publicKeyX963,
                                        auditDir: dir, dbGeneration: 5,
                                        currentStateDigest: "state-B")
        #expect(issues.map(\.code) == ["state-rolled-back"])
        // The same digest passes clean.
        let clean = IntegrityCheck.run(anchor: anchor, anchorExpected: true,
                                       signerPub: signer.publicKeyX963,
                                       currentSignerPub: signer.publicKeyX963,
                                       auditDir: dir, dbGeneration: 5,
                                       currentStateDigest: "state-A")
        #expect(clean.isEmpty)
    }

    @Test("truncating the journal below the anchored head is detected")
    func truncationDetected() throws {
        let (dir, signer, anchor) = try world(4)
        // Cut the last two rows — an attacker hiding recent activity.
        let path = dir.appendingPathComponent(AuditLog.fileName)
        let lines = try String(contentsOf: path, encoding: .utf8).split(separator: "\n")
        try Data((lines.prefix(2).joined(separator: "\n") + "\n").utf8).write(to: path)

        let issues = IntegrityCheck.run(anchor: anchor, anchorExpected: true,
                                        signerPub: signer.publicKeyX963,
                                        currentSignerPub: signer.publicKeyX963,
                                        auditDir: dir, dbGeneration: 5,
                                        currentStateDigest: "")
        #expect(issues.map(\.code).contains("audit-rolled-back"))
    }

    @Test("a vault generation older than anchored is detected (#12)")
    func dbRollbackDetected() throws {
        let (dir, signer, anchor) = try world(2, generation: 9)
        let issues = IntegrityCheck.run(anchor: anchor, anchorExpected: true,
                                        signerPub: signer.publicKeyX963,
                                        currentSignerPub: signer.publicKeyX963,
                                        auditDir: dir, dbGeneration: 3,   // restored old vault.db
                                        currentStateDigest: "")
        #expect(issues.map(\.code).contains("vault-rolled-back"))
    }

    @Test("an anchor signed by a foreign key proves nothing — flagged as forged")
    func forgedAnchorDetected() throws {
        let (dir, signer, _) = try world(2)
        let attacker = SoftwareAuditSigner()
        let forged = try IntegrityCheck.mintAnchor(previous: nil, signer: attacker,
                                                   auditDir: dir, dbGeneration: 99, stateDigest: "")
        let issues = IntegrityCheck.run(anchor: forged, anchorExpected: true,
                                        signerPub: signer.publicKeyX963,
                                        currentSignerPub: signer.publicKeyX963,
                                        auditDir: dir, dbGeneration: 5,
                                        currentStateDigest: "")
        #expect(issues.map(\.code) == ["anchor-forged"])
    }

    @Test("missing anchor: alarmed when expected, silent when arming a fresh vault")
    func missingAnchor() throws {
        let (dir, signer, _) = try world(1)
        let expected = IntegrityCheck.run(anchor: nil, anchorExpected: true,
                                          signerPub: signer.publicKeyX963,
                                          currentSignerPub: signer.publicKeyX963,
                                          auditDir: dir, dbGeneration: 0,
                                          currentStateDigest: "")
        #expect(expected.map(\.code) == ["anchor-missing"])
        let fresh = IntegrityCheck.run(anchor: nil, anchorExpected: false,
                                       signerPub: signer.publicKeyX963,
                                       currentSignerPub: signer.publicKeyX963,
                                       auditDir: dir, dbGeneration: 0,
                                       currentStateDigest: "")
        #expect(fresh.isEmpty)
    }

    @Test("a changed signing key is flagged, and a head signed by a foreign key is untrusted")
    func signerChangeAndUntrustedHead() throws {
        let (dir, signer, anchor) = try world(2)
        let newSigner = SoftwareAuditSigner()
        let issues = IntegrityCheck.run(anchor: anchor, anchorExpected: true,
                                        signerPub: signer.publicKeyX963,
                                        currentSignerPub: newSigner.publicKeyX963,
                                        auditDir: dir, dbGeneration: 5,
                                        currentStateDigest: "")
        #expect(issues.map(\.code).contains("signer-changed"))

        // A journal whose head the adopted key never signed (e.g. fabricated
        // wholesale with a foreign keypair) is untrusted even with a chain +
        // matching structure.
        let foreign = IntegrityCheck.run(anchor: try IntegrityCheck.mintAnchor(
                                            previous: nil, signer: newSigner,
                                            auditDir: dir, dbGeneration: 5, stateDigest: ""),
                                         anchorExpected: true,
                                         signerPub: newSigner.publicKeyX963,
                                         currentSignerPub: newSigner.publicKeyX963,
                                         auditDir: dir, dbGeneration: 5,
                                         currentStateDigest: "")
        #expect(foreign.map(\.code).contains("audit-untrusted"))
    }

    @Test("replaying an OLD anchor+journal pair is rejected by the sealed counter floor")
    func anchorReplayDetected() throws {
        // Day 1: the attacker snapshots anchor (counter 3) + journal.
        let (dir, signer, _) = try world(2)
        var old = try IntegrityCheck.mintAnchor(previous: nil, signer: signer,
                                                auditDir: dir, dbGeneration: 5, stateDigest: "")
        old.counter = 3
        old.sig = try signer.sign(old.signedPayload).base64EncodedString()

        // Day 30: the vault has since sealed floor 9. The restored pair is
        // internally consistent — signature valid, head present, generation
        // fine — and STILL rejected, because the anchor itself is old.
        let issues = IntegrityCheck.run(anchor: old, anchorExpected: true,
                                        signerPub: signer.publicKeyX963,
                                        currentSignerPub: signer.publicKeyX963,
                                        auditDir: dir, dbGeneration: 5,
                                        currentStateDigest: "",
                                        anchorCounterFloor: 9)
        #expect(issues.map(\.code).contains("anchor-rolled-back"))

        // With no floor recorded yet (fresh arming), the same anchor passes.
        let fresh = IntegrityCheck.run(anchor: old, anchorExpected: true,
                                       signerPub: signer.publicKeyX963,
                                       currentSignerPub: signer.publicKeyX963,
                                       auditDir: dir, dbGeneration: 5,
                                       currentStateDigest: "",
                                       anchorCounterFloor: 0)
        #expect(!fresh.map(\.code).contains("anchor-rolled-back"))
    }

    @Test("the file anchor store round-trips and resets")
    func anchorStoreRoundTrip() throws {
        let dir = try freshDir()
        let store = FileAnchorStore(url: dir.appendingPathComponent("anchor.json"))
        #expect(try store.load() == nil)
        let signer = SoftwareAuditSigner()
        let a = try IntegrityCheck.mintAnchor(previous: nil, signer: signer,
                                              auditDir: dir, dbGeneration: 1, stateDigest: "")
        try store.save(a)
        #expect(try store.load() == a)
        try store.reset()
        #expect(try store.load() == nil)
    }
}

@Suite("Session journal — durable lifecycle + crash reconciliation (#23)")
struct SessionJournalTests {

    private func activity(_ key: String, name: String = "claude") -> AuditEvent {
        var e = row("http.request", session: key)
        e.origin = AuditEvent.Origin(name: name, pid: 42)
        return e
    }

    @Test("a clean lock closes every session — no orphans at the next unlock")
    func cleanLockNoOrphans() {
        let events = [
            SessionJournal.boundaryEvent(locked: false),
            activity("42:100"),
            SessionJournal.endedEvent(SessionInfo(key: "42:100", pid: 42, name: "claude",
                                                  status: .approved, calls: 3, approvedAt: Date())),
            SessionJournal.boundaryEvent(locked: true),
        ]
        #expect(SessionJournal.orphans(in: events).isEmpty)
    }

    @Test("a crash with live sessions leaves exactly those sessions as orphans")
    func crashLeavesOrphans() {
        let events = [
            SessionJournal.boundaryEvent(locked: false),
            activity("42:100"),
            activity("77:200", name: "cursor"),
            SessionJournal.endedEvent(SessionInfo(key: "77:200", pid: 77, name: "cursor",
                                                  status: .approved, approvedAt: Date())),
            // no vault.locked row — the app died here
        ]
        let orphans = SessionJournal.orphans(in: events)
        #expect(orphans.map(\.key) == ["42:100"])
        #expect(orphans.first?.name == "claude")
    }

    @Test("a revoked session is closed; orphan rows themselves close the loop across restarts")
    func revokeAndOrphanRowsClose() {
        var events = [
            SessionJournal.boundaryEvent(locked: false),
            activity("42:100"),
            SessionJournal.revokedEvent(key: "42:100"),
        ]
        #expect(SessionJournal.orphans(in: events).isEmpty)

        // Crash → next unlock writes the orphan row + boundary; a THIRD run
        // must not re-orphan the same session.
        events = [
            activity("9:9"),
            SessionJournal.orphanedEvent(key: "9:9", identity: "agent://t", name: "claude"),
            SessionJournal.boundaryEvent(locked: false),
        ]
        #expect(SessionJournal.orphans(in: events).isEmpty)
    }

    @Test("locked-vault deny rows carry no session and never orphan")
    func denyRowsDoNotOrphan() {
        let events = [row("http.request")]   // session == ""
        #expect(SessionJournal.orphans(in: events).isEmpty)
    }
}


@Suite("Agent allowlist — persistence + matching")
struct AllowlistPersistenceTests {
    @Test("entries survive a JSON round-trip (the sealed-blob format)")
    func roundTrip() throws {
        let list = [
            AllowlistEntry(id: "a", label: "Claude", kind: .cdhash, cdhashes: ["ab12", "cd34"],
                           teamID: "T", bundleID: "com.x", capturedFrom: "live:pid 1", scopeHosts: ["api.x.com"]),
            AllowlistEntry(id: "b", label: "Cursor", kind: .publisher,
                           requirement: "anchor apple generic", teamID: "U", bundleID: "com.y"),
        ]
        let data = try JSONEncoder().encode(list)
        let back = try JSONDecoder().decode([AllowlistEntry].self, from: data)
        #expect(back == list)
    }

    @Test("the sealed allowlist blob round-trips through the vault store")
    func blobRoundTrip() async throws {
        let dir = try freshDir()
        let store = try VaultStore(creatingAt: dir.appendingPathComponent("v.db"), keystore: FileAgeKeystore())
        let list = [AllowlistEntry(id: "a", label: "Claude", kind: .cdhash, cdhashes: ["ff"])]
        try await store.setBlob(key: VaultStore.allowlistBlobKey, data: JSONEncoder().encode(list))
        let raw = try #require(try await store.blob(key: VaultStore.allowlistBlobKey))
        #expect(try JSONDecoder().decode([AllowlistEntry].self, from: raw) == list)
        // Sealed at rest: the label/hash never appear in the raw DB file.
        let onDisk = try Data(contentsOf: dir.appendingPathComponent("v.db"))
        #expect(onDisk.range(of: Data("Claude".utf8)) == nil)
        await store.close()
    }

    @Test("an unusable entry (empty matcher) is dropped on hydrate")
    func unusableDropped() {
        let allow = Allowlist(matcher: { _, _, c in c.first })
        allow.hydrate([
            AllowlistEntry(id: "ok", label: "x", kind: .cdhash, cdhashes: ["h"]),
            AllowlistEntry(id: "bad", label: "y", kind: .cdhash, cdhashes: []),          // no hash
            AllowlistEntry(id: "bad2", label: "z", kind: .publisher, requirement: ""),    // no requirement
        ])
        #expect(allow.list().map(\.id) == ["ok"])
    }

    @Test("match threads the process start time to the matcher — a recycled pid won't match (#4)")
    func matchBindsToProcessInstance() {
        let entry = AllowlistEntry(id: "e", label: "x", kind: .cdhash, cdhashes: ["h"])
        // Models the real Provenance matcher's instance pin: trust only the
        // process that started at 999; a reused pid (different start time) fails.
        let allow = Allowlist(matcher: { _, startedAt, cands in startedAt == 999 ? cands.first : nil })
        allow.hydrate([entry])
        #expect(allow.match(pid: 5, startedAt: 999, targetHost: "any")?.id == "e")
        #expect(allow.match(pid: 5, startedAt: 111, targetHost: "any") == nil,
                "a recycled pid (different kernel start time) must never inherit the identity")
    }

    @Test("the live matcher fails closed when the process start time is unknown (#4)")
    func matchAllowlistFailsClosedWithoutStartTime() {
        let e = AllowlistEntry(id: "x", label: "x", kind: .cdhash, cdhashes: ["deadbeef"])
        // A real, alive pid — but startedAt == 0 (unknown) must never match: we
        // can't prove it's the same instance, so we fall through to the ceremony.
        #expect(Provenance.matchAllowlist(pid: Int(getpid()), startedAt: 0, entries: [e]) == nil)
    }
}
