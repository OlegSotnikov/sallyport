import Foundation
import CryptoKit
import Darwin
import SallyportKit

/// Encrypted, hash-chained JSONL audit journal. Rows can be appended with the
/// public recipient key while locked and decrypted only after unlock.

// MARK: - Event

/// One audit event. Coding-key values are part of the sealed format.
public struct AuditEvent: Codable, Sendable, Equatable {

    /// Kernel-captured calling process. Omitted for internal events.
    public struct Origin: Codable, Sendable, Equatable {
        public var name: String
        public var path: String
        public var app: String
        public var pid: Int
        public var signed: Bool
        public var signedBy: String
        public var chain: String            // "Claude → login → sp"

        public init(name: String = "", path: String = "", app: String = "",
                    pid: Int = 0, signed: Bool = false, signedBy: String = "",
                    chain: String = "") {
            self.name = name; self.path = path; self.app = app; self.pid = pid
            self.signed = signed; self.signedBy = signedBy; self.chain = chain
        }

        enum CodingKeys: String, CodingKey {
            case name, path, app, pid, signed, signedBy, chain
        }

        /// Canonical form writes with omitempty semantics; decode tolerantly.
        public init(from decoder: any Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            name = try c.decodeIfPresent(String.self, forKey: .name) ?? ""
            path = try c.decodeIfPresent(String.self, forKey: .path) ?? ""
            app = try c.decodeIfPresent(String.self, forKey: .app) ?? ""
            pid = try c.decodeIfPresent(Int.self, forKey: .pid) ?? 0
            signed = try c.decodeIfPresent(Bool.self, forKey: .signed) ?? false
            signedBy = try c.decodeIfPresent(String.self, forKey: .signedBy) ?? ""
            chain = try c.decodeIfPresent(String.self, forKey: .chain) ?? ""
        }

        /// Canonical form with omitempty semantics: zero-valued fields are
        /// dropped, so the sealed payload is deterministic.
        var canonicalValue: CanonicalJSON.Value {
            var obj: [String: CanonicalJSON.Value] = [:]
            if !name.isEmpty { obj["name"] = .string(name) }
            if !path.isEmpty { obj["path"] = .string(path) }
            if !app.isEmpty { obj["app"] = .string(app) }
            if pid != 0 { obj["pid"] = .int(pid) }
            if signed { obj["signed"] = .bool(true) }
            if !signedBy.isEmpty { obj["signedBy"] = .string(signedBy) }
            if !chain.isEmpty { obj["chain"] = .string(chain) }
            return .object(obj)
        }
    }

    /// Chain position filled by `AuditLog.append`.
    public var seq: Int64
    public var ts: String                   // RFC 3339 UTC; filled by append if empty
    public var prevHash: String
    public var identity: String             // asserted caller, e.g. "agent://mac.cli"
    public var session: String
    public var channel: String              // "http" | "ssh" | "mcp"
    public var tool: String                 // "http.request" | "ssh.exec" | …
    public var target: String               // host / destination, never a full URL with query secrets
    public var argsPreview: String          // Short redacted preview, never raw arguments.
    public var decision: String             // allow | deny | ask
    public var rule: String
    public var policyHash: String
    public var grantId: String
    public var isError: Bool
    public var bytesOut: Int
    public var durationMs: Int64
    public var dlpRedactions: Int
    public var recording: String
    /// SHA-256 fingerprint of the SSH host key, or empty for other events.
    public var hostKeyFp: String
    public var origin: Origin?
    public var thisHash: String

    public init(identity: String = "", session: String = "", channel: String = "",
                tool: String = "", target: String = "", argsPreview: String = "",
                decision: String = "", rule: String = "", policyHash: String = "",
                grantId: String = "", isError: Bool = false, bytesOut: Int = 0,
                durationMs: Int64 = 0, dlpRedactions: Int = 0, recording: String = "",
                hostKeyFp: String = "", origin: Origin? = nil, ts: String = "") {
        self.seq = 0; self.ts = ts; self.prevHash = ""; self.thisHash = ""
        self.identity = identity; self.session = session; self.channel = channel
        self.tool = tool; self.target = target; self.argsPreview = argsPreview
        self.decision = decision; self.rule = rule; self.policyHash = policyHash
        self.grantId = grantId; self.isError = isError; self.bytesOut = bytesOut
        self.durationMs = durationMs; self.dlpRedactions = dlpRedactions
        self.recording = recording; self.hostKeyFp = hostKeyFp; self.origin = origin
    }

    enum CodingKeys: String, CodingKey {
        case seq, ts, identity, session, channel, tool, target, decision, rule
        case recording, origin
        case prevHash = "prev_hash"
        case argsPreview = "args_preview"
        case policyHash = "policy_hash"
        case grantId = "grant_id"
        case isError = "is_error"
        case bytesOut = "bytes_out"
        case durationMs = "duration_ms"
        case dlpRedactions = "dlp_redactions"
        case hostKeyFp = "host_key_fp"
        case thisHash = "this_hash"
    }

    /// Decode with zero-value defaults, so a sealed payload round-trips into the
    /// identical struct.
    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        seq = try c.decodeIfPresent(Int64.self, forKey: .seq) ?? 0
        ts = try c.decodeIfPresent(String.self, forKey: .ts) ?? ""
        prevHash = try c.decodeIfPresent(String.self, forKey: .prevHash) ?? ""
        identity = try c.decodeIfPresent(String.self, forKey: .identity) ?? ""
        session = try c.decodeIfPresent(String.self, forKey: .session) ?? ""
        channel = try c.decodeIfPresent(String.self, forKey: .channel) ?? ""
        tool = try c.decodeIfPresent(String.self, forKey: .tool) ?? ""
        target = try c.decodeIfPresent(String.self, forKey: .target) ?? ""
        argsPreview = try c.decodeIfPresent(String.self, forKey: .argsPreview) ?? ""
        decision = try c.decodeIfPresent(String.self, forKey: .decision) ?? ""
        rule = try c.decodeIfPresent(String.self, forKey: .rule) ?? ""
        policyHash = try c.decodeIfPresent(String.self, forKey: .policyHash) ?? ""
        grantId = try c.decodeIfPresent(String.self, forKey: .grantId) ?? ""
        isError = try c.decodeIfPresent(Bool.self, forKey: .isError) ?? false
        bytesOut = try c.decodeIfPresent(Int.self, forKey: .bytesOut) ?? 0
        durationMs = try c.decodeIfPresent(Int64.self, forKey: .durationMs) ?? 0
        dlpRedactions = try c.decodeIfPresent(Int.self, forKey: .dlpRedactions) ?? 0
        recording = try c.decodeIfPresent(String.self, forKey: .recording) ?? ""
        hostKeyFp = try c.decodeIfPresent(String.self, forKey: .hostKeyFp) ?? ""
        origin = try c.decodeIfPresent(Origin.self, forKey: .origin)
        thisHash = try c.decodeIfPresent(String.self, forKey: .thisHash) ?? ""
    }

    /// Canonical sealed payload without outer chain fields.
    var canonicalValue: CanonicalJSON.Value {
        var obj: [String: CanonicalJSON.Value] = [
            "seq": .int(Int(seq)),
            "ts": .string(ts),
            "identity": .string(identity),
            "session": .string(session),
            "channel": .string(channel),
            "tool": .string(tool),
            "target": .string(target),
            "args_preview": .string(argsPreview),
            "decision": .string(decision),
            "rule": .string(rule),
            "policy_hash": .string(policyHash),
            "grant_id": .string(grantId),
            "is_error": .bool(isError),
            "bytes_out": .int(bytesOut),
            "duration_ms": .int(Int(durationMs)),
            "dlp_redactions": .int(dlpRedactions),
            "recording": .string(recording),
        ]
        // Omit an empty host fingerprint to preserve existing canonical rows.
        if !hostKeyFp.isEmpty { obj["host_key_fp"] = .string(hostKeyFp) }
        if let origin { obj["origin"] = origin.canonicalValue }
        return .object(obj)
    }

    /// Canonical payload string for tests.
    var canonicalString: String { CanonicalJSON.string(canonicalValue) }
}

// MARK: - Errors

/// Audit failures. The engine denies an action when its audit row cannot be appended.
public enum AuditError: Error, Sendable, CustomStringConvertible, Equatable {
    case io(String)
    case corruptRow(row: Int, detail: String)
    case seqGap(row: Int64, got: Int64)
    case brokenLink(seq: Int64)
    case tampered(seq: Int64)
    /// A sealed row could not be decrypted.
    case unreadable(seq: Int64)
    /// Signature enforcement was requested and a row carries none.
    case unsigned(seq: Int64)
    /// A row's signature does not verify with the vault's audit signer.
    case badSignature(seq: Int64)
    /// The adopted signer public key is unavailable.
    case signerUnavailable

    public var description: String {
        switch self {
        case .io(let m): return m
        case .corruptRow(let row, let detail): return "audit: row \(row) not valid JSON: \(detail)"
        case .seqGap(let row, let got): return "audit: seq gap at row \(row): got \(got)"
        case .brokenLink(let seq): return "audit: broken link at seq \(seq): prev_hash mismatch"
        case .tampered(let seq): return "audit: tamper detected at seq \(seq): this_hash mismatch"
        case .unreadable(let seq): return "audit: row \(seq) does not decrypt with this vault's audit identity"
        case .unsigned(let seq): return "audit: row \(seq) is unsigned"
        case .badSignature(let seq): return "audit: row \(seq) was not signed by this vault's audit signer"
        case .signerUnavailable: return "audit: signer key unavailable; rows cannot be verified"
        }
    }
}

// MARK: - Sealed row

/// The on-disk row shape. Everything an offline observer sees: a sequence
/// number, an opaque ciphertext, and the chain hashes over that ciphertext.
struct SealedAuditRow: Codable {
    var seq: Int64
    var sealed: String        // base64 ECIES blob of the canonical event JSON
    var prevHash: String
    var thisHash: String
    /// Base64 DER ECDSA signature over `thisHash`, or empty without a signer.
    var sig: String

    enum CodingKeys: String, CodingKey {
        case seq, sealed, sig
        case prevHash = "prev_hash"
        case thisHash = "this_hash"
    }

    init(seq: Int64, sealed: String, prevHash: String, thisHash: String, sig: String = "") {
        self.seq = seq; self.sealed = sealed
        self.prevHash = prevHash; self.thisHash = thisHash; self.sig = sig
    }

    init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        seq = try c.decode(Int64.self, forKey: .seq)
        sealed = try c.decode(String.self, forKey: .sealed)
        prevHash = try c.decode(String.self, forKey: .prevHash)
        thisHash = try c.decode(String.self, forKey: .thisHash)
        sig = try c.decodeIfPresent(String.self, forKey: .sig) ?? ""
    }
}

// MARK: - Log

/// An append-only encrypted audit log rooted at a directory
/// (`audit-000001.jsonl`; single numbered file, no rotation).
///
/// Thread-safe: all mutable chain state (file handle position, seq, prev) is
/// guarded by `lock`, hence `@unchecked Sendable`.
public final class AuditLog: @unchecked Sendable {

    /// The `prev_hash` of the first row in a chain.
    public static let genesisPrev = String(repeating: "0", count: 64)

    static let fileName = "audit-000001.jsonl"

    /// One row contains a bounded, redacted event. Refusing larger rows keeps a
    /// oversized journal from exhausting memory during verification or unlock.
    static let maximumRowBytes = 1 * 1024 * 1024
    private static let readChunkBytes = 64 * 1024

    /// The feed is a recent-history view, not an unbounded in-memory export.
    /// `read` still authenticates and decrypts the complete journal before it
    /// returns this tail, so old-row tampering cannot hide behind retention.
    public static let defaultReadRetention = 10_000
    public static let defaultReadRetentionBytes = 32 * 1024 * 1024

    private static func incremented(_ value: Int, context: String) throws -> Int {
        let (next, overflow) = value.addingReportingOverflow(1)
        guard !overflow else { throw AuditError.io("audit: \(context) overflow") }
        return next
    }

    private struct OpenJournal {
        let fd: Int32
        let size: off_t
    }

    /// Fixed-snapshot JSONL reader. Total journal size is irrelevant to memory
    /// use: at most one bounded row and one fixed read chunk are resident.
    private struct JournalLineReader {
        let fd: Int32
        let fileSize: off_t
        var fileOffset: off_t = 0
        var chunk = [UInt8](repeating: 0, count: AuditLog.readChunkBytes)
        var chunkOffset = 0
        var chunkCount = 0

        mutating func nextLine(rowNumber: Int) throws -> Data? {
            var line = Data()
            while true {
                if chunkOffset == chunkCount {
                    guard fileOffset < fileSize else {
                        guard line.isEmpty else {
                            throw AuditError.corruptRow(
                                row: rowNumber,
                                detail: "unterminated final row")
                        }
                        return nil
                    }

                    let (remaining, remainingUnderflow) = fileSize.subtractingReportingOverflow(fileOffset)
                    guard !remainingUnderflow, remaining > 0 else {
                        throw AuditError.io("audit: journal size underflow")
                    }
                    guard let remainingBytes = Int(exactly: remaining) else {
                        throw AuditError.io("audit: journal size is not representable")
                    }
                    let wanted = min(chunk.count, remainingBytes)
                    let n = chunk.withUnsafeMutableBytes { raw in
                        Darwin.pread(fd, raw.baseAddress, wanted, fileOffset)
                    }
                    if n < 0 {
                        if errno == EINTR { continue }
                        throw AuditError.io("audit: read: \(String(cString: strerror(errno)))")
                    }
                    guard n > 0 else {
                        throw AuditError.io("audit: journal changed while being read")
                    }
                    let (nextOffset, offsetOverflow) = fileOffset.addingReportingOverflow(off_t(n))
                    guard !offsetOverflow, nextOffset <= fileSize else {
                        throw AuditError.io("audit: journal offset overflow")
                    }
                    fileOffset = nextOffset
                    chunkOffset = 0
                    chunkCount = n
                }

                let available = chunk[chunkOffset..<chunkCount]
                if let newline = available.firstIndex(of: 0x0A) {
                    let (segmentCount, segmentUnderflow) = newline.subtractingReportingOverflow(chunkOffset)
                    let (rowCapacity, capacityUnderflow) = AuditLog.maximumRowBytes
                        .subtractingReportingOverflow(line.count)
                    guard !segmentUnderflow, !capacityUnderflow, segmentCount <= rowCapacity else {
                        throw AuditError.corruptRow(
                            row: rowNumber,
                            detail: "row exceeds \(AuditLog.maximumRowBytes) bytes")
                    }
                    line.append(contentsOf: chunk[chunkOffset..<newline])
                    let (nextChunkOffset, chunkOverflow) = newline.addingReportingOverflow(1)
                    guard !chunkOverflow, nextChunkOffset <= chunkCount else {
                        throw AuditError.io("audit: read buffer offset overflow")
                    }
                    chunkOffset = nextChunkOffset
                    guard !line.isEmpty else {
                        throw AuditError.corruptRow(row: rowNumber, detail: "empty row")
                    }
                    return line
                }

                let (segmentCount, segmentUnderflow) = chunkCount.subtractingReportingOverflow(chunkOffset)
                let (rowCapacity, capacityUnderflow) = AuditLog.maximumRowBytes
                    .subtractingReportingOverflow(line.count)
                guard !segmentUnderflow, !capacityUnderflow, segmentCount <= rowCapacity else {
                    throw AuditError.corruptRow(
                        row: rowNumber,
                        detail: "row exceeds \(AuditLog.maximumRowBytes) bytes")
                }
                line.append(contentsOf: chunk[chunkOffset..<chunkCount])
                chunkOffset = chunkCount
            }
        }
    }

    /// Amortized-O(1) tail buffer bounded by event count and estimated decoded
    /// memory. Count alone is insufficient when an individual valid row may be
    /// large. Periodic compaction prevents evicted entries retaining storage.
    private struct EventTail {
        struct Entry {
            let event: AuditEvent
            let byteCost: Int
        }

        let capacity: Int
        let byteCapacity: Int
        var storage: [Entry] = []
        var head = 0
        var retainedBytes = 0

        mutating func append(_ event: AuditEvent, byteCost: Int) throws {
            guard capacity > 0, byteCapacity > 0,
                  byteCost >= 0, byteCost <= byteCapacity else { return }
            let (availableBytes, capacityUnderflow) = byteCapacity.subtractingReportingOverflow(byteCost)
            guard !capacityUnderflow else {
                throw AuditError.io("audit: retention byte capacity underflow")
            }
            while head < storage.count {
                let (retainedCount, countUnderflow) = storage.count.subtractingReportingOverflow(head)
                guard !countUnderflow else {
                    throw AuditError.io("audit: retention count underflow")
                }
                guard retainedCount >= capacity || retainedBytes > availableBytes else { break }

                let (nextBytes, byteUnderflow) = retainedBytes.subtractingReportingOverflow(
                    storage[head].byteCost)
                let (nextHead, headOverflow) = head.addingReportingOverflow(1)
                guard !byteUnderflow, !headOverflow, nextHead <= storage.count else {
                    throw AuditError.io("audit: retention accounting overflow")
                }
                retainedBytes = nextBytes
                head = nextHead
            }
            storage.append(Entry(event: event, byteCost: byteCost))
            let (nextBytes, byteOverflow) = retainedBytes.addingReportingOverflow(byteCost)
            guard !byteOverflow, nextBytes <= byteCapacity else {
                storage.removeLast()
                throw AuditError.io("audit: retention byte accounting overflow")
            }
            retainedBytes = nextBytes

            if head >= 1_024, head >= storage.count / 2 {
                storage.removeFirst(head)
                head = 0
            }
        }

        var ordered: [AuditEvent] {
            storage[head...].map(\.event)
        }
    }

    private let lock = NSLock()
    private let handle: FileHandle
    private let recipient: P256.KeyAgreement.PublicKey
    /// Recipient key captured when the writer opens. The integrity gate compares
    /// it with the vault-sealed identity.
    public var recipientX963: Data { recipient.x963Representation }
    /// When present, signs every row. A signing failure prevents the append.
    private let signer: (any AuditSigner)?
    private var closed = false
    private var seq: Int64
    private var prev: String
    /// Exact byte length of the durably committed prefix represented by
    /// `seq`/`prev`. An external truncate/growth invalidates that state.
    private var committedSize: off_t
    /// Durability barrier override for tests.
    /// Nil means fsync(2) on the log fd.
    private var syncOverride: (@Sendable () throws -> Void)?

    /// Opens (or creates) the audit log in `dir`, reading any existing chain to
    /// recover the last sequence number and hash so appends continue the chain.
    /// `recipientX963` is the audit recipient public key.
    public init(dir: URL, recipientX963: Data, signer: (any AuditSigner)? = nil) throws {
        do {
            self.recipient = try P256.KeyAgreement.PublicKey(x963Representation: recipientX963)
        } catch {
            throw AuditError.io("audit: recipient is not a P-256 public key")
        }
        self.signer = signer
        let opened: OpenJournal
        do {
            guard let journal = try Self.openJournal(dir: dir, forWriting: true) else {
                throw AuditError.io("audit: could not create journal")
            }
            opened = journal
        } catch {
            throw error
        }
        do {
            (self.seq, self.prev) = try Self.recover(fd: opened.fd, fileSize: opened.size)
            let afterRecovery = try Self.validateJournalFD(
                opened.fd, repairPermissions: false)
            guard afterRecovery.st_size == opened.size else {
                throw AuditError.io("audit: journal changed during recovery")
            }
            self.committedSize = opened.size
        } catch {
            Darwin.close(opened.fd)
            throw error
        }
        self.handle = FileHandle(fileDescriptor: opened.fd, closeOnDealloc: true)
    }

    /// Reads the last sequence number and hash from an existing file.
    private static func recover(fd: Int32, fileSize: off_t) throws -> (seq: Int64, prev: String) {
        let decoder = JSONDecoder()
        var seq: Int64 = 0
        var prev = genesisPrev
        var row = 0
        var reader = JournalLineReader(fd: fd, fileSize: fileSize)
        while true {
            let rowNumber = try incremented(row, context: "row number")
            guard let line = try reader.nextLine(rowNumber: rowNumber) else { break }
            row = rowNumber
            do {
                let r = try decoder.decode(SealedAuditRow.self, from: line)
                let (expectedSeq, sequenceOverflow) = seq.addingReportingOverflow(1)
                guard !sequenceOverflow else {
                    throw AuditError.io("audit: sequence overflow during recovery")
                }
                guard r.seq == expectedSeq else {
                    throw AuditError.seqGap(row: expectedSeq, got: r.seq)
                }
                guard r.prevHash == prev else {
                    throw AuditError.brokenLink(seq: r.seq)
                }
                guard chainHash(prev: prev, seq: r.seq, sealed: r.sealed) == r.thisHash else {
                    throw AuditError.tampered(seq: r.seq)
                }
                seq = expectedSeq
                prev = r.thisHash
            } catch let error as AuditError {
                throw error
            } catch {
                throw AuditError.corruptRow(row: row, detail: String(describing: error))
            }
        }
        return (seq, prev)
    }

    /// Seals and writes an event, filling seq/ts and the outer chain hashes, and
    /// returns the completed event. A write or fsync error restores the last
    /// committed chain head and is rethrown.
    @discardableResult
    public func append(_ event: AuditEvent) throws -> AuditEvent {
        lock.lock()
        defer { lock.unlock() }
        // Check before touching FileHandle because a closed handle can raise an
        // Objective-C exception instead of throwing.
        if closed {
            throw AuditError.io("audit: log is closed")
        }
        // Detect unlink/replacement, hardlinking, or permission widening that
        // happened after open. Continue writing only to the private inode that
        // was validated at construction.
        let current = try Self.validateJournalFD(
            handle.fileDescriptor, repairPermissions: false)
        guard current.st_size == committedSize else {
            throw AuditError.io("audit: journal size changed outside the writer")
        }
        let originalSeq = seq
        let (nextSeq, sequenceOverflow) = originalSeq.addingReportingOverflow(1)
        guard !sequenceOverflow else {
            throw AuditError.io("audit: sequence exhausted")
        }
        var e = event
        seq = nextSeq
        e.seq = nextSeq
        if e.ts.isEmpty { e.ts = Self.timestamp() }
        e.prevHash = ""
        e.thisHash = ""

        let payload = CanonicalJSON.data(e.canonicalValue)
        let sealedBlob: Data
        do {
            sealedBlob = try ECIES.seal(payload, to: recipient)
        } catch {
            seq = originalSeq
            throw AuditError.io("audit: sealing failed: \(error)")
        }
        var row = SealedAuditRow(seq: e.seq, sealed: sealedBlob.base64EncodedString(),
                                 prevHash: prev, thisHash: "")
        row.thisHash = Self.chainHash(prev: prev, seq: row.seq, sealed: row.sealed)
        if let signer {
            do {
                row.sig = try signer.sign(Data(row.thisHash.utf8)).base64EncodedString()
            } catch {
                seq = originalSeq
                throw AuditError.io("audit: signing failed: \(error)")
            }
        }

        var line = CanonicalJSON.data(Self.canonicalRow(row))
        guard line.count <= Self.maximumRowBytes else {
            seq = originalSeq
            throw AuditError.io("audit: row exceeds \(Self.maximumRowBytes) bytes")
        }
        line.append(0x0A)
        // Save EOF so a failed append can restore the last committed row.
        let fd = handle.fileDescriptor
        let preSize = lseek(fd, 0, SEEK_END)
        guard preSize == committedSize else {
            seq = originalSeq
            throw AuditError.io("audit: journal changed before append")
        }
        func rollback() {
            seq = originalSeq
            if preSize >= 0 { _ = ftruncate(fd, preSize) }
        }
        do {
            try handle.write(contentsOf: line)
        } catch {
            rollback()
            throw AuditError.io("audit: write failed: \(error.localizedDescription)")
        }
        do {
            try sync()
        } catch {
            rollback()
            throw AuditError.io("audit: sync failed: \(error)")
        }
        guard let lineSize = off_t(exactly: line.count) else {
            rollback()
            throw AuditError.io("audit: row size is not representable")
        }
        let (expectedSize, sizeOverflow) = preSize.addingReportingOverflow(lineSize)
        guard !sizeOverflow else {
            rollback()
            throw AuditError.io("audit: journal size overflow")
        }
        let afterWrite: stat
        do {
            afterWrite = try Self.validateJournalFD(fd, repairPermissions: false)
        } catch {
            rollback()
            throw error
        }
        guard afterWrite.st_size == expectedSize else {
            rollback()
            throw AuditError.io("audit: journal changed during append")
        }
        committedSize = expectedSize
        prev = row.thisHash
        // Mirror the outer chain into the returned event for in-process consumers.
        e.prevHash = row.prevHash
        e.thisHash = row.thisHash
        return e
    }

    /// Closes the underlying file. Later appends fail.
    public func close() throws {
        lock.lock()
        defer { lock.unlock() }
        if closed { return }
        closed = true
        try handle.close()
    }

    // MARK: - Verify (no key needed)

    /// Verifies row hashes and links without decrypting the log.
    public static func verify(dir: URL) -> (count: Int, ok: Bool) {
        let r = verifyDetailed(dir: dir)
        return (r.count, r.failure == nil)
    }

    /// Identifies the first invalid row. When a signer key is supplied, every row
    /// must also have a valid signature.
    public static func verifyDetailed(dir: URL, signerPublicKeyX963: Data? = nil) -> (count: Int, failure: AuditError?) {
        let opened: OpenJournal
        do {
            guard let journal = try openJournal(dir: dir, forWriting: false) else {
                return (0, nil)
            }
            opened = journal
        } catch {
            return (0, error as? AuditError ?? .io("audit: read: \(error.localizedDescription)"))
        }
        defer { Darwin.close(opened.fd) }
        let decoder = JSONDecoder()
        var prev = genesisPrev
        var count = 0
        var wantSeq: Int64 = 0
        var reader = JournalLineReader(fd: opened.fd, fileSize: opened.size)
        while true {
            let rowNumber: Int
            do {
                rowNumber = try incremented(count, context: "row number")
            } catch {
                return (count, error as? AuditError ?? .io("audit: row number overflow"))
            }
            let line: Data
            do {
                guard let next = try reader.nextLine(rowNumber: rowNumber) else { break }
                line = next
            } catch {
                return (count, error as? AuditError ?? .io("audit: read: \(error.localizedDescription)"))
            }
            let r: SealedAuditRow
            do {
                r = try decoder.decode(SealedAuditRow.self, from: line)
            } catch {
                return (count, .corruptRow(row: rowNumber, detail: String(describing: error)))
            }
            let (nextSeq, overflow) = wantSeq.addingReportingOverflow(1)
            guard !overflow else {
                return (count, .io("audit: sequence overflow"))
            }
            wantSeq = nextSeq
            guard r.seq == wantSeq else {
                return (count, .seqGap(row: wantSeq, got: r.seq))
            }
            guard r.prevHash == prev else {
                return (count, .brokenLink(seq: r.seq))
            }
            guard chainHash(prev: prev, seq: r.seq, sealed: r.sealed) == r.thisHash else {
                return (count, .tampered(seq: r.seq))
            }
            if let e = checkSignature(r, pub: signerPublicKeyX963) {
                return (count, e)
            }
            prev = r.thisHash
            count = rowNumber
        }
        return (count, nil)
    }

    /// Returns the current chain head and the hash at an earlier sequence.
    public static func chainFacts(dir: URL, hashAtSeq: Int64) -> (headSeq: Int64, headHash: String, headSig: String, hashAt: String?)? {
        let opened: OpenJournal
        do {
            guard let journal = try openJournal(dir: dir, forWriting: false) else {
                return (0, genesisPrev, "", hashAtSeq == 0 ? genesisPrev : nil)
            }
            opened = journal
        } catch {
            return nil
        }
        defer { Darwin.close(opened.fd) }
        if opened.size == 0 {
            return (0, genesisPrev, "", hashAtSeq == 0 ? genesisPrev : nil)
        }
        let decoder = JSONDecoder()
        var headSeq: Int64 = 0
        var headHash = genesisPrev
        var headSig = ""
        var hashAt: String? = hashAtSeq == 0 ? genesisPrev : nil
        var rowNumber = 0
        var reader = JournalLineReader(fd: opened.fd, fileSize: opened.size)
        while true {
            let nextRowNumber: Int
            do {
                nextRowNumber = try incremented(rowNumber, context: "row number")
            } catch {
                return nil
            }
            let line: Data
            do {
                guard let next = try reader.nextLine(rowNumber: nextRowNumber) else { break }
                line = next
            } catch {
                return nil
            }
            rowNumber = nextRowNumber
            guard let r = try? decoder.decode(SealedAuditRow.self, from: line) else {
                return nil
            }
            headSeq = r.seq
            headHash = r.thisHash
            headSig = r.sig
            if r.seq == hashAtSeq { hashAt = r.thisHash }
        }
        return (headSeq, headHash, headSig, hashAt)
    }

    // MARK: - Read (requires the vault's audit identity)

    /// Decrypts the log with the vault's P-256 audit identity. Every row is
    /// verified and decrypted, but only the newest
    /// `maxEvents` and `maxRetainedBytes` are retained in memory. The caller
    /// zeroizes `identityRaw` after use. Pass larger explicit bounds for a
    /// bounded export operation.
    public static func read(dir: URL, identityRaw: Data, signerPublicKeyX963: Data? = nil,
                            retainingLast maxEvents: Int = defaultReadRetention,
                            retainingAtMostBytes maxRetainedBytes: Int = defaultReadRetentionBytes) throws -> [AuditEvent] {
        guard maxEvents >= 0, maxRetainedBytes >= 0 else {
            throw AuditError.io("audit: retention limits must not be negative")
        }
        let identity: P256.KeyAgreement.PrivateKey
        do {
            identity = try P256.KeyAgreement.PrivateKey(rawRepresentation: identityRaw)
        } catch {
            throw AuditError.io("audit: identity is not a P-256 private key")
        }
        guard let opened = try openJournal(dir: dir, forWriting: false) else { return [] }
        defer { Darwin.close(opened.fd) }
        let decoder = JSONDecoder()
        var prev = genesisPrev
        var wantSeq: Int64 = 0
        var events = EventTail(capacity: maxEvents, byteCapacity: maxRetainedBytes)
        var rowNo = 0
        var reader = JournalLineReader(fd: opened.fd, fileSize: opened.size)
        while true {
            let nextRowNumber = try incremented(rowNo, context: "row number")
            guard let line = try reader.nextLine(rowNumber: nextRowNumber) else { break }
            rowNo = nextRowNumber
            let r: SealedAuditRow
            do {
                r = try decoder.decode(SealedAuditRow.self, from: line)
            } catch {
                throw AuditError.corruptRow(row: rowNo, detail: String(describing: error))
            }
            let (nextSeq, overflow) = wantSeq.addingReportingOverflow(1)
            guard !overflow else { throw AuditError.io("audit: sequence overflow") }
            wantSeq = nextSeq
            guard r.seq == wantSeq else { throw AuditError.seqGap(row: wantSeq, got: r.seq) }
            guard r.prevHash == prev else { throw AuditError.brokenLink(seq: r.seq) }
            guard chainHash(prev: prev, seq: r.seq, sealed: r.sealed) == r.thisHash else {
                throw AuditError.tampered(seq: r.seq)
            }
            if let e = checkSignature(r, pub: signerPublicKeyX963) { throw e }
            prev = r.thisHash

            guard let blob = Data(base64Encoded: r.sealed) else {
                throw AuditError.unreadable(seq: r.seq)
            }
            let payload: Data
            do {
                payload = try ECIES.open(blob) { ephemeralPub in
                    try identity.sharedSecretFromKeyAgreement(with: ephemeralPub)
                }
            } catch {
                throw AuditError.unreadable(seq: r.seq)
            }
            var e: AuditEvent
            do {
                e = try decoder.decode(AuditEvent.self, from: payload)
            } catch {
                throw AuditError.corruptRow(row: rowNo, detail: String(describing: error))
            }
            e.seq = r.seq
            e.prevHash = r.prevHash
            e.thisHash = r.thisHash
            // Strings and collection metadata cost more than their encoded
            // payload. A conservative 4x + fixed allowance keeps the retained
            // decoded heap beneath the explicit byte budget in normal layouts.
            let (scaled, scaleOverflow) = payload.count.multipliedReportingOverflow(by: 4)
            let (estimatedBytes, addOverflow) = scaled.addingReportingOverflow(512)
            try events.append(e, byteCost: scaleOverflow || addOverflow ? Int.max : estimatedBytes)
        }
        return events.ordered
    }

    // MARK: - Safe journal open

    /// Pin the directory, then open only its fixed direct child. O_NONBLOCK
    /// prevents a planted FIFO from hanging before fstat can reject it;
    /// O_NOFOLLOW rejects a final symlink; nlink==1 rejects hardlink aliases.
    private static func openJournal(dir: URL, forWriting: Bool) throws -> OpenJournal? {
        guard !dir.path.utf8.contains(0) else {
            throw AuditError.io("audit: directory path contains NUL")
        }
        if forWriting {
            do {
                try FileManager.default.createDirectory(
                    at: dir, withIntermediateDirectories: true,
                    attributes: [.posixPermissions: 0o700])
            } catch {
                throw AuditError.io("audit: mkdir \(dir.path): \(error.localizedDescription)")
            }
        }

        let dirFD = Darwin.open(dir.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard dirFD >= 0 else {
            if !forWriting, errno == ENOENT { return nil }
            throw AuditError.io("audit: open directory \(dir.path): \(String(cString: strerror(errno)))")
        }
        defer { Darwin.close(dirFD) }

        if forWriting {
            try validateDirectoryFD(dirFD, repairPermissions: true)
        }

        var flags = O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC
        flags |= forWriting ? (O_CREAT | O_RDWR | O_APPEND) : O_RDONLY
        let fd = fileName.withCString { Darwin.openat(dirFD, $0, flags, 0o600) }
        guard fd >= 0 else {
            if !forWriting, errno == ENOENT { return nil }
            throw AuditError.io("audit: open journal: \(String(cString: strerror(errno)))")
        }
        var keepFD = false
        defer { if !keepFD { Darwin.close(fd) } }

        if !forWriting {
            try validateDirectoryFD(dirFD, repairPermissions: false)
        }
        var info = try validateJournalFD(fd, repairPermissions: forWriting)
        if forWriting {
            guard flock(fd, LOCK_EX | LOCK_NB) == 0 else {
                throw AuditError.io("audit: journal already has a writer")
            }
            // Snapshot after acquiring writer ownership.
            info = try validateJournalFD(fd, repairPermissions: false)
        }
        guard info.st_size >= 0 else {
            throw AuditError.io("audit: invalid journal size")
        }
        keepFD = true
        return OpenJournal(fd: fd, size: info.st_size)
    }

    private static func validateDirectoryFD(_ fd: Int32, repairPermissions: Bool) throws {
        var info = stat()
        guard Darwin.fstat(fd, &info) == 0 else {
            throw AuditError.io("audit: fstat directory: \(String(cString: strerror(errno)))")
        }
        guard (info.st_mode & S_IFMT) == S_IFDIR, info.st_uid == geteuid() else {
            throw AuditError.io("audit: directory is not a private owned directory")
        }
        if repairPermissions {
            guard Darwin.fchmod(fd, 0o700) == 0 else {
                throw AuditError.io("audit: chmod directory: \(String(cString: strerror(errno)))")
            }
        } else if (info.st_mode & 0o777) != 0o700 {
            throw AuditError.io("audit: directory permissions must be 0700")
        }
    }

    @discardableResult
    private static func validateJournalFD(_ fd: Int32, repairPermissions: Bool) throws -> stat {
        var info = stat()
        guard Darwin.fstat(fd, &info) == 0 else {
            throw AuditError.io("audit: fstat journal: \(String(cString: strerror(errno)))")
        }
        guard (info.st_mode & S_IFMT) == S_IFREG,
              info.st_nlink == 1,
              info.st_uid == geteuid() else {
            throw AuditError.io("audit: journal must be one private owned regular file")
        }
        if repairPermissions {
            guard Darwin.fchmod(fd, 0o600) == 0 else {
                throw AuditError.io("audit: chmod journal: \(String(cString: strerror(errno)))")
            }
            guard Darwin.fstat(fd, &info) == 0 else {
                throw AuditError.io("audit: fstat journal: \(String(cString: strerror(errno)))")
            }
        }
        guard (info.st_mode & 0o777) == 0o600 else {
            throw AuditError.io("audit: journal permissions must be 0600")
        }
        return info
    }

    // MARK: - Chain hash

    /// Canonical outer-row preimage containing `seq` and `sealed`.
    private static func canonicalPreimage(seq: Int64, sealed: String) -> CanonicalJSON.Value {
        .object(["seq": .int(Int(seq)), "sealed": .string(sealed)])
    }

    /// Canonical disk row. The randomized ECDSA signature is excluded from the
    /// chain preimage and verified separately.
    private static func canonicalRow(_ r: SealedAuditRow) -> CanonicalJSON.Value {
        var obj: [String: CanonicalJSON.Value] = [
            "seq": .int(Int(r.seq)), "sealed": .string(r.sealed),
            "prev_hash": .string(r.prevHash), "this_hash": .string(r.thisHash)]
        if !r.sig.isEmpty { obj["sig"] = .string(r.sig) }
        return .object(obj)
    }

    /// Signature check for one row: required and valid when `pub` is given.
    private static func checkSignature(_ r: SealedAuditRow, pub: Data?) -> AuditError? {
        guard let pub else { return nil }
        guard !r.sig.isEmpty, let der = Data(base64Encoded: r.sig) else {
            return .unsigned(seq: r.seq)
        }
        guard AuditSignatureVerifier.isValid(signatureDER: der,
                                             message: Data(r.thisHash.utf8),
                                             publicKeyX963: pub) else {
            return .badSignature(seq: r.seq)
        }
        return nil
    }

    /// `this_hash = SHA256(prev ‖ canonical({seq, sealed}))`. `prev` is hashed
    /// as its ASCII hex characters.
    static func chainHash(prev: String, seq: Int64, sealed: String) -> String {
        var hasher = SHA256()
        hasher.update(data: Data(prev.utf8))
        hasher.update(data: CanonicalJSON.data(canonicalPreimage(seq: seq, sealed: sealed)))
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    /// RFC 3339 UTC with fractional seconds.
    static func timestamp(now: Date = Date()) -> String {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f.string(from: now)
    }

    private func sync() throws {
        if let syncOverride {
            try syncOverride()
            return
        }
        guard fsync(handle.fileDescriptor) == 0 else {
            throw AuditError.io(String(cString: strerror(errno)))
        }
    }

    // MARK: Test hooks

    func _setSyncForTesting(_ fn: (@Sendable () throws -> Void)?) {
        lock.lock()
        defer { lock.unlock() }
        syncOverride = fn
    }

    var _chainStateForTesting: (seq: Int64, prev: String) {
        lock.lock()
        defer { lock.unlock() }
        return (seq, prev)
    }
}
