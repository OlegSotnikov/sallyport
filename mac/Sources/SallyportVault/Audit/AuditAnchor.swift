import Foundation
import CryptoKit
import SallyportKit
import Darwin

/// Signed vault-generation and audit-head checkpoint used to detect partial rollback.
/// A consistent rollback of vault, journal, and anchor is indistinguishable from backup restore.
public struct AnchorState: Codable, Equatable, Sendable {
    public var v: Int
    /// Strictly increasing anchor counter.
    public var counter: Int64
    public var headSeq: Int64
    public var headHash: String
    /// Vault configuration generation at checkpoint time.
    public var generation: Int64
    /// SHA-256 over trust-bearing ciphertext at checkpoint time.
    public var stateDigest: String
    public var ts: String
    /// base64 DER ECDSA over the canonical form of every field above.
    public var sig: String

    public init(v: Int = 1, counter: Int64, headSeq: Int64, headHash: String,
                generation: Int64, stateDigest: String = "", ts: String, sig: String = "") {
        self.v = v; self.counter = counter
        self.headSeq = headSeq; self.headHash = headHash
        self.generation = generation; self.stateDigest = stateDigest
        self.ts = ts; self.sig = sig
    }

    /// The exact signed bytes. Canonical JSON, `sig` excluded.
    var signedPayload: Data {
        // Sallyport targets 64-bit macOS, where Int represents every Int64.
        // `clamping:` keeps this conversion total even if the package is ever
        // inspected or built for a narrower unsupported target.
        CanonicalJSON.data(.object([
            "v": .int(v),
            "counter": .int(Int(clamping: counter)),
            "head_seq": .int(Int(clamping: headSeq)),
            "head_hash": .string(headHash),
            "generation": .int(Int(clamping: generation)),
            "state_digest": .string(stateDigest),
            "ts": .string(ts),
        ]))
    }

    enum CodingKeys: String, CodingKey {
        case v, counter, generation, ts, sig
        case headSeq = "head_seq"
        case headHash = "head_hash"
        case stateDigest = "state_digest"
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        v = try c.decode(Int.self, forKey: .v)
        counter = try c.decode(Int64.self, forKey: .counter)
        headSeq = try c.decode(Int64.self, forKey: .headSeq)
        headHash = try c.decode(String.self, forKey: .headHash)
        generation = try c.decode(Int64.self, forKey: .generation)
        stateDigest = try c.decodeIfPresent(String.self, forKey: .stateDigest) ?? ""
        ts = try c.decode(String.self, forKey: .ts)
        sig = try c.decodeIfPresent(String.self, forKey: .sig) ?? ""
    }
}

/// Persistence interface for the rollback anchor.
public protocol AnchorStore: Sendable {
    /// Missing is distinct from unreadable/corrupt. Integrity callers must never
    /// turn an I/O or decode failure into "no anchor yet" and mint over evidence.
    func load() throws -> AnchorState?
    func save(_ anchor: AnchorState) throws
    func reset() throws
}

public enum AnchorStoreError: Error, Equatable, Sendable {
    case invalidState
    case nonMonotonic(previous: Int64, next: Int64)
    case unsafeParent
    case unsafeFile
    case tooLarge
    case io(Int32)
}

/// Stores the signed anchor in one 0600 JSON file.
public final class FileAnchorStore: AnchorStore, @unchecked Sendable {
    private let url: URL
    private let lock = NSLock()
    private static let maxBytes: off_t = 1 * 1024 * 1024

    public init(url: URL) { self.url = url }

    public func load() throws -> AnchorState? {
        lock.lock(); defer { lock.unlock() }
        let dirFD = try openParent()
        defer { Darwin.close(dirFD) }
        guard let data = try readFile(dirFD: dirFD) else { return nil }
        return try JSONDecoder().decode(AnchorState.self, from: data)
    }

    public func save(_ anchor: AnchorState) throws {
        lock.lock(); defer { lock.unlock() }
        guard anchor.v == 1, anchor.counter > 0, anchor.headSeq >= 0,
              anchor.generation >= 0 else {
            throw AnchorStoreError.invalidState
        }
        let dirFD = try openParent()
        defer { Darwin.close(dirFD) }
        if let data = try readFile(dirFD: dirFD) {
            let previous = try JSONDecoder().decode(AnchorState.self, from: data)
            guard anchor.counter > previous.counter else {
                throw AnchorStoreError.nonMonotonic(previous: previous.counter, next: anchor.counter)
            }
        }
        let enc = JSONEncoder()
        enc.outputFormatting = [.sortedKeys]
        let data = try enc.encode(anchor)
        guard data.count <= Int(Self.maxBytes) else { throw AnchorStoreError.tooLarge }
        try writeAtomically(data, dirFD: dirFD)
    }

    public func reset() throws {
        lock.lock(); defer { lock.unlock() }
        let dirFD = try openParent()
        defer { Darwin.close(dirFD) }
        let rc = url.lastPathComponent.withCString { Darwin.unlinkat(dirFD, $0, 0) }
        if rc != 0, errno != ENOENT { throw AnchorStoreError.io(errno) }
        if rc == 0, Darwin.fsync(dirFD) != 0 { throw AnchorStoreError.io(errno) }
    }

    /// Pin the exact parent directory. This rejects the same-UID pre-planted
    /// symlink that would otherwise redirect the off-home freshness anchor back
    /// into an attacker-controlled rollback set.
    private func openParent() throws -> Int32 {
        let filename = url.lastPathComponent
        guard !filename.isEmpty, filename != ".", filename != "..", !filename.contains("/") else {
            throw AnchorStoreError.unsafeFile
        }
        let parent = url.deletingLastPathComponent().path
        let fd = parent.withCString {
            Darwin.open($0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        }
        guard fd >= 0 else {
            if errno == ELOOP || errno == ENOTDIR { throw AnchorStoreError.unsafeParent }
            throw AnchorStoreError.io(errno)
        }
        var st = stat()
        guard Darwin.fstat(fd, &st) == 0 else {
            let code = errno; Darwin.close(fd); throw AnchorStoreError.io(code)
        }
        guard (st.st_mode & S_IFMT) == S_IFDIR,
              st.st_uid == geteuid(),
              (st.st_mode & 0o022) == 0 else {
            Darwin.close(fd)
            throw AnchorStoreError.unsafeParent
        }
        return fd
    }

    private func readFile(dirFD: Int32) throws -> Data? {
        let fd = url.lastPathComponent.withCString {
            Darwin.openat(dirFD, $0, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        }
        guard fd >= 0 else {
            if errno == ENOENT { return nil }
            if errno == ELOOP { throw AnchorStoreError.unsafeFile }
            throw AnchorStoreError.io(errno)
        }
        defer { Darwin.close(fd) }
        var before = stat()
        guard Darwin.fstat(fd, &before) == 0 else { throw AnchorStoreError.io(errno) }
        guard (before.st_mode & S_IFMT) == S_IFREG,
              before.st_nlink == 1,
              before.st_uid == geteuid(),
              (before.st_mode & 0o077) == 0 else {
            throw AnchorStoreError.unsafeFile
        }
        guard before.st_size >= 0, before.st_size <= Self.maxBytes,
              let count = Int(exactly: before.st_size) else {
            throw AnchorStoreError.tooLarge
        }
        var data = Data(count: count)
        if count > 0 {
            try data.withUnsafeMutableBytes { raw in
                guard let base = raw.baseAddress else { throw AnchorStoreError.io(EIO) }
                var offset = 0
                while offset < count {
                    let n = Darwin.read(fd, base.advanced(by: offset), count - offset)
                    if n < 0, errno == EINTR { continue }
                    guard n > 0 else { throw AnchorStoreError.io(n < 0 ? errno : EIO) }
                    offset += n
                }
            }
        }
        var after = stat()
        guard Darwin.fstat(fd, &after) == 0 else { throw AnchorStoreError.io(errno) }
        guard after.st_dev == before.st_dev, after.st_ino == before.st_ino,
              after.st_nlink == 1, after.st_size == before.st_size,
              after.st_mtimespec.tv_sec == before.st_mtimespec.tv_sec,
              after.st_mtimespec.tv_nsec == before.st_mtimespec.tv_nsec else {
            throw AnchorStoreError.unsafeFile
        }
        return data
    }

    private func writeAtomically(_ data: Data, dirFD: Int32) throws {
        let temp = ".anchor-\(UUID().uuidString).tmp"
        let fd = temp.withCString {
            Darwin.openat(dirFD, $0,
                          O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                          mode_t(0o600))
        }
        guard fd >= 0 else { throw AnchorStoreError.io(errno) }
        var keepTemp = true
        defer {
            Darwin.close(fd)
            if keepTemp { _ = temp.withCString { Darwin.unlinkat(dirFD, $0, 0) } }
        }
        try data.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return }
            var offset = 0
            while offset < raw.count {
                let n = Darwin.write(fd, base.advanced(by: offset), raw.count - offset)
                if n < 0, errno == EINTR { continue }
                guard n > 0 else { throw AnchorStoreError.io(n < 0 ? errno : EIO) }
                offset += n
            }
        }
        guard Darwin.fsync(fd) == 0 else { throw AnchorStoreError.io(errno) }
        let renameRC = temp.withCString { src in
            url.lastPathComponent.withCString { dst in
                Darwin.renameat(dirFD, src, dirFD, dst)
            }
        }
        guard renameRC == 0 else { throw AnchorStoreError.io(errno) }
        keepTemp = false
        guard Darwin.fsync(dirFD) == 0 else { throw AnchorStoreError.io(errno) }
        // The descriptor remains pinned until the caller returns, so neither an
        // ancestor rename nor a path swap can redirect this commit.
        var st = stat()
        guard url.lastPathComponent.withCString({ Darwin.fstatat(dirFD, $0, &st, AT_SYMLINK_NOFOLLOW) }) == 0,
              (st.st_mode & S_IFMT) == S_IFREG, st.st_nlink == 1,
              st.st_uid == geteuid(), (st.st_mode & 0o077) == 0 else {
            throw AnchorStoreError.unsafeFile
        }
    }
}

// MARK: - Integrity check

/// Detected integrity problem. `code` is stable for
/// tests and logs; `message` is what the banner shows.
public struct IntegrityIssue: Equatable, Sendable {
    public let code: String
    public let message: String
    public init(_ code: String, _ message: String) {
        self.code = code; self.message = message
    }
}

/// Evaluates the unlock-time integrity inputs without external state.
public enum IntegrityCheck {

    /// Compares journal and vault state with the anchor.
    ///
    /// - Parameters:
    ///   - anchor: the persisted anchor, nil when missing.
    ///   - anchorExpected: False for a vault created during this launch.
    ///   - signerPub: the DEK-sealed signer public key (the trust root).
    ///   - currentSignerPub: The current signer's public key.
    ///   - auditDir: the journal directory.
    ///   - dbGeneration: the vault's sealed configuration generation.
    ///   - anchorCounterFloor: Last sealed counter; zero when absent.
    public static func run(anchor: AnchorState?,
                           anchorExpected: Bool,
                           signerPub: Data,
                           currentSignerPub: Data,
                           auditDir: URL,
                           dbGeneration: Int64,
                           currentStateDigest: String,
                           anchorCounterFloor: Int64 = 0) -> [IntegrityIssue] {
        var issues: [IntegrityIssue] = []

        guard dbGeneration >= 0, anchorCounterFloor >= 0 else {
            return [IntegrityIssue("integrity-counter-invalid",
                "The vault contains an invalid integrity counter.")]
        }

        if currentSignerPub != signerPub {
            issues.append(IntegrityIssue("signer-changed",
                "The audit signing key changed. Accept the current state to start a new audit chain."))
        }

        guard let anchor else {
            if anchorExpected {
                issues.append(IntegrityIssue("anchor-missing",
                    "The integrity anchor is missing, so the audit log and settings cannot be checked for rollback. Accept the current state to create a new anchor."))
            }
            return issues
        }

        guard anchor.v == 1, anchor.counter > 0, anchor.headSeq >= 0,
              anchor.generation >= 0 else {
            issues.append(IntegrityIssue("anchor-invalid",
                "The integrity anchor contains invalid version or counter fields."))
            return issues
        }

        // The anchor must be OURS: signed by the adopted signer.
        guard let der = Data(base64Encoded: anchor.sig),
              AuditSignatureVerifier.isValid(signatureDER: der,
                                             message: anchor.signedPayload,
                                             publicKeyX963: signerPub) else {
            issues.append(IntegrityIssue("anchor-forged",
                "This vault's audit key did not sign the integrity anchor. It may have been replaced or corrupted."))
            return issues   // an untrusted anchor proves nothing further
        }

        // Reject an anchor older than the counter sealed in the vault.
        if anchor.counter < anchorCounterFloor {
            issues.append(IntegrityIssue("anchor-rolled-back",
                "The integrity anchor is older than the vault's recorded counter (\(anchor.counter) < \(anchorCounterFloor)). It may have been restored from backup."))
        }

        // The audit log must still contain the anchored head.
        if let facts = AuditLog.chainFacts(dir: auditDir, hashAtSeq: anchor.headSeq) {
            if facts.headSeq < anchor.headSeq || facts.hashAt != anchor.headHash {
                issues.append(IntegrityIssue("audit-rolled-back",
                    "The audit log is older than its last known state. Entries after sequence \(anchor.headSeq) are missing or changed."))
            }
        } else {
            issues.append(IntegrityIssue("audit-unreadable",
                "The audit journal cannot be read for the integrity check."))
        }

        // Verify every row's chain link and signature with the adopted key.
        if let f = AuditLog.verifyDetailed(dir: auditDir, signerPublicKeyX963: signerPub).failure {
            issues.append(IntegrityIssue("audit-untrusted",
                "The audit log failed verification: \(f)"))
        }

        // The vault's configuration must be at least as new as anchored.
        if dbGeneration < anchor.generation {
            issues.append(IntegrityIssue("vault-rolled-back",
                "The vault database is older than its last known state (generation \(dbGeneration) < \(anchor.generation)). Deleted keys or old settings may have returned."))
        }

        // Detect content rollback even when the generation and anchor still match.
        if !anchor.stateDigest.isEmpty, anchor.stateDigest != currentStateDigest {
            issues.append(IntegrityIssue("state-rolled-back",
                "The stored configuration does not match the signed integrity anchor. Sealed content may have been rolled back."))
        }

        return issues
    }

    /// Builds a signed anchor. A signing failure leaves the previous anchor intact.
    public static func mintAnchor(previous: AnchorState?,
                                  signer: any AuditSigner,
                                  auditDir: URL,
                                  dbGeneration: Int64,
                                  stateDigest: String,
                                  minimumCounter: Int64 = 0) throws -> AnchorState {
        guard dbGeneration >= 0, minimumCounter >= 0 else {
            throw AnchorStoreError.invalidState
        }
        let facts = AuditLog.chainFacts(dir: auditDir, hashAtSeq: 0)
        let prior = max(previous?.counter ?? 0, minimumCounter)
        let (counter, overflow) = prior.addingReportingOverflow(1)
        guard !overflow, counter > 0 else {
            throw AnchorStoreError.invalidState
        }
        var a = AnchorState(counter: counter,
                            headSeq: facts?.headSeq ?? 0,
                            headHash: facts?.headHash ?? AuditLog.genesisPrev,
                            generation: dbGeneration,
                            stateDigest: stateDigest,
                            ts: AuditLog.timestamp())
        a.sig = try signer.sign(a.signedPayload).base64EncodedString()
        return a
    }
}
