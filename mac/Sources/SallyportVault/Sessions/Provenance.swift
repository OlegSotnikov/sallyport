import Darwin
import Foundation
import Security
import os

/// Captures process identity from Darwin kernel and code-signing data.

// MARK: - Types

/// Available identity of the process behind a request.
public struct Origin: Sendable, Codable, Hashable {
    public var pid: Int
    /// Kernel start time used with the PID to detect PID reuse.
    public var startedAt: Int64
    public var name: String
    public var path: String
    /// The `.app` bundle display name, when any ("" for a plain CLI binary).
    public var appName: String
    /// Code-signing authority. Empty when unsigned or unavailable.
    public var signedBy: String
    public var validSignature: Bool

    public init(pid: Int = 0, startedAt: Int64 = 0, name: String = "", path: String = "",
                appName: String = "", signedBy: String = "", validSignature: Bool = false) {
        self.pid = pid; self.startedAt = startedAt; self.name = name; self.path = path
        self.appName = appName; self.signedBy = signedBy; self.validSignature = validSignature
    }
}

/// A single process in the parent chain.
public struct Hop: Sendable, Codable, Hashable {
    public var pid: Int
    public var name: String
    public var path: String
    public var ppid: Int
    /// Kernel start time, unix ns (anti-reuse).
    public var startedAt: Int64

    public init(pid: Int = 0, name: String = "", path: String = "", ppid: Int = 0,
                startedAt: Int64 = 0) {
        self.pid = pid; self.name = name; self.path = path; self.ppid = ppid
        self.startedAt = startedAt
    }
}

/// Process chain that originated a request. The app sets `intact` after checking
/// each hop's code signature.
public struct Provenance: Sendable, Codable, Hashable {
    public var origin: Origin
    public var chain: [Hop]
    public var intact: Bool

    public init(origin: Origin = Origin(), chain: [Hop] = [], intact: Bool = false) {
        self.origin = origin; self.chain = chain; self.intact = intact
    }
}

// MARK: - Kernel facts

extension Provenance {

    /// Caps how far up the parent chain we walk.
    private static let maxDepth = 16

    /// sys/un.h constants, spelled out because the C macros don't reliably
    /// import into Swift. Stable Darwin ABI: SOL_LOCAL = 0, LOCAL_PEERPID = 2.
    private static let solLocal: Int32 = 0
    private static let localPeerPID: Int32 = 0x002

    /// Returns the peer PID from `LOCAL_PEERPID`, or 0 on failure.
    public static func peerPID(fromFD fd: Int32) -> Int {
        var pid: pid_t = 0
        var len = socklen_t(MemoryLayout<pid_t>.size)
        guard getsockopt(fd, solLocal, localPeerPID, &pid, &len) == 0 else { return 0 }
        return Int(pid)
    }

    /// Walks the process parent chain from `pid`.
    public static func chain(pid: Int) -> Provenance {
        var hops: [Hop] = []
        var cur = pid
        for _ in 0..<maxDepth {
            guard cur > 1, let kp = kinfo(pid: cur) else { break }
            let ppid = Int(kp.kp_eproc.e_ppid)
            hops.append(Hop(pid: cur, name: commName(kp), path: "", ppid: ppid,
                            startedAt: startNanos(kp)))
            if ppid <= 1 || ppid == cur { break }
            cur = ppid
        }
        // Add executable paths and readable names.
        for i in hops.indices {
            hops[i].path = exePath(pid: hops[i].pid)
            // Prefer the executable basename over the truncated kernel name.
            hops[i].name = displayName(path: hops[i].path, comm: hops[i].name)
        }
        var prov = Provenance(chain: hops)
        // Skip the Sallyport shim when selecting the requesting process.
        if let h = originHop(hops) {
            var o = Origin(pid: h.pid, startedAt: h.startedAt, name: h.name, path: h.path)
            o.appName = appName(fromPath: h.path)
            // Verify the running code rather than the replaceable file path.
            let sig = codesign(pid: h.pid, path: h.path)
            o.validSignature = sig.valid
            o.signedBy = sig.authority
            prov.origin = o
        }
        return prov
    }

    /// Whether the PID still belongs to the captured process instance.
    public static func alive(pid: Int, startedAt: Int64) -> Bool {
        guard pid > 0, startedAt > 0, let kp = kinfo(pid: pid) else { return false }
        return startNanos(kp) == startedAt
    }

    // MARK: Chain internals (internal for tests)

    /// First process outside the Sallyport shim.
    static func originHop(_ hops: [Hop]) -> Hop? {
        guard let first = hops.first else { return nil }
        return hops.first { !isSallyportShim($0) } ?? first
    }

    /// Whether the running process is the Sallyport shim signed by this app's team.
    static func isSallyportShim(_ h: Hop) -> Bool {
        var base = h.path
        if let i = base.lastIndex(of: "/") { base = String(base[base.index(after: i)...]) }
        guard h.name == "sp" || base == "sp" else { return false }   // pre-filter
        guard let team = ourTeam() else { return true }   // ad-hoc dev: trust the name
        return liveCodeSatisfies(pid: h.pid,
            requirement: "anchor apple generic and certificate leaf[subject.OU] = \"\(team)\"")
    }

    /// This process's own Team ID (nil for an ad-hoc / unsigned dev binary).
    static func ourTeam() -> String? {
        var me: SecCode?
        guard SecCodeCopySelf([], &me) == errSecSuccess, let me else { return nil }
        guard let staticCode = staticCode(me) else { return nil }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode,
                                            SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let dict = info as? [String: Any] else { return nil }
        return dict[kSecCodeInfoTeamIdentifier as String] as? String
    }

    /// Whether the running code for `pid` satisfies a signing requirement.
    static func liveCodeSatisfies(pid: Int, requirement: String) -> Bool {
        guard pid > 0 else { return false }
        var codeRef: SecCode?
        let attrs = [kSecGuestAttributePid as String: pid] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attrs, [], &codeRef) == errSecSuccess, let code = codeRef else {
            return false
        }
        var req: SecRequirement?
        guard SecRequirementCreateWithString(requirement as CFString, [], &req) == errSecSuccess, let req else {
            return false
        }
        return SecCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), req) == errSecSuccess
    }

    // MARK: - Agent allowlist

    /// Returns the allowlist entry matching the running process.
    public static func matchAllowlist(pid: Int, startedAt: Int64, entries: [AllowlistEntry]) -> AllowlistEntry? {
        guard pid > 0, !entries.isEmpty else { return nil }
        // Reject a reused PID by checking the kernel start time.
        guard startedAt > 0, alive(pid: pid, startedAt: startedAt),
              let code = liveGuest(pid: pid) else { return nil }
        let liveHash = cdHash(of: code)
        for e in entries {
            switch e.kind {
            case .cdhash:
                if let liveHash, e.cdhashes.contains(liveHash) { return e }
            case .publisher:
                var req: SecRequirement?
                if SecRequirementCreateWithString(e.requirement as CFString, [], &req) == errSecSuccess,
                   let req,
                   SecCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), req) == errSecSuccess {
                    return e
                }
            }
        }
        return nil
    }

    /// Captures identity from a running process.
    public static func captureIdentity(pid: Int) -> AllowlistCapture? {
        guard pid > 0, let code = liveGuest(pid: pid), let staticCode = staticCode(code) else {
            return nil
        }
        return capture(from: staticCode, from: "live:pid \(pid)")
    }

    /// Captures code identity from a selected file. Prefer a running process.
    public static func captureIdentity(path: String) -> AllowlistCapture? {
        guard !path.isEmpty else { return nil }
        var sc: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &sc) == errSecSuccess,
              let sc else { return nil }
        return capture(from: sc, from: path)
    }

    /// The live `SecCode` for a pid (spoof-resistant vs a swappable file).
    private static func liveGuest(pid: Int) -> SecCode? {
        var codeRef: SecCode?
        let attrs = [kSecGuestAttributePid as String: pid] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attrs, [], &codeRef) == errSecSuccess else { return nil }
        return codeRef
    }

    private static func signingInfo(_ sc: SecStaticCode) -> [String: Any]? {
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(sc, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let dict = info as? [String: Any] else { return nil }
        return dict
    }

    /// Security.framework exposes distinct dynamic/static CF types. Convert
    /// through the supported API instead of relying on an unsafe object cast.
    private static func staticCode(_ code: SecCode) -> SecStaticCode? {
        var result: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &result) == errSecSuccess else { return nil }
        return result
    }

    /// The running slice's cdhash (hex) from a live `SecCode`.
    private static func cdHash(of code: SecCode) -> String? {
        guard let staticCode = staticCode(code),
              let info = signingInfo(staticCode),
              let data = info[kSecCodeInfoUnique as String] as? Data else { return nil }
        return data.map { String(format: "%02x", $0) }.joined()
    }

    /// Extract cdhashes (all arches) + team + bundle id + authority from a code
    /// object, for building an allowlist entry.
    private static func capture(from sc: SecStaticCode, from source: String) -> AllowlistCapture? {
        let valid: Bool = {
            var req: SecRequirement?
            guard SecRequirementCreateWithString("anchor apple generic" as CFString, [], &req) == errSecSuccess,
                  let req else { return false }
            return SecStaticCodeCheckValidity(sc, SecCSFlags(rawValue: kSecCSStrictValidate), req) == errSecSuccess
        }()
        guard let info = signingInfo(sc) else { return nil }
        var hashes: [String] = []
        if let arr = info[kSecCodeInfoCdHashes as String] as? [Data] {
            hashes = arr.map { $0.map { String(format: "%02x", $0) }.joined() }
        } else if let one = info[kSecCodeInfoUnique as String] as? Data {
            hashes = [one.map { String(format: "%02x", $0) }.joined()]
        }
        let team = info[kSecCodeInfoTeamIdentifier as String] as? String ?? ""
        let bundle = info[kSecCodeInfoIdentifier as String] as? String ?? ""
        var authority = ""
        if let certs = info[kSecCodeInfoCertificates as String] as? [SecCertificate], let leaf = certs.first {
            authority = (SecCertificateCopySubjectSummary(leaf) as String?) ?? ""
        }
        let label = appName(fromPath: source.hasPrefix("live:") ? "" : source)
        return AllowlistCapture(
            label: label.isEmpty ? (bundle.isEmpty ? "agent" : bundle) : label,
            cdhashes: hashes, teamID: team, bundleID: bundle,
            signed: valid, authority: authority, capturedFrom: source)
    }

    /// Returns the app name, executable basename, or kernel process name.
    static func displayName(path: String, comm: String) -> String {
        let app = appName(fromPath: path)
        if !app.isEmpty { return app }
        if let i = path.lastIndex(of: "/"), path.index(after: i) < path.endIndex {
            return String(path[path.index(after: i)...])
        }
        return comm
    }

    /// The `.app` bundle display name from an executable path, e.g.
    /// Returns `Claude` for `/Applications/Claude.app/Contents/MacOS/Claude`. Empty for a
    /// plain CLI binary (no .app in the path).
    static func appName(fromPath path: String) -> String {
        guard let r = path.range(of: ".app/") else { return "" }
        let seg = path[..<r.lowerBound]
        if let s = seg.lastIndex(of: "/") {
            return String(seg[seg.index(after: s)...])
        }
        return String(seg)
    }

    // MARK: sysctl plumbing

    /// One exact-process lookup: sysctl(kern.proc.pid). nil when the pid is gone
    /// (the call "succeeds" with size 0) or invalid.
    private static func kinfo(pid: Int) -> kinfo_proc? {
        guard let p = Int32(exactly: pid), p > 0 else { return nil }
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, p]
        // KERN_PROC_PID can transiently return zero bytes or EINVAL for a live
        // process while the process table changes. Retry before reporting exit.
        for attempt in 0..<5 {
            var info = kinfo_proc()
            var size = MemoryLayout<kinfo_proc>.stride
            if sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0) == 0,
               size == MemoryLayout<kinfo_proc>.stride {
                return info
            }
            if attempt < 4 { usleep(300) }
        }
        return nil
    }

    /// The executable path of pid via sysctl(kern.procargs2): the buffer is
    /// `[argc:int32][exec_path\0]`, so the path is the first C string. Returns an
    /// empty string on failure.
    private static func exePath(pid: Int) -> String {
        guard let p = Int32(exactly: pid), p > 0 else { return "" }
        var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, p]
        // KERN_PROCARGS2 can fail transiently while the process table changes.
        // Retry to avoid treating an unreadable path as identity drift.
        for attempt in 0..<5 {
            var size = 0
            if sysctl(&mib, UInt32(mib.count), nil, &size, nil, 0) == 0, size > 4 {
                var buf = [UInt8](repeating: 0, count: size)
                let capacity = buf.count
                if sysctl(&mib, UInt32(mib.count), &buf, &size, nil, 0) == 0,
                   size > 4, size <= capacity {
                    let rest = buf[4..<size] // skip argc
                    if let nul = rest.firstIndex(of: 0), nul > rest.startIndex {
                        return String(decoding: rest[rest.startIndex..<nul], as: UTF8.self)
                    }
                }
            }
            if attempt < 4 { usleep(300) }
        }
        return ""
    }

    /// A process's kernel start time as unix nanoseconds, read from
    /// kinfo_proc.kp_proc.p_starttime (a timeval). Paired with the PID it is a
    /// reuse-proof identity.
    private static func startNanos(_ kp: kinfo_proc) -> Int64 {
        let tv = kp.kp_proc.p_starttime
        return Int64(tv.tv_sec) * 1_000_000_000 + Int64(tv.tv_usec) * 1_000
    }

    /// The NUL-terminated p_comm char array as a String.
    private static func commName(_ kp: kinfo_proc) -> String {
        withUnsafeBytes(of: kp.kp_proc.p_comm) { raw in
            String(decoding: raw.prefix(while: { $0 != 0 }), as: UTF8.self)
        }
    }
}

// MARK: - Code-signature verification (cached)

extension Provenance {

    private struct SigResult: Sendable {
        var valid: Bool
        var authority: String
        var mtime: Int64
    }

    /// Caches signature results by path and modification time.
    private static let sigCache = OSAllocatedUnfairLock(initialState: [String: SigResult]())

    /// Validates running code and returns its leaf-certificate subject.
    /// A missing PID does not fall back to path validation.
    public static func codesign(pid: Int, path: String) -> (valid: Bool, authority: String) {
        guard pid > 0 else { return codesign(path: path) }
        // Retry transient guest lookup failures. An unsigned process can still
        // resolve successfully with an empty authority.
        for attempt in 0..<5 {
            var codeRef: SecCode?
            let attrs = [kSecGuestAttributePid as String: pid] as CFDictionary
            guard SecCodeCopyGuestWithAttributes(nil, attrs, [], &codeRef) == errSecSuccess,
                  let code = codeRef else {
                if attempt < 4 { usleep(300); continue }
                return (false, "")
            }
            var valid = false
            var reqRef: SecRequirement?
            if SecRequirementCreateWithString("anchor apple generic" as CFString, [], &reqRef) == errSecSuccess,
               let req = reqRef {
                valid = SecCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), req) == errSecSuccess
            }
            var authority = ""
            var infoRef: CFDictionary?
            if let sc = staticCode(code),
               SecCodeCopySigningInformation(sc, SecCSFlags(rawValue: kSecCSSigningInformation), &infoRef) == errSecSuccess,
               let info = infoRef as? [String: Any],
               let certs = info[kSecCodeInfoCertificates as String] as? [SecCertificate],
               let leaf = certs.first {
                authority = (SecCertificateCopySubjectSummary(leaf) as String?) ?? ""
            }
            return (valid, authority)
        }
        return (false, "")
    }

    public static func codesign(path: String) -> (valid: Bool, authority: String) {
        guard !path.isEmpty else { return (false, "") }
        var st = stat()
        guard stat(path, &st) == 0 else { return (false, "") }
        let mtime = Int64(st.st_mtimespec.tv_sec) * 1_000_000_000 + Int64(st.st_mtimespec.tv_nsec)

        if let cached = sigCache.withLock({ $0[path] }), cached.mtime == mtime {
            return (cached.valid, cached.authority)
        }

        let (valid, authority) = verifySignature(atPath: path)
        sigCache.withLock { $0[path] = SigResult(valid: valid, authority: authority, mtime: mtime) }
        return (valid, authority)
    }

    private static func verifySignature(atPath path: String) -> (Bool, String) {
        var staticCodeRef: SecStaticCode?
        let url = URL(fileURLWithPath: path) as CFURL
        guard SecStaticCodeCreateWithPath(url, [], &staticCodeRef) == errSecSuccess,
              let sc = staticCodeRef else {
            return (false, "")
        }

        // Strict validation against an Apple-rooted signing requirement.
        var valid = false
        var requirementRef: SecRequirement?
        if SecRequirementCreateWithString("anchor apple generic" as CFString, [], &requirementRef)
            == errSecSuccess, let requirement = requirementRef {
            valid = SecStaticCodeCheckValidity(
                sc, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess
        }

        // Leaf-certificate subject, empty for unsigned or ad hoc code.
        var authority = ""
        var infoRef: CFDictionary?
        if SecCodeCopySigningInformation(
            sc, SecCSFlags(rawValue: kSecCSSigningInformation), &infoRef) == errSecSuccess,
           let info = infoRef as? [String: Any],
           let certs = info[kSecCodeInfoCertificates as String] as? [SecCertificate],
           let leaf = certs.first {
            authority = (SecCertificateCopySubjectSummary(leaf) as String?) ?? ""
        }
        return (valid, authority)
    }
}
