import Foundation
import Security
import SallyportKit
import Darwin

/// Preserves SSH failure evidence across the throwing executor boundary so the
/// Engine can write the fingerprint and sealed recording into the completion
/// audit row instead of losing them in a generic error translation.
struct SSHExecutionError: Error, Sendable, CustomStringConvertible {
    let message: String
    let bytesOut: Int
    let recording: String
    let hostKeyFingerprint: String

    var description: String { message }
}


/// Tracks in-flight `ssh.exec` children. Lock kills each process group and revokes
/// its signing agent.
public final class SSHLifecycle: @unchecked Sendable {
    private let lock = NSLock()
    private var live: [(pid: pid_t, agent: SSHAgentServer)] = []

    public init() {}

    func register(pid: pid_t, agent: SSHAgentServer) {
        lock.withLock { live.append((pid, agent)) }
    }
    func unregister(pid: pid_t) {
        lock.withLock { live.removeAll { $0.pid == pid } }
    }
    /// Revoke every live agent and kill every live process group. Called on lock.
    public func killAll() {
        let victims = lock.withLock { () -> [(pid: pid_t, agent: SSHAgentServer)] in
            let v = live; live = []; return v
        }
        for v in victims { v.agent.revoke(); kill(-v.pid, SIGKILL) }
    }
}

/// Synchronizes watchdog cancellation with process-group kills to prevent PID reuse races.
final class ProcessGroupWatchdog: @unchecked Sendable {
    private let lock = NSLock()
    private var armed = true
    private var work: DispatchWorkItem?
    private let pid: pid_t
    private let killer: @Sendable (pid_t) -> Void

    init(pid: pid_t, delay: TimeInterval,
         queue: DispatchQueue = .global(),
         killer: @escaping @Sendable (pid_t) -> Void = { kill(-$0, SIGKILL) }) {
        self.pid = pid
        self.killer = killer
        let boundedDelay = delay.isFinite && delay > 0 ? delay : 0
        let item = DispatchWorkItem { [weak self] in self?.fire() }
        work = item
        queue.asyncAfter(deadline: .now() + boundedDelay, execute: item)
    }

    private func fire() {
        lock.withLock {
            guard armed else { return }
            killer(pid)
        }
    }

    func cancelAndWait() {
        lock.withLock { armed = false }
        work?.cancel()
    }
}

/// Executes SSH through `sp-ssh`. Private keys remain in the vault process, which
/// serves signatures over a private agent socket. Recordings are sealed before disk.
public struct SSHSpawner: SSHExecuting {
    // The helper retains at most 8 MiB of raw output, but an asciicast JSON event
    // can expand control bytes up to 6x and the response base64-encodes both the
    // output and cast. 80 MiB covers that worst case while remaining a hard cap.
    static let maxExecHelperResponseBytes = 80 * 1024 * 1024
    static let maxNormalizeHelperResponseBytes = 2 * 1024 * 1024
    public let helperPath: String        // bundled sp-ssh binary
    public let knownHostsPath: String
    public let recordDir: String
    private let inventory: @Sendable (String) -> HostRef?
    /// Seals a cast with its filename as AAD. Nil disables recording.
    private let seal: (@Sendable (Data, String) throws -> Data)?
    /// Tracks active `ssh.exec` process groups for synchronous lock cleanup.
    private let lifecycle: SSHLifecycle?

    public init(helperPath: String, knownHostsPath: String, recordDir: String,
                inventory: @escaping @Sendable (String) -> HostRef?,
                seal: (@Sendable (Data, String) throws -> Data)? = nil,
                lifecycle: SSHLifecycle? = nil) {
        self.helperPath = helperPath; self.knownHostsPath = knownHostsPath
        self.recordDir = recordDir; self.inventory = inventory; self.seal = seal
        self.lifecycle = lifecycle
    }

    public func host(_ name: String) -> HostRef? { inventory(name) }

    /// Verifies the helper's static code and, in signed builds, the app's Team ID.
    static func verifyHelper(_ path: String) throws {
        guard !path.isEmpty, FileManager.default.isExecutableFile(atPath: path) else {
            throw EngineError.notConfigured("the bundled sp-ssh helper is missing")
        }
        var helper: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &helper) == errSecSuccess,
              let helper else {
            throw EngineError.notConfigured("sp-ssh: code signature is unreadable")
        }
        guard SecStaticCodeCheckValidity(helper, [], nil) == errSecSuccess else {
            throw EngineError.notConfigured("sp-ssh: code signature is invalid")
        }
        // Pin to the running app's signing identity.
        // own designated requirement's leaf team, so only a helper signed by the
        // same team is trusted. Skipped when we ourselves are ad-hoc signed.
        guard let team = SSHSpawner.ownTeamIdentifier() else { return }
        var req: SecRequirement?
        let text = "anchor apple generic and certificate leaf[subject.OU] = \"\(team)\"" as CFString
        guard SecRequirementCreateWithString(text, [], &req) == errSecSuccess, let req else { return }
        guard SecStaticCodeCheckValidity(helper, [], req) == errSecSuccess else {
            throw EngineError.notConfigured("sp-ssh is not signed by this app's team")
        }
    }

    /// Verifies the suspended child against the app's Team ID and the expected
    /// code-directory hash. Ad hoc development builds skip this check.
    static func verifyLiveChild(pid: Int32, expectedCDHash: String?) throws {
        guard let team = ownTeamIdentifier() else { return }
        guard Provenance.liveCodeSatisfies(pid: Int(pid),
                requirement: "anchor apple generic and certificate leaf[subject.OU] = \"\(team)\"") else {
            throw EngineError.notConfigured("sp-ssh: running helper is not signed by this app's team")
        }
        // Require the running binary to match the verified file.
        if let expectedCDHash {
            guard let live = liveCDHash(pid: pid), live == expectedCDHash else {
                throw EngineError.notConfigured("sp-ssh: running helper does not match the verified binary")
            }
        }
    }

    /// Hex code-directory hash for the signed binary at `path`.
    static func expectedCDHash(path: String) -> String? {
        var sc: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &sc) == errSecSuccess,
              let sc else { return nil }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(sc, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess
        else { return nil }
        return cdHashHex(info)
    }

    static func liveCDHash(pid: Int32) -> String? {
        let attrs = [kSecGuestAttributePid as String: pid] as CFDictionary
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, attrs, [], &code) == errSecSuccess, let code else { return nil }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess,
              let staticCode else { return nil }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode,
                                            SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess
        else { return nil }
        return cdHashHex(info)
    }

    private static func cdHashHex(_ info: CFDictionary?) -> String? {
        guard let dict = info as? [String: Any],
              let d = dict[kSecCodeInfoUnique as String] as? Data else { return nil }
        return d.map { String(format: "%02x", $0) }.joined()
    }

    /// This process's own Team ID (nil for an ad-hoc / unsigned dev binary).
    static func ownTeamIdentifier() -> String? {
        var me: SecCode?
        guard SecCodeCopySelf([], &me) == errSecSuccess, let me else { return nil }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(me, [], &staticCode) == errSecSuccess,
              let staticCode else { return nil }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode,
                                            SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let dict = info as? [String: Any] else { return nil }
        return dict["teamid"] as? String
    }

    /// A spawned `sp-ssh` child and the parent's ends of its stdio pipes.
    struct SpawnedChild {
        let pid: pid_t
        let stdinWrite: Int32     // parent writes the request here
        let stdoutRead: Int32     // parent reads the response here
    }

    /// Strictly decoded helper response, exposed internally for boundary tests.
    struct DecodedExecResponse {
        let stdout: Data
        let stderr: Data
        let exitCode: Int
        let bytesOut: Int
        let hostKeyFingerprint: String
        let castB64: String
        let truncated: Bool
        let helperError: String
    }

    struct BoundedReadResult {
        let data: Data
        let exceeded: Bool
        let errorCode: Int32?
    }

    /// Read a helper pipe to EOF under a retention cap. Surplus is drained and
    /// discarded so the child cannot block forever trying to finish its write.
    /// The caller performs process/agent cleanup before turning `exceeded` or
    /// `errorCode` into an outward error.
    static func readBoundedResponse(fd: Int32, maxBytes: Int) -> BoundedReadResult {
        let cap = max(0, maxBytes)
        var retained = Data()
        retained.reserveCapacity(min(cap, 64 * 1024))
        var exceeded = false
        var buffer = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let count = Darwin.read(fd, &buffer, buffer.count)
            if count < 0 {
                if errno == EINTR { continue }
                return BoundedReadResult(data: retained, exceeded: exceeded, errorCode: errno)
            }
            if count == 0 { break }
            let remaining = cap - retained.count
            if remaining > 0 {
                retained.append(contentsOf: buffer.prefix(min(count, remaining)))
            }
            if count > remaining { exceeded = true }
        }
        return BoundedReadResult(data: retained, exceeded: exceeded, errorCode: nil)
    }

    static func recordingTimestampMilliseconds(secondsSince1970: TimeInterval) -> UInt64 {
        let milliseconds = (secondsSince1970 * 1_000).rounded(.towardZero)
        return milliseconds.isFinite ? (UInt64(exactly: milliseconds) ?? 0) : 0
    }

    struct WaitResult {
        let status: Int32
        let errorCode: Int32?
    }

    /// waitpid is interruptible. Treating EINTR as child exit can leave a live
    /// helper (and its inherited descriptors/secrets) behind.
    static func waitForExit(_ pid: pid_t) -> WaitResult {
        var status: Int32 = 0
        while true {
            let result = waitpid(pid, &status, 0)
            if result == pid { return WaitResult(status: status, errorCode: nil) }
            if result < 0, errno == EINTR { continue }
            return WaitResult(status: status, errorCode: result < 0 ? errno : ECHILD)
        }
    }

    static func decodeExecResponse(_ data: Data) throws -> DecodedExecResponse {
        guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw EngineError.notConfigured("sp-ssh: unreadable response")
        }
        let helperError: String
        if let rawError = obj["error"] {
            guard let error = rawError as? String else {
                throw EngineError.notConfigured("sp-ssh: unreadable response")
            }
            helperError = error
        } else {
            helperError = ""
        }

        let truncated: Bool
        if let rawTruncated = obj["truncated"] {
            guard let flag = rawTruncated as? Bool else {
                throw EngineError.notConfigured("sp-ssh: unreadable response")
            }
            truncated = flag
        } else {
            truncated = false // backward-compatible with pre-flag helpers
        }
        guard let stdoutB64 = obj["stdout"] as? String,
              let stderrB64 = obj["stderr"] as? String,
              let stdout = Data(base64Encoded: stdoutB64),
              let stderr = Data(base64Encoded: stderrB64),
              let exitCode = obj["exitCode"] as? Int,
              let bytesOut = obj["bytesOut"] as? Int,
              bytesOut >= 0, bytesOut >= stdout.count + stderr.count,
              let fingerprint = obj["hostKeyFp"] as? String else {
            throw EngineError.notConfigured("sp-ssh: malformed response")
        }
        let castB64: String
        if let rawCast = obj["castB64"] {
            guard let cast = rawCast as? String else {
                throw EngineError.notConfigured("sp-ssh: malformed response")
            }
            castB64 = cast
        } else {
            castB64 = ""
        }
        return DecodedExecResponse(stdout: stdout, stderr: stderr,
                                   exitCode: exitCode, bytesOut: bytesOut,
                                   hostKeyFingerprint: fingerprint, castB64: castB64,
                                   truncated: truncated, helperError: helperError)
    }

    private static func setCloexec(_ fd: Int32) {
        let f = fcntl(fd, F_GETFD)
        if f >= 0 { _ = fcntl(fd, F_SETFD, f | FD_CLOEXEC) }
    }

    /// Launches `path` suspended with stdin and stdout pipes, stderr at `/dev/null`,
    /// and, when `agentChildFD >= 0`, the SSH agent socket at
    /// fd 3. Foundation's `Process` can only wire 0/1/2 and can't start suspended,
    /// Spawns the helper suspended with only its configured file descriptors.
    static func spawnHelper(path: String, agentChildFD: Int32) throws -> SpawnedChild {
        var inPipe: [Int32] = [0, 0], outPipe: [Int32] = [0, 0]
        guard pipe(&inPipe) == 0 else { throw EngineError.notConfigured("sp-ssh: pipe failed") }
        guard pipe(&outPipe) == 0 else {
            close(inPipe[0]); close(inPipe[1]); throw EngineError.notConfigured("sp-ssh: pipe failed")
        }
        let devnull = open("/dev/null", O_WRONLY)
        guard devnull >= 0 else {
            [inPipe[0], inPipe[1], outPipe[0], outPipe[1]].forEach { close($0) }
            throw EngineError.notConfigured("sp-ssh: /dev/null unavailable")
        }
        var raw = [inPipe[0], inPipe[1], outPipe[0], outPipe[1], devnull]
        if agentChildFD >= 0 { raw.append(agentChildFD) }
        raw.forEach { setCloexec($0) }

        var actions: posix_spawn_file_actions_t?
        posix_spawn_file_actions_init(&actions)
        posix_spawn_file_actions_adddup2(&actions, inPipe[0], 0)
        posix_spawn_file_actions_adddup2(&actions, outPipe[1], 1)
        posix_spawn_file_actions_adddup2(&actions, devnull, 2)
        if agentChildFD >= 0 { posix_spawn_file_actions_adddup2(&actions, agentChildFD, 3) }

        // Apple extensions close unlisted descriptors, start the child suspended
        // for live-code verification, and create a process group for cleanup.
        let cloexecDefault: Int16 = 0x4000
        let startSuspended: Int16 = 0x0080
        let setpgroup: Int16 = 0x0002
        var attr: posix_spawnattr_t?
        posix_spawnattr_init(&attr)
        posix_spawnattr_setflags(&attr, cloexecDefault | startSuspended | setpgroup)
        posix_spawnattr_setpgroup(&attr, 0)

        var pid: pid_t = 0
        var argv: [UnsafeMutablePointer<CChar>?] = [strdup(path), nil]
        let rc = posix_spawn(&pid, path, &actions, &attr, &argv, environ)
        posix_spawn_file_actions_destroy(&actions)
        posix_spawnattr_destroy(&attr)
        for p in argv where p != nil { free(p) }

        close(inPipe[0]); close(outPipe[1]); close(devnull)   // parent drops the child ends
        guard rc == 0 else {
            close(inPipe[1]); close(outPipe[0])
            throw EngineError.notConfigured("sp-ssh: posix_spawn failed (\(rc))")
        }
        // Prevent SIGPIPE if the child exits before a write.
        guard fcntl(inPipe[1], F_SETNOSIGPIPE, 1) == 0 else {
            let code = errno
            close(inPipe[1]); close(outPipe[0])
            kill(-pid, SIGKILL)
            _ = waitForExit(pid)
            throw EngineError.notConfigured("sp-ssh: could not secure helper stdin (\(code))")
        }
        return SpawnedChild(pid: pid, stdinWrite: inPipe[1], stdoutRead: outPipe[0])
    }

    /// The blocking body runs on a dedicated thread (spawn, agent serve, waitpid,
    /// pthread_join are all synchronous), so it never blocks the async executor
    /// and can use the synchronous joins the concurrency checker forbids in an
    /// async frame.
    public func execute(host: HostRef, command: String, timeoutS: Int, keyPEM: Data) async throws -> ExecOutput {
        let selfCopy = self
        return try await withCheckedThrowingContinuation { cont in
            Thread.detachNewThread {
                do { cont.resume(returning: try selfCopy.executeSync(host: host, command: command,
                                                                     timeoutS: timeoutS, keyPEM: keyPEM)) }
                catch { cont.resume(throwing: error) }
            }
        }
    }

    private func executeSync(host: HostRef, command: String, timeoutS: Int, keyPEM: Data) throws -> ExecOutput {
        // Verify the bundled helper before giving it access to the signing agent.
        try SSHSpawner.verifyHelper(helperPath)
        let expectedCDHash = SSHSpawner.expectedCDHash(path: helperPath)

        // Keep the execution key in this process and serve signatures over a
        // private agent socket.
        let key: SSHPrivateKey
        do { key = try SSHPrivateKey(opensshPEM: keyPEM) }
        catch { throw EngineError.notConfigured("sp-ssh: unusable private key: \(error)") }

        let recordsSealed = seal != nil && !recordDir.isEmpty
        let req: [String: Any] = [
            "host": host.addr.isEmpty ? host.name : host.addr,
            "user": host.user, "port": host.port,
            "hostKeyPolicy": host.hostKeyPolicy,
            "command": command,
            "timeoutS": timeoutS,
            "knownHostsPath": knownHostsPath,
            // Return the cast in memory so it can be sealed before disk storage.
            "returnCast": recordsSealed,
            // The child receives the SSH agent on file descriptor 3.
            "agentFD": 3,
        ]
        let reqData = try JSONSerialization.data(withJSONObject: req)

        // A private, unnamed socketpair: one end serves the agent from here, the
        // other is inherited by the child as fd 3. Nothing in the filesystem, so
        // no other process can reach the agent.
        var sp: [Int32] = [0, 0]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &sp) == 0 else {
            throw EngineError.notConfigured("sp-ssh: socketpair failed")
        }
        let agentParent = sp[0], agentChild = sp[1]
        // Return EPIPE instead of SIGPIPE and keep the serving descriptor out of
        // other child processes.
        var one: Int32 = 1
        setsockopt(agentParent, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        SSHSpawner.setCloexec(agentParent)

        let child: SpawnedChild
        do { child = try SSHSpawner.spawnHelper(path: helperPath, agentChildFD: agentChild) }
        catch { close(agentParent); close(agentChild); throw error }
        close(agentChild)                        // parent keeps only its end
        let pid = child.pid

        // Verify the suspended child's live code before resuming it.
        do { try SSHSpawner.verifyLiveChild(pid: pid, expectedCDHash: expectedCDHash) }
        catch {
            kill(-pid, SIGKILL); _ = SSHSpawner.waitForExit(pid)
            close(agentParent); close(child.stdinWrite); close(child.stdoutRead)
            throw error
        }
        // Register the suspended child before resuming so lock cleanup can always
        // terminate its process group and revoke the agent.
        let agentServer = SSHAgentServer(key: key,
                                         comment: host.keyName.isEmpty ? "sallyport" : host.keyName)
        lifecycle?.register(pid: pid, agent: agentServer)
        defer { lifecycle?.unregister(pid: pid) }

        // Arm before resuming and, critically, before the potentially blocking
        // stdin write. A signed-but-incompatible helper that stays alive without
        // reading must not wedge the vault on a request larger than pipe capacity.
        let deadline = TimeInterval(timeoutS > 0 ? timeoutS : 30) + 15
        let watchdog = ProcessGroupWatchdog(pid: pid, delay: deadline)
        kill(pid, SIGCONT)   // Resume after verification and registration.

        // The agent thread owns and closes `agentParent`, then signals completion.
        let agentDone = DispatchSemaphore(value: 0)
        let servedFD = agentParent
        Thread.detachNewThread {
            agentServer.serve(fd: servedFD)
            close(servedFD)
            agentDone.signal()
        }

        // Send the key-free request and read the reply to EOF.
        _ = fcntl(child.stdinWrite, F_SETNOSIGPIPE, 1)
        // Close this descriptor explicitly once.
        let stdinHandle = FileHandle(fileDescriptor: child.stdinWrite, closeOnDealloc: false)
        try? stdinHandle.write(contentsOf: reqData)
        try? stdinHandle.close()

        let helperRead = SSHSpawner.readBoundedResponse(
            fd: child.stdoutRead, maxBytes: Self.maxExecHelperResponseBytes)
        close(child.stdoutRead)

        // Stop the process group before reaping its leader to avoid PID reuse.
        agentServer.revoke()
        kill(-pid, SIGKILL)
        let waited = SSHSpawner.waitForExit(pid)
        watchdog.cancelAndWait()       // synchronized before PID reuse is possible
        // Force the agent socket closed if its serving thread does not exit.
        if agentDone.wait(timeout: .now() + 5) == .timedOut {
            shutdown(agentParent, SHUT_RDWR)
            _ = agentDone.wait(timeout: .now() + 2)
        }

        guard waited.errorCode == nil else {
            throw EngineError.notConfigured("sp-ssh: could not reap helper process")
        }

        guard helperRead.errorCode == nil else {
            throw EngineError.notConfigured("sp-ssh: response read failed")
        }
        guard !helperRead.exceeded else {
            throw EngineError.notConfigured("sp-ssh: response exceeded the bounded parent limit")
        }

        let response = try SSHSpawner.decodeExecResponse(helperRead.data)
        let fp = response.hostKeyFingerprint

        // Preserve any recording before translating the helper's error. Failed
        // authentication still produces a cast and a host-key fingerprint; both
        // belong in the completion audit row even though no command ran.
        var recording = ""
        if recordsSealed, let seal {
            if let cast = Data(base64Encoded: response.castB64), !cast.isEmpty {
                do {
                    // Add a random suffix to avoid same-millisecond filename collisions.
                    let stamp = Self.recordingTimestampMilliseconds(
                        secondsSince1970: Date().timeIntervalSince1970)
                    let filename = "ssh-\(stamp)-\(UUID().uuidString.prefix(8)).cast.sealed"
                    let sealed = try seal(cast, filename)
                    try FileManager.default.createDirectory(
                        atPath: recordDir, withIntermediateDirectories: true,
                        attributes: [.posixPermissions: 0o700])
                    let path = (recordDir as NSString).appendingPathComponent(filename)
                    try sealed.write(to: URL(fileURLWithPath: path), options: [.atomic])
                    try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path)
                    recording = path
                } catch {
                    let preservationError = "could not preserve sealed SSH recording: \(error.localizedDescription)"
                    let message = response.helperError.isEmpty
                        ? preservationError
                        : "\(response.helperError); \(preservationError)"
                    throw SSHExecutionError(message: message, bytesOut: response.bytesOut,
                                            recording: "", hostKeyFingerprint: fp)
                }
            } else if response.helperError.isEmpty && !response.truncated {
                // Successful calls require their requested security recording.
                throw SSHExecutionError(message: "sp-ssh: no session recording returned",
                                        bytesOut: response.bytesOut, recording: "",
                                        hostKeyFingerprint: fp)
            }
        }

        if !response.helperError.isEmpty {
            throw SSHExecutionError(message: response.helperError, bytesOut: response.bytesOut,
                                    recording: recording, hostKeyFingerprint: fp)
        }
        if response.truncated {
            // stdout/stderr and returnCast share the helper's retention budget.
            // The partial cast is retained as evidence, but incomplete output is
            // never returned to the agent as though the command succeeded.
            throw SSHExecutionError(
                message: "sp-ssh: command output exceeded the retention limit; output and session recording are incomplete",
                bytesOut: response.bytesOut, recording: recording,
                hostKeyFingerprint: fp)
        }

        // SSH authentication uses signatures; no vault credential bytes are
        // injected into command output. Do not rewrite the remote program's
        // output based on guesses about credential-shaped strings.
        let so = response.stdout
        let se = response.stderr
        let exit = response.exitCode

        return ExecOutput(output: [
            "stdout": .string(String(decoding: so, as: UTF8.self)),
            "stderr": .string(String(decoding: se, as: UTF8.self)),
            "exit_code": .double(Double(exit)),
            "host": .string(host.addr.isEmpty ? host.name : host.addr),
            "host_key_fingerprint": .string(fp),
        ], bytesOut: response.bytesOut, recording: recording)
    }
}

/// Validates and normalizes imported SSH keys as unencrypted OpenSSH PEM before
/// vault encryption. The passphrase is not stored.
public enum SSHKeyImport {
    private static let normalizeWatchdogSeconds: TimeInterval = 30
    public enum ImportError: Error, Equatable, Sendable {
        /// The key is encrypted and needs a passphrase.
        case passphraseRequired
        /// Invalid key / wrong passphrase / helper failure, with the reason.
        case invalid(String)
    }

    /// Run `sp-ssh` op=normalize_key. Returns the normalized PEM. When
    /// `helperPath` is empty, returns the key unchanged for tests.
    public static func normalize(helperPath: String, pem: Data, passphrase: String) throws -> Data {
        try normalize(helperPath: helperPath, pem: pem, passphrase: passphrase,
                      watchdogSeconds: normalizeWatchdogSeconds)
    }

    /// Timeout override for key-normalization tests. The default is 30 seconds.
    static func normalize(helperPath: String, pem: Data, passphrase: String,
                          watchdogSeconds: TimeInterval) throws -> Data {
        guard !helperPath.isEmpty, FileManager.default.isExecutableFile(atPath: helperPath) else {
            return pem
        }
        // Verify the helper before writing the imported key and passphrase.
        do { try SSHSpawner.verifyHelper(helperPath) }
        catch { throw ImportError.invalid("\(error)") }
        let expectedCDHash = SSHSpawner.expectedCDHash(path: helperPath)
        var req: [String: Any] = ["op": "normalize_key", "privateKeyB64": pem.base64EncodedString()]
        if !passphrase.isEmpty { req["passphrase"] = passphrase }
        var reqData = try JSONSerialization.data(withJSONObject: req)
        req["privateKeyB64"] = ""; req["passphrase"] = ""   // drop dict copies

        // Verify the suspended child before sending key material on stdin.
        let child: SSHSpawner.SpawnedChild
        do { child = try SSHSpawner.spawnHelper(path: helperPath, agentChildFD: -1) }
        catch {
            reqData.resetBytes(in: 0..<reqData.count)
            throw ImportError.invalid("sp-ssh unavailable: \(error)")
        }
        let pid = child.pid
        do { try SSHSpawner.verifyLiveChild(pid: pid, expectedCDHash: expectedCDHash) }
        catch {
            kill(-pid, SIGKILL); _ = SSHSpawner.waitForExit(pid)
            close(child.stdinWrite); close(child.stdoutRead)
            reqData.resetBytes(in: 0..<reqData.count)
            throw ImportError.invalid("\(error)")
        }
        kill(pid, SIGCONT)   // Resume after verification.

        let boundedWatchdog = watchdogSeconds.isFinite && watchdogSeconds > 0
            ? min(watchdogSeconds, normalizeWatchdogSeconds)
            : normalizeWatchdogSeconds
        let watchdog = ProcessGroupWatchdog(pid: pid, delay: boundedWatchdog)

        _ = fcntl(child.stdinWrite, F_SETNOSIGPIPE, 1)
        let stdinH = FileHandle(fileDescriptor: child.stdinWrite, closeOnDealloc: false)
        try? stdinH.write(contentsOf: reqData)
        try? stdinH.close()
        reqData.resetBytes(in: 0..<reqData.count)   // the buffer carried the key + passphrase
        let helperRead = SSHSpawner.readBoundedResponse(
            fd: child.stdoutRead, maxBytes: SSHSpawner.maxNormalizeHelperResponseBytes)
        close(child.stdoutRead)
        let waited = SSHSpawner.waitForExit(pid)
        watchdog.cancelAndWait()

        guard waited.errorCode == nil else {
            throw ImportError.invalid("sp-ssh: could not reap normalize helper")
        }

        guard helperRead.errorCode == nil else {
            throw ImportError.invalid("sp-ssh: response read failed")
        }
        guard !helperRead.exceeded else {
            throw ImportError.invalid("sp-ssh: normalize response exceeded the bounded parent limit")
        }

        guard let obj = try? JSONSerialization.jsonObject(with: helperRead.data) as? [String: Any] else {
            throw ImportError.invalid("sp-ssh: unreadable response")
        }
        if let err = obj["error"] as? String, !err.isEmpty {
            // The helper's stable sentinel for "encrypted, needs a passphrase".
            if err.contains("passphrase-protected") { throw ImportError.passphraseRequired }
            throw ImportError.invalid(err)
        }
        guard let b64 = obj["normalizedKeyB64"] as? String,
              let normalized = Data(base64Encoded: b64), !normalized.isEmpty else {
            throw ImportError.invalid("sp-ssh: empty normalize response")
        }
        return normalized
    }
}
