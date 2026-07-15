import Darwin
import Foundation
import Testing
@testable import SallyportVault

private enum SSHResponseTestError: Error { case pipe }

@Suite("SSH helper response — truncation and malformed output", .serialized)
struct SSHSpawnerResponseSecurityTests {
    private func response(_ changes: [String: Any] = [:]) throws -> Data {
        var object: [String: Any] = [
            "stdout": Data("out".utf8).base64EncodedString(),
            "stderr": Data("err".utf8).base64EncodedString(),
            "exitCode": 0,
            "bytesOut": 6,
            "hostKeyFp": "SHA256:test",
        ]
        for (key, value) in changes { object[key] = value }
        return try JSONSerialization.data(withJSONObject: object)
    }

    @Test("a helper truncation flag fails closed before output or recording is accepted")
    func truncatedResponseFailsClosed() throws {
        let data = try response([
            "truncated": true,
            "castB64": Data("partial recording".utf8).base64EncodedString(),
        ])
        #expect(throws: EngineError.self) {
            _ = try SSHSpawner.decodeExecResponse(data)
        }
    }

    @Test("absent/false truncation flags remain compatible and full byte counts survive")
    func completeResponsesDecode() throws {
        let absent = try SSHSpawner.decodeExecResponse(response(["bytesOut": 9]))
        #expect(absent.stdout == Data("out".utf8))
        #expect(absent.stderr == Data("err".utf8))
        #expect(absent.bytesOut == 9, "audit accounting must use the full drained byte count")

        let explicitlyComplete = try SSHSpawner.decodeExecResponse(response(["truncated": false]))
        #expect(explicitlyComplete.exitCode == 0)
        #expect(explicitlyComplete.hostKeyFingerprint == "SHA256:test")
    }

    @Test("invalid base64, field types, and impossible byte accounting are rejected")
    func malformedResponsesFailClosed() throws {
        for changes: [String: Any] in [
            ["stdout": "%%%"],
            ["stderr": 7],
            ["exitCode": "zero"],
            ["bytesOut": -1],
            ["bytesOut": 5], // retained bytes cannot exceed total drained bytes
            ["hostKeyFp": 12],
            ["truncated": "yes"],
            ["castB64": false],
        ] {
            #expect(throws: EngineError.self) {
                _ = try SSHSpawner.decodeExecResponse(response(changes))
            }
        }

        #expect(throws: EngineError.self) {
            _ = try SSHSpawner.decodeExecResponse(Data("not-json".utf8))
        }
    }

    @Test("the fd reader retains only its cap but drains surplus through EOF")
    func boundedReaderDrains() throws {
        var fds: [Int32] = [0, 0]
        guard pipe(&fds) == 0 else { throw SSHResponseTestError.pipe }
        let finished = DispatchSemaphore(value: 0)
        let writer = fds[1]
        Thread.detachNewThread {
            let payload = Data(repeating: 0x61, count: 256 * 1024)
            payload.withUnsafeBytes { raw in
                var offset = 0
                while offset < raw.count {
                    let n = Darwin.write(writer, raw.baseAddress!.advanced(by: offset), raw.count - offset)
                    if n < 0, errno == EINTR { continue }
                    if n <= 0 { break }
                    offset += n
                }
            }
            Darwin.close(writer)
            finished.signal()
        }

        let result = SSHSpawner.readBoundedResponse(fd: fds[0], maxBytes: 1024)
        Darwin.close(fds[0])
        #expect(result.data == Data(repeating: 0x61, count: 1024))
        #expect(result.exceeded)
        #expect(result.errorCode == nil)
        #expect(finished.wait(timeout: .now() + 1) == .success,
                "surplus must be drained so the helper writer can exit")
    }

    @Test("recording timestamp conversion is total for corrupt system clocks")
    func recordingTimestampBoundaries() {
        #expect(SSHSpawner.recordingTimestampMilliseconds(secondsSince1970: 1.234) == 1_234)
        #expect(SSHSpawner.recordingTimestampMilliseconds(secondsSince1970: -1) == 0)
        #expect(SSHSpawner.recordingTimestampMilliseconds(secondsSince1970: .infinity) == 0)
        #expect(SSHSpawner.recordingTimestampMilliseconds(
            secondsSince1970: .greatestFiniteMagnitude) == 0)
    }

    @Test("key normalization kills and reaps a wedged signed helper")
    func normalizeWatchdog() throws {
        let start = Date.now
        #expect(throws: SSHKeyImport.ImportError.self) {
            // `yes` is an Apple-signed executable that never reads stdin and
            // writes forever. The oversized request fills its stdin pipe, proving
            // the watchdog is armed before that blocking write, not merely before
            // the later response read.
            _ = try SSHKeyImport.normalize(helperPath: "/usr/bin/yes",
                                           pem: Data(repeating: 0x61, count: 1024 * 1024),
                                           passphrase: "",
                                           watchdogSeconds: 0.05)
        }
        #expect(Date.now.timeIntervalSince(start) < 2,
                "normalization must not remain blocked in write/read/waitpid")
    }

    @Test("disarming a watchdog forbids a delayed signal after child reaping")
    func watchdogDisarmIsSynchronized() throws {
        final class KillRecorder: @unchecked Sendable {
            let lock = NSLock()
            var pids: [pid_t] = []
        }
        let recorder = KillRecorder()
        let watchdog = ProcessGroupWatchdog(pid: 42, delay: 0.05) { pid in
            recorder.lock.withLock { recorder.pids.append(pid) }
        }
        watchdog.cancelAndWait()
        Thread.sleep(forTimeInterval: 0.1)
        #expect(recorder.lock.withLock { recorder.pids.isEmpty },
                "a cancelled work item must not signal a pid that may have been reused")
    }
}
