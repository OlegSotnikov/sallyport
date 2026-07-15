import Darwin
import CryptoKit
import Foundation
import Testing
@testable import SallyportVault
import SallyportKit

private enum BinaryTestError: Error { case posix(Int32) }

@Suite("SSH wire — hostile binary boundaries")
struct SSHWireBoundaryTests {
    @Test("reader accessors reject every truncated or oversized length without indexing out of range")
    func readerBounds() throws {
        var empty = SSHWire.Reader(Data())
        #expect(throws: SSHError.truncated) { _ = try empty.byte() }

        for bytes in [Data(), Data([0]), Data([0, 0]), Data([0, 0, 0])] {
            var reader = SSHWire.Reader(bytes)
            #expect(throws: SSHError.truncated) { _ = try reader.uint32() }
        }

        // Declared lengths are attacker-controlled UInt32 values. Neither the
        // maximum nor an ordinary short payload may escape the bounds check.
        for bytes in [
            Data([0xff, 0xff, 0xff, 0xff]),
            Data([0, 0, 0, 2, 0xaa]),
            Data([0, 1, 0, 0]),
        ] {
            var reader = SSHWire.Reader(bytes)
            #expect(throws: SSHError.truncated) { _ = try reader.string() }
        }

        var reader = SSHWire.Reader(Data([0xaa, 0, 0, 0, 1, 0xbb]))
        #expect(try reader.byte() == 0xaa)
        #expect(reader.consumed == 1)
        #expect(try reader.string() == Data([0xbb]))
        #expect(reader.isAtEnd)
        #expect(reader.remaining.isEmpty)

        var invalidUTF8 = SSHWire.Reader(Data([0, 0, 0, 1, 0xff]))
        #expect(throws: SSHError.malformed("invalid UTF-8 string")) {
            _ = try invalidUTF8.stringUTF8()
        }
    }

    @Test("mpint canonicalization handles zero, leading zeroes, and the positive sign bit")
    func mpintCanonicalization() throws {
        let cases: [(Data, Data)] = [
            (Data(), Data()),
            (Data([0]), Data()),
            (Data([0, 0, 1]), Data([1])),
            (Data([0x7f]), Data([0x7f])),
            (Data([0x80]), Data([0x80])),
            (Data([0, 0xff]), Data([0xff])),
        ]
        for (input, expectedMagnitude) in cases {
            var writer = SSHWire.Writer()
            writer.mpint(input)
            var reader = SSHWire.Reader(writer.data)
            #expect(try reader.mpint() == expectedMagnitude)
            #expect(reader.isAtEnd)
        }

        // This used to call Data.removeFirst() once per zero, making a hostile
        // mpint quadratic. Keep a large regression case in the ordinary suite.
        var writer = SSHWire.Writer()
        writer.string(Data(repeating: 0, count: 128 * 1024) + Data([1]))
        var reader = SSHWire.Reader(writer.data)
        #expect(try reader.mpint() == Data([1]))
    }

    @Test("all SSH errors have stable, non-secret diagnostic text")
    func errorDescriptions() {
        #expect(SSHError.truncated.description.contains("truncated"))
        #expect(SSHError.badMagic.description.contains("openssh-key-v1"))
        #expect(SSHError.encryptedKey.description.contains("encrypted"))
        #expect(SSHError.unsupportedKeyType("alien").description.contains("alien"))
        #expect(SSHError.malformed("bad field").description.contains("bad field"))
        #expect(SSHError.signFailed("provider error").description.contains("provider error"))
    }
}

@Suite("SSH private key parser — malformed input never crashes")
struct SSHPrivateKeyMalformedTests {
    private func envelope(cipher: String = "none", kdf: String = "none", count: UInt32 = 1,
                          publicBlob: Data = Data(), privateBlob: Data = Data(),
                          trailing: Data = Data()) -> Data {
        var fields = SSHWire.Writer()
        fields.string(cipher)
        fields.string(kdf)
        fields.string(Data())
        fields.uint32(count)
        fields.string(publicBlob)
        fields.string(privateBlob)
        return Data("openssh-key-v1\0".utf8) + fields.data + trailing
    }

    private func privateBlob(type: String, check1: UInt32 = 7, check2: UInt32 = 7,
                             fields append: (inout SSHWire.Writer) -> Void = { _ in }) -> Data {
        var writer = SSHWire.Writer()
        writer.uint32(check1)
        writer.uint32(check2)
        writer.string(type)
        append(&writer)
        writer.string("test")
        for byte in UInt8(1)...UInt8(7) { writer.byte(byte) }
        return writer.data
    }

    private func validEd25519Raw() -> Data {
        let seed = Data((0..<32).map(UInt8.init))
        let publicKey = try! Curve25519.Signing.PrivateKey(rawRepresentation: seed)
            .publicKey.rawRepresentation
        var publicWriter = SSHWire.Writer()
        publicWriter.string("ssh-ed25519")
        publicWriter.string(publicKey)
        return envelope(publicBlob: publicWriter.data,
                        privateBlob: privateBlob(type: "ssh-ed25519") { writer in
            writer.string(publicKey)
            writer.string(seed + publicKey)
        })
    }

    @Test("every prefix before the final required byte throws instead of reading past the blob")
    func everyTruncatedPrefixFails() throws {
        let raw = validEd25519Raw()
        _ = try SSHPrivateKey(opensshRaw: raw)
        for length in 0..<raw.count {
            #expect(throws: (any Error).self) {
                _ = try SSHPrivateKey(opensshRaw: Data(raw.prefix(length)))
            }
        }
    }

    @Test("single-byte corruption across the complete container is total")
    func everySingleByteMutationIsTotal() throws {
        let raw = validEd25519Raw()
        for index in raw.indices {
            var mutated = raw
            mutated[index] ^= 0xa5
            do {
                // Mutations confined to the opaque comment may remain valid;
                // anything accepted must still be a usable, coherent key.
                let key = try SSHPrivateKey(opensshRaw: mutated)
                _ = try key.sign(Data("mutation probe".utf8))
            } catch {
                // Rejection is the expected outcome for structural/key bytes.
            }
        }
    }

    @Test("bad envelope, checkints, key types, and key sizes fail closed")
    func malformedFields() {
        #expect(throws: SSHError.badMagic) { _ = try SSHPrivateKey(opensshRaw: Data("not-a-key".utf8)) }
        #expect(throws: (any Error).self) { _ = try SSHPrivateKey(opensshPEM: Data("%%%".utf8)) }
        #expect(throws: SSHError.encryptedKey) {
            _ = try SSHPrivateKey(opensshRaw: envelope(cipher: "aes256-ctr", kdf: "bcrypt"))
        }
        #expect(throws: (any Error).self) {
            _ = try SSHPrivateKey(opensshRaw: envelope(count: 2))
        }
        #expect(throws: (any Error).self) {
            _ = try SSHPrivateKey(opensshRaw: envelope(
                privateBlob: privateBlob(type: "ssh-ed25519", check1: 1, check2: 2)))
        }
        #expect(throws: SSHError.unsupportedKeyType("ssh-unknown")) {
            _ = try SSHPrivateKey(opensshRaw: envelope(
                privateBlob: privateBlob(type: "ssh-unknown")))
        }
        #expect(throws: (any Error).self) {
            _ = try SSHPrivateKey(opensshRaw: envelope(
                privateBlob: privateBlob(type: "ssh-ed25519") { writer in
                    writer.string(Data(repeating: 1, count: 31))
                    writer.string(Data(repeating: 2, count: 64))
                }))
        }
        #expect(throws: (any Error).self) {
            _ = try SSHPrivateKey(opensshRaw: envelope(
                privateBlob: privateBlob(type: "ecdsa-sha2-nistp256") { writer in
                    writer.string("nistp999")
                    writer.string(Data(repeating: 1, count: 65))
                    writer.mpint(Data([1]))
                }))
        }
        #expect(throws: (any Error).self) {
            _ = try SSHPrivateKey(opensshRaw: envelope(
                privateBlob: privateBlob(type: "ecdsa-sha2-nistp256") { writer in
                    writer.string("nistp384")
                    writer.string(Data(repeating: 1, count: 97))
                    writer.mpint(Data([1]))
                }))
        }
    }

    @Test("oversized and structurally inconsistent key containers fail closed")
    func consistencyAndSizeLimits() throws {
        let oversized = Data(repeating: 0, count: SSHPrivateKey.maxInputBytes + 1)
        #expect(throws: (any Error).self) { _ = try SSHPrivateKey(opensshRaw: oversized) }
        #expect(throws: (any Error).self) { _ = try SSHPrivateKey(opensshPEM: oversized) }

        let valid = validEd25519Raw()
        _ = try SSHPrivateKey(opensshRaw: valid)
        #expect(throws: (any Error).self) {
            _ = try SSHPrivateKey(opensshRaw: valid + Data([0]))
        }

        let seed = Data((0..<32).map(UInt8.init))
        let publicKey = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
            .publicKey.rawRepresentation
        var declared = SSHWire.Writer()
        declared.string("ssh-ed25519")
        declared.string(publicKey)

        #expect(throws: (any Error).self) {
            _ = try SSHPrivateKey(opensshRaw: envelope(
                publicBlob: Data([0]),
                privateBlob: privateBlob(type: "ssh-ed25519") { writer in
                    writer.string(publicKey)
                    writer.string(seed + publicKey)
                }))
        }

        var wrongPublic = publicKey
        wrongPublic[wrongPublic.startIndex] ^= 0xff
        #expect(throws: (any Error).self) {
            _ = try SSHPrivateKey(opensshRaw: envelope(
                publicBlob: declared.data,
                privateBlob: privateBlob(type: "ssh-ed25519") { writer in
                    writer.string(publicKey)
                    writer.string(seed + wrongPublic)
                }))
        }

        var invalidPadding = SSHWire.Writer()
        invalidPadding.uint32(7)
        invalidPadding.uint32(7)
        invalidPadding.string("ssh-ed25519")
        invalidPadding.string(publicKey)
        invalidPadding.string(seed + publicKey)
        invalidPadding.string("test")
        invalidPadding.byte(2)
        #expect(throws: (any Error).self) {
            _ = try SSHPrivateKey(opensshRaw: envelope(
                publicBlob: declared.data, privateBlob: invalidPadding.data))
        }
    }

    @Test("malformed RSA primes are rejected before modulo arithmetic can trap")
    func malformedRSAPrimes() {
        let raw = envelope(privateBlob: privateBlob(type: "ssh-rsa") { writer in
            writer.mpint(Data([3])) // n
            writer.mpint(Data([3])) // e
            writer.mpint(Data([1])) // d
            writer.mpint(Data([1])) // iqmp
            writer.mpint(Data([1])) // p: p-1 == zero, must be rejected
            writer.mpint(Data([2])) // q
        })
        #expect(throws: (any Error).self) { _ = try SSHPrivateKey(opensshRaw: raw) }
    }
}

@Suite("BigUIntLite — RSA setup arithmetic")
struct BigUIntLiteBoundaryTests {
    private func bytes(_ value: UInt64) -> Data {
        var value = value.bigEndian
        return withUnsafeBytes(of: &value) { Data($0) }
    }

    private func uint64(_ bytes: Data) -> UInt64 {
        bytes.reduce(0) { ($0 << 8) | UInt64($1) }
    }

    @Test("mod agrees with native UInt64 over deterministic adversarial inputs")
    func moduloProperty() {
        var state: UInt64 = 0x4d59_5df4_d0f3_3173
        for _ in 0..<2_048 {
            state = state &* 6_364_136_223_846_793_005 &+ 1_442_695_040_888_963_407
            let value = state
            state = state &* 6_364_136_223_846_793_005 &+ 1_442_695_040_888_963_407
            let modulus = state | 1
            let actual = BigUIntLite(bigEndian: bytes(value))
                .mod(BigUIntLite(bigEndian: bytes(modulus))).bigEndianBytes()
            #expect(uint64(actual) == value % modulus)
        }
    }

    @Test("zero, one, limb borrow, and zero modulus are total operations")
    func edgeArithmetic() {
        let zero = BigUIntLite(bigEndian: Data())
        let one = BigUIntLite(bigEndian: Data([1]))
        #expect(zero.minusOneOrZero().isZero)
        #expect(one.minusOneOrZero().isZero)

        let limbBoundary = BigUIntLite(bigEndian: Data([1, 0, 0, 0, 0]))
        #expect(limbBoundary.minusOneOrZero().bigEndianBytes() == Data([0xff, 0xff, 0xff, 0xff]))
        #expect(limbBoundary.mod(zero) == limbBoundary)
        #expect(BigUIntLite(bigEndian: Data([3])).mod(BigUIntLite(bigEndian: Data([7])))
                == BigUIntLite(bigEndian: Data([3])))
    }
}

@Suite("SSH agent — concurrency and frame resource caps")
struct SSHAgentConcurrencyTests {
    private static let ed25519PEM = """
    -----BEGIN OPENSSH PRIVATE KEY-----
    b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
    QyNTUxOQAAACD7h/ZZqiUmzNnzYaRYIrev5Txs+zE2rMN6yA7dS9FKrAAAAJAF/g86Bf4P
    OgAAAAtzc2gtZWQyNTUxOQAAACD7h/ZZqiUmzNnzYaRYIrev5Txs+zE2rMN6yA7dS9FKrA
    AAAEBym//pp6FZ+2w6QefNdl+sIHqX8UoD4q/+8BOE+njHtfuH9lmqJSbM2fNhpFgit6/l
    PGz7MTasw3rIDt1L0UqsAAAABmZpeC1lZAECAwQFBgc=
    -----END OPENSSH PRIVATE KEY-----
    """

    private func keyAndRequest() throws -> (SSHPrivateKey, Data) {
        let key = try SSHPrivateKey(opensshPEM: Data(Self.ed25519PEM.utf8))
        var request = SSHWire.Writer()
        request.byte(13)
        request.string(key.publicKeyBlob)
        request.string(Data("concurrent challenge".utf8))
        request.uint32(0)
        return (key, request.data)
    }

    @Test("the signature budget is atomic under concurrent requests")
    func concurrentBudget() async throws {
        let (_, request) = try keyAndRequest()
        let server = SSHAgentServer(key: try keyAndRequest().0, maxSignatures: 7)
        let successes = await withTaskGroup(of: Bool.self, returning: Int.self) { group in
            for _ in 0..<128 {
                group.addTask { server.handle(request).first == 14 }
            }
            var count = 0
            for await success in group where success { count += 1 }
            return count
        }
        #expect(successes == 7)
        #expect(server.handle(request).first == 5)
    }

    @Test("zero, over-cap, and truncated frames terminate the serve loop without allocation or hang")
    func invalidFrameLengthsTerminate() throws {
        let (key, _) = try keyAndRequest()
        let headers: [(Data, Data)] = [
            (Data([0, 0, 0, 0]), Data()),
            (Data([0, 4, 0, 1]), Data()), // 256 KiB + 1: rejected before body allocation
            (Data([0, 0, 0, 4]), Data([13, 0])), // promised four, peer sends two
        ]

        for (header, partialBody) in headers {
            var pair = [Int32](repeating: -1, count: 2)
            guard socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0 else {
                throw BinaryTestError.posix(errno)
            }
            var noSigPipe: Int32 = 1
            _ = setsockopt(pair[1], SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe,
                           socklen_t(MemoryLayout<Int32>.size))
            let serverFD = pair[0]
            let server = SSHAgentServer(key: key)
            let finished = DispatchSemaphore(value: 0)
            let thread = Thread {
                server.serve(fd: serverFD)
                finished.signal()
            }
            thread.start()
            var input = header
            input.append(partialBody)
            _ = input.withUnsafeBytes {
                Darwin.write(pair[1], $0.baseAddress, $0.count)
            }
            _ = shutdown(pair[1], SHUT_WR)
            #expect(finished.wait(timeout: .now() + 1) == .success)
            Darwin.close(pair[0])
            Darwin.close(pair[1])
        }
    }
}

@Suite("Numeric conversion crash guards")
struct NumericCrashGuardTests {
    @Test("agent-supplied numeric values cannot trap Int conversion")
    func engineIntegerArguments() {
        #expect(Engine.intArg(.double(.infinity)) == 0)
        #expect(Engine.intArg(.double(-Double.infinity)) == 0)
        #expect(Engine.intArg(.double(.nan)) == 0)
        #expect(Engine.intArg(.double(1.0e100)) == 0)
        #expect(Engine.intArg(.double(-1.0e100)) == 0)
        #expect(Engine.intArg(.double(Double(Int.max))) == 0)
        #expect(Engine.intArg(.double(Double(Int.min))) == Int.min)
        #expect(Engine.intArg(.string("999999999999999999999999999999")) == 0)
        #expect(Engine.intArg(.double(42.9)) == 42)
        #expect(Engine.intArg(.int(Int.max)) == Int.max)
    }

    @Test("negative and extreme PIDs are inert for watch and unwatch")
    func procWatcherRejectsInvalidPIDs() throws {
        let callback = LockedCounter()
        let watcher = try ProcWatcher { _ in callback.increment() }
        watcher.watch(pid: 0, startedAt: 0, key: "zero")
        watcher.watch(pid: -1, startedAt: 0, key: "negative")
        watcher.watch(pid: Int.min, startedAt: 0, key: "minimum")
        watcher.unwatch(pid: -1)
        watcher.unwatch(pid: Int.min)
        watcher.close()
        #expect(callback.value == 0)
    }
}

private final class LockedCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    func increment() { lock.withLock { count += 1 } }
    var value: Int { lock.withLock { count } }
}
