import Darwin
import Foundation
import Testing
@testable import SallyportKit

@Suite("Bounded trust-state file reads")
struct BoundedFileReaderTests {
    @Test("a direct regular file at the exact cap is read")
    func exactCap() throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let file = fixture.root.appendingPathComponent("state")
        let expected = Data(repeating: 0x5a, count: 64)
        try expected.write(to: file)
        #expect(try BoundedFileReader.read(file, maxBytes: 64) == expected)
    }

    @Test("oversized and invalid-limit reads fail before allocation")
    func sizeLimits() throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let file = fixture.root.appendingPathComponent("state")
        try Data(repeating: 1, count: 65).write(to: file)
        #expect(throws: BoundedFileReader.ReadError.tooLarge(65)) {
            _ = try BoundedFileReader.read(file, maxBytes: 64)
        }
        #expect(throws: BoundedFileReader.ReadError.invalidLimit) {
            _ = try BoundedFileReader.read(file, maxBytes: -1)
        }
    }

    @Test("symlinks, hardlinks, directories, and FIFOs are refused without blocking")
    func hostileFilesystemObjects() throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let target = fixture.root.appendingPathComponent("target")
        try Data("secret".utf8).write(to: target)

        let symlink = fixture.root.appendingPathComponent("link")
        try FileManager.default.createSymbolicLink(at: symlink, withDestinationURL: target)
        #expect(throws: (any Error).self) {
            _ = try BoundedFileReader.read(symlink, maxBytes: 64)
        }

        let hardlink = fixture.root.appendingPathComponent("hardlink")
        #expect(Darwin.link(target.path, hardlink.path) == 0)
        #expect(throws: BoundedFileReader.ReadError.multipleLinks) {
            _ = try BoundedFileReader.read(target, maxBytes: 64)
        }

        #expect(throws: BoundedFileReader.ReadError.notRegularFile) {
            _ = try BoundedFileReader.read(fixture.root, maxBytes: 64)
        }

        let fifo = fixture.root.appendingPathComponent("pipe")
        #expect(mkfifo(fifo.path, 0o600) == 0)
        let started = ContinuousClock.now
        #expect(throws: BoundedFileReader.ReadError.notRegularFile) {
            _ = try BoundedFileReader.read(fifo, maxBytes: 64)
        }
        #expect(ContinuousClock.now - started < .seconds(1))
    }

    private struct Fixture {
        let root: URL

        init() throws {
            root = URL(fileURLWithPath: "/tmp/sallyport-bounded-\(UUID().uuidString)",
                       isDirectory: true)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        }

        func remove() { try? FileManager.default.removeItem(at: root) }
    }
}
