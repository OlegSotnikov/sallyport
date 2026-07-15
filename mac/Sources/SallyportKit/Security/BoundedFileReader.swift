import Darwin
import Foundation

/// Reads bounded regular files without following links.
public enum BoundedFileReader {
    public enum ReadError: Error, Equatable, Sendable {
        case invalidLimit
        case open(Int32)
        case stat(Int32)
        case notRegularFile
        case multipleLinks
        case tooLarge(Int64)
        case changedDuringRead
        case read(Int32)
    }

    public static func read(_ url: URL, maxBytes: Int) throws -> Data {
        guard maxBytes >= 0 else { throw ReadError.invalidLimit }
        let fd = url.path.withCString {
            Darwin.open($0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
        }
        guard fd >= 0 else { throw ReadError.open(errno) }
        defer { Darwin.close(fd) }

        var before = stat()
        guard Darwin.fstat(fd, &before) == 0 else { throw ReadError.stat(errno) }
        guard (before.st_mode & S_IFMT) == S_IFREG else { throw ReadError.notRegularFile }
        guard before.st_nlink == 1 else { throw ReadError.multipleLinks }
        guard before.st_size >= 0,
              before.st_size <= off_t(maxBytes),
              let count = Int(exactly: before.st_size) else {
            throw ReadError.tooLarge(Int64(before.st_size))
        }

        var data = Data(count: count)
        if count > 0 {
            try data.withUnsafeMutableBytes { raw in
                guard let base = raw.baseAddress else { throw ReadError.read(EIO) }
                var offset = 0
                while offset < count {
                    let result = Darwin.read(fd, base.advanced(by: offset), count - offset)
                    if result < 0, errno == EINTR { continue }
                    guard result > 0 else {
                        throw ReadError.read(result < 0 ? errno : EIO)
                    }
                    offset += result
                }
            }
        }

        var after = stat()
        guard Darwin.fstat(fd, &after) == 0 else { throw ReadError.stat(errno) }
        guard after.st_dev == before.st_dev,
              after.st_ino == before.st_ino,
              after.st_nlink == 1,
              after.st_size == before.st_size,
              after.st_mtimespec.tv_sec == before.st_mtimespec.tv_sec,
              after.st_mtimespec.tv_nsec == before.st_mtimespec.tv_nsec else {
            throw ReadError.changedDuringRead
        }
        return data
    }
}
