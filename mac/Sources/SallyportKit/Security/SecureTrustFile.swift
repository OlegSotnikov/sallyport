import Darwin
import Foundation

/// Descriptor-pinned storage that validates file type, ownership, links, and permissions.
public enum SecureTrustFile {
    public enum FileError: Error, Equatable, Sendable {
        case invalidPath
        case invalidLimit
        case notFound
        case unsafeParent
        case unsafeFile
        case tooLarge(Int64)
        case system(Int32)
    }

    private struct PinnedParent {
        let fd: Int32
        let path: String
        let device: dev_t
        let inode: ino_t
    }

    /// Create (if needed), own, and restrict a private directory to 0700.
    /// The final component must be a directory, not a symlink.
    public static func prepareDirectory(_ url: URL) throws {
        let sentinel = url.appendingPathComponent(".sallyport-directory-check", isDirectory: false)
        let parent = try openParent(for: sentinel, create: true)
        defer { Darwin.close(parent.fd) }
        try validate(parent)
    }

    /// Atomically replace a private regular file and durably commit the rename.
    public static func write(_ data: Data, to url: URL, maxBytes: Int) throws {
        try writeImpl(data, to: url, maxBytes: maxBytes, beforeRename: nil)
    }

    /// Read one immutable snapshot without following links or trusting a path
    /// after it has been opened.
    public static func read(_ url: URL, maxBytes: Int) throws -> Data {
        guard maxBytes >= 0 else { throw FileError.invalidLimit }
        let (name, _) = try validatedPath(url)
        let parent = try openParent(for: url, create: false)
        defer { Darwin.close(parent.fd) }

        let fd = name.withCString {
            Darwin.openat(parent.fd, $0,
                          O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        }
        guard fd >= 0 else {
            if errno == ENOENT { throw FileError.notFound }
            if errno == ELOOP { throw FileError.unsafeFile }
            throw FileError.system(errno)
        }
        defer { Darwin.close(fd) }

        let before = try inspectFile(fd: fd, maxBytes: maxBytes)
        guard let count = Int(exactly: before.st_size) else {
            throw FileError.tooLarge(Int64(before.st_size))
        }
        var data = Data(count: count)
        if count > 0 {
            try data.withUnsafeMutableBytes { raw in
                guard let base = raw.baseAddress else { throw FileError.system(EIO) }
                var offset = 0
                while offset < count {
                    let n = Darwin.read(fd, base.advanced(by: offset), count - offset)
                    if n < 0, errno == EINTR { continue }
                    guard n > 0 else { throw FileError.system(n < 0 ? errno : EIO) }
                    offset += n
                }
            }
        }

        let after = try inspectFile(fd: fd, maxBytes: maxBytes)
        guard sameSnapshot(before, after) else { throw FileError.unsafeFile }
        try validateEntry(name: name, in: parent, expected: after)
        try validate(parent)
        return data
    }

    /// True only for a current-user-owned, single-link, 0600 regular file.
    public static func exists(_ url: URL, maxBytes: Int) -> Bool {
        guard maxBytes >= 0, let (name, _) = try? validatedPath(url),
              let parent = try? openParent(for: url, create: false) else { return false }
        defer { Darwin.close(parent.fd) }
        let fd = name.withCString {
            Darwin.openat(parent.fd, $0,
                          O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        }
        guard fd >= 0 else { return false }
        defer { Darwin.close(fd) }
        guard let info = try? inspectFile(fd: fd, maxBytes: maxBytes),
              (try? validateEntry(name: name, in: parent, expected: info)) != nil,
              (try? validate(parent)) != nil else { return false }
        return true
    }

    /// Removes a validated file. Unsafe path entries are left in place.
    public static func remove(_ url: URL, maxBytes: Int) throws {
        guard maxBytes >= 0 else { throw FileError.invalidLimit }
        let (name, _) = try validatedPath(url)
        let parent = try openParent(for: url, create: false)
        defer { Darwin.close(parent.fd) }

        let fd = name.withCString {
            Darwin.openat(parent.fd, $0,
                          O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        }
        guard fd >= 0 else {
            if errno == ENOENT { throw FileError.notFound }
            if errno == ELOOP { throw FileError.unsafeFile }
            throw FileError.system(errno)
        }
        defer { Darwin.close(fd) }
        let info = try inspectFile(fd: fd, maxBytes: maxBytes)
        try validateEntry(name: name, in: parent, expected: info)
        guard name.withCString({ Darwin.unlinkat(parent.fd, $0, 0) }) == 0 else {
            throw FileError.system(errno)
        }
        guard Darwin.fsync(parent.fd) == 0 else { throw FileError.system(errno) }
        try validate(parent)
    }

    // MARK: - Test seam

    /// Lets tests deterministically interrupt the transaction before rename or
    /// replace the live pathname while the pinned directory remains open.
    static func writeForTesting(_ data: Data, to url: URL, maxBytes: Int,
                                beforeRename: @escaping () throws -> Void) throws {
        try writeImpl(data, to: url, maxBytes: maxBytes, beforeRename: beforeRename)
    }

    // MARK: - Pinned path operations

    private static func writeImpl(_ data: Data, to url: URL, maxBytes: Int,
                                  beforeRename: (() throws -> Void)?) throws {
        guard maxBytes >= 0 else { throw FileError.invalidLimit }
        guard data.count <= maxBytes else { throw FileError.tooLarge(Int64(data.count)) }
        let (name, _) = try validatedPath(url)
        let parent = try openParent(for: url, create: true)
        defer { Darwin.close(parent.fd) }

        // Refuse a pre-planted redirect or alias. A later race cannot redirect
        // the write: renameat replaces the directory entry without following it.
        try validateExistingEntryIfPresent(name: name, in: parent, maxBytes: maxBytes)

        let temporaryName = ".sallyport-\(UUID().uuidString).tmp"
        let fd = temporaryName.withCString {
            Darwin.openat(parent.fd, $0,
                          O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                          mode_t(0o600))
        }
        guard fd >= 0 else { throw FileError.system(errno) }
        var keepTemporary = true
        defer {
            Darwin.close(fd)
            if keepTemporary {
                _ = temporaryName.withCString { Darwin.unlinkat(parent.fd, $0, 0) }
            }
        }
        guard Darwin.fchmod(fd, mode_t(0o600)) == 0 else { throw FileError.system(errno) }

        try data.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return }
            var offset = 0
            while offset < raw.count {
                let n = Darwin.write(fd, base.advanced(by: offset), raw.count - offset)
                if n < 0, errno == EINTR { continue }
                guard n > 0 else { throw FileError.system(n < 0 ? errno : EIO) }
                offset += n
            }
        }
        try durableFileSync(fd)
        let temporaryInfo = try inspectFile(fd: fd, maxBytes: maxBytes)

        try beforeRename?()

        let renameResult = temporaryName.withCString { source in
            name.withCString { destination in
                Darwin.renameat(parent.fd, source, parent.fd, destination)
            }
        }
        guard renameResult == 0 else { throw FileError.system(errno) }
        keepTemporary = false

        try validateEntry(name: name, in: parent, expected: temporaryInfo)
        guard Darwin.fsync(parent.fd) == 0 else { throw FileError.system(errno) }
        try validate(parent)
    }

    private static func validatedPath(_ url: URL) throws -> (name: String, parent: String) {
        guard url.isFileURL else { throw FileError.invalidPath }
        let path = url.path
        let name = url.lastPathComponent
        let parent = url.deletingLastPathComponent().path
        guard path == url.standardizedFileURL.path,
              path.hasPrefix("/"), !path.utf8.contains(0), !parent.utf8.contains(0),
              !name.isEmpty, name != ".", name != "..", !name.contains("/") else {
            throw FileError.invalidPath
        }
        return (name, parent)
    }

    private static func openParent(for url: URL, create: Bool) throws -> PinnedParent {
        let (_, parentPath) = try validatedPath(url)
        if create {
            do {
                try FileManager.default.createDirectory(
                    at: url.deletingLastPathComponent(),
                    withIntermediateDirectories: true,
                    attributes: [.posixPermissions: 0o700])
            } catch {
                throw FileError.system((error as NSError).code == NSFileWriteNoPermissionError ? EACCES : EIO)
            }
        }

        // lstat before open rejects the immediate parent as a symlink; openat
        // operations then remain tied to the resulting inode for the transaction.
        var pathInfo = stat()
        guard parentPath.withCString({ Darwin.lstat($0, &pathInfo) }) == 0 else {
            if errno == ENOENT { throw FileError.notFound }
            throw FileError.system(errno)
        }
        guard (pathInfo.st_mode & S_IFMT) == S_IFDIR else { throw FileError.unsafeParent }

        let fd = parentPath.withCString {
            Darwin.open($0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        }
        guard fd >= 0 else {
            if errno == ELOOP || errno == ENOTDIR { throw FileError.unsafeParent }
            throw FileError.system(errno)
        }
        var keep = true
        defer { if keep { Darwin.close(fd) } }

        var info = stat()
        guard Darwin.fstat(fd, &info) == 0 else { throw FileError.system(errno) }
        guard (info.st_mode & S_IFMT) == S_IFDIR,
              info.st_uid == geteuid(),
              info.st_dev == pathInfo.st_dev,
              info.st_ino == pathInfo.st_ino else {
            throw FileError.unsafeParent
        }
        // Existing private directories from older builds may be 0755 because
        // createDirectory's attributes do not alter an existing inode. Tighten
        // through the descriptor before any trust-state operation.
        guard Darwin.fchmod(fd, mode_t(0o700)) == 0 else { throw FileError.system(errno) }

        let parent = PinnedParent(fd: fd, path: parentPath,
                                  device: info.st_dev, inode: info.st_ino)
        try validate(parent)
        keep = false
        return parent
    }

    private static func validate(_ parent: PinnedParent) throws {
        var pinned = stat()
        var path = stat()
        guard Darwin.fstat(parent.fd, &pinned) == 0 else { throw FileError.system(errno) }
        guard parent.path.withCString({ Darwin.lstat($0, &path) }) == 0 else {
            throw FileError.unsafeParent
        }
        guard (pinned.st_mode & S_IFMT) == S_IFDIR,
              pinned.st_uid == geteuid(),
              (pinned.st_mode & 0o7777) == 0o700,
              pinned.st_dev == parent.device, pinned.st_ino == parent.inode,
              path.st_dev == parent.device, path.st_ino == parent.inode,
              (path.st_mode & S_IFMT) == S_IFDIR else {
            throw FileError.unsafeParent
        }
        try rejectExtendedACL(fd: parent.fd, error: .unsafeParent)
    }

    private static func inspectFile(fd: Int32, maxBytes: Int) throws -> stat {
        var info = stat()
        guard Darwin.fstat(fd, &info) == 0 else { throw FileError.system(errno) }
        guard (info.st_mode & S_IFMT) == S_IFREG,
              info.st_nlink == 1,
              info.st_uid == geteuid(),
              (info.st_mode & 0o7777) == 0o600 else {
            throw FileError.unsafeFile
        }
        try rejectExtendedACL(fd: fd, error: .unsafeFile)
        guard info.st_size >= 0, info.st_size <= off_t(maxBytes) else {
            throw FileError.tooLarge(Int64(info.st_size))
        }
        return info
    }

    private static func validateExistingEntryIfPresent(name: String, in parent: PinnedParent,
                                                        maxBytes: Int) throws {
        var info = stat()
        let rc = name.withCString {
            Darwin.fstatat(parent.fd, $0, &info, AT_SYMLINK_NOFOLLOW)
        }
        if rc != 0 {
            if errno == ENOENT { return }
            throw FileError.system(errno)
        }
        guard (info.st_mode & S_IFMT) == S_IFREG,
              info.st_nlink == 1,
              info.st_uid == geteuid(),
              (info.st_mode & 0o7777) == 0o600 else {
            throw FileError.unsafeFile
        }
        guard info.st_size >= 0, info.st_size <= off_t(maxBytes) else {
            throw FileError.tooLarge(Int64(info.st_size))
        }
    }

    private static func validateEntry(name: String, in parent: PinnedParent,
                                      expected: stat) throws {
        var entry = stat()
        guard name.withCString({
            Darwin.fstatat(parent.fd, $0, &entry, AT_SYMLINK_NOFOLLOW)
        }) == 0 else {
            throw FileError.unsafeFile
        }
        guard entry.st_dev == expected.st_dev,
              entry.st_ino == expected.st_ino,
              (entry.st_mode & S_IFMT) == S_IFREG,
              entry.st_nlink == 1,
              entry.st_uid == geteuid(),
              (entry.st_mode & 0o7777) == 0o600 else {
            throw FileError.unsafeFile
        }
    }

    private static func sameSnapshot(_ lhs: stat, _ rhs: stat) -> Bool {
        lhs.st_dev == rhs.st_dev && lhs.st_ino == rhs.st_ino &&
        lhs.st_mode == rhs.st_mode && lhs.st_nlink == rhs.st_nlink &&
        lhs.st_uid == rhs.st_uid && lhs.st_size == rhs.st_size &&
        lhs.st_mtimespec.tv_sec == rhs.st_mtimespec.tv_sec &&
        lhs.st_mtimespec.tv_nsec == rhs.st_mtimespec.tv_nsec &&
        lhs.st_ctimespec.tv_sec == rhs.st_ctimespec.tv_sec &&
        lhs.st_ctimespec.tv_nsec == rhs.st_ctimespec.tv_nsec
    }

    private static func durableFileSync(_ fd: Int32) throws {
        // F_FULLFSYNC adds the storage-device cache flush that plain fsync does
        // not promise on macOS. Fall back only on filesystems/devices that do not
        // implement it; every path still receives at least fsync durability.
        if Darwin.fcntl(fd, F_FULLFSYNC) == 0 { return }
        let fullSyncError = errno
        guard fullSyncError == EINVAL || fullSyncError == ENOTSUP || fullSyncError == ENOTTY else {
            throw FileError.system(fullSyncError)
        }
        guard Darwin.fsync(fd) == 0 else { throw FileError.system(errno) }
    }

    /// POSIX mode bits do not account for macOS extended ACL entries. A trust
    /// root with an inherited allow-entry can be readable despite 0600/0700, so
    /// reject it rather than presenting the mode as stronger than it is.
    private static func rejectExtendedACL(fd: Int32, error: FileError) throws {
        errno = 0
        guard let acl = Darwin.acl_get_fd_np(fd, ACL_TYPE_EXTENDED) else {
            if errno == ENOENT || errno == ENOTSUP { return }
            throw FileError.system(errno)
        }
        defer { Darwin.acl_free(UnsafeMutableRawPointer(acl)) }
        var entry: acl_entry_t?
        errno = 0
        if Darwin.acl_get_entry(acl, Int32(ACL_FIRST_ENTRY.rawValue), &entry) == 0 {
            throw error
        }
        guard errno == EINVAL else { throw FileError.system(errno) }
    }
}
