import Foundation
import Security   // only for the OSStatus constants (errSecSuccess/errSecIO); no SecItem calls

/// Private-file fallback for unsigned debug builds. Secure Enclave keys do not
/// use this store. Files are restricted to mode 0600 and replaced atomically.
public enum Keychain {

    public static let service = "dev.sallyport.mac"

    /// `~/Library/Application Support/dev.sallyport.mac`, created 0700 on demand.
    private static func storeDir() -> URL? {
        guard let base = try? FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask,
            appropriateFor: nil, create: true) else { return nil }
        let dir = base.appendingPathComponent(service, isDirectory: true)
        do {
            try SecureTrustFile.prepareDirectory(dir)
        } catch {
            return nil
        }
        return dir
    }

    /// The 0700 App Support directory blobs live in, exposed so sibling stores
    /// (e.g. the sealed-identity `IdentityGate`) share the same location and
    /// convention instead of hardcoding their own path. Nil if it can't be made.
    public static func storeDirectory() -> URL? { storeDir() }

    private static func fileStore() -> KeychainFileStore? {
        guard let directory = storeDir() else { return nil }
        return KeychainFileStore(directory: directory)
    }

    /// Store (or replace) `data` under `account`. Returns `errSecSuccess` on
    /// success and `errSecIO` on failure.
    @discardableResult
    public static func set(_ data: Data, account: String) -> OSStatus {
        fileStore()?.set(data, account: account) ?? errSecIO
    }

    /// Load the blob stored under `account`, or nil if absent / unreadable.
    public static func get(account: String) -> Data? {
        fileStore()?.get(account: account)
    }

    /// Stores, reads, and deletes a diagnostic blob.
    public static func roundTrip() -> (add: OSStatus, readBack: Bool) {
        let account = "diag.roundtrip"
        let payload = Data("sallyport-diag".utf8)
        let add = set(payload, account: account)
        let got = get(account: account)
        delete(account: account)
        return (add, got == payload)
    }

    /// Removes the blob under `account`.
    @discardableResult
    public static func delete(account: String) -> OSStatus {
        fileStore()?.delete(account: account) ?? errSecIO
    }
}

/// File-backed blob store used by `Keychain` and tests.
struct KeychainFileStore: Sendable {
    static let maxBlobBytes = 1 * 1024 * 1024
    let directory: URL

    private func fileURL(account: String) -> URL? {
        guard !account.isEmpty, account.utf8.count <= 200,
              account != ".", account != "..",
              account.unicodeScalars.allSatisfy({ scalar in
                  switch scalar.value {
                  case 45, 46, 48...57, 65...90, 95, 97...122: return true
                  default: return false
                  }
              }) else { return nil }
        return directory.appendingPathComponent(account + ".blob", isDirectory: false)
    }

    @discardableResult
    func set(_ data: Data, account: String) -> OSStatus {
        guard let url = fileURL(account: account), data.count <= Self.maxBlobBytes else {
            return errSecIO
        }
        do {
            try SecureTrustFile.write(data, to: url, maxBytes: Self.maxBlobBytes)
            return errSecSuccess
        } catch {
            return errSecIO
        }
    }

    func get(account: String) -> Data? {
        guard let url = fileURL(account: account) else { return nil }
        return try? SecureTrustFile.read(url, maxBytes: Self.maxBlobBytes)
    }

    @discardableResult
    func delete(account: String) -> OSStatus {
        guard let url = fileURL(account: account) else { return errSecIO }
        do {
            try SecureTrustFile.remove(url, maxBytes: Self.maxBlobBytes)
            return errSecSuccess
        } catch SecureTrustFile.FileError.notFound {
            return errSecItemNotFound
        } catch {
            return errSecIO
        }
    }
}
