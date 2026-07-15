import Foundation

/// A small FIFO async mutex for configuration mutations. NSLock protects each
/// in-memory snapshot, but it cannot span an `await`; without this gate two vault
/// writes can finish out of order and persist an older snapshot last.
actor AsyncMutationGate {
    private var held = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func withLock<T: Sendable>(
        _ operation: @Sendable () async throws -> T
    ) async rethrows -> T {
        await acquire()
        do {
            let value = try await operation()
            release()
            return value
        } catch {
            release()
            throw error
        }
    }

    private func acquire() async {
        if !held {
            held = true
            return
        }
        await withCheckedContinuation { continuation in
            waiters.append(continuation)
        }
    }

    private func release() {
        if waiters.isEmpty {
            held = false
        } else {
            waiters.removeFirst().resume()
        }
    }
}
