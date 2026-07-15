import Foundation
import LocalAuthentication
import SallyportKit

enum AuthOutcome: Sendable, Equatable {
    case approved
    case denied
}

/// Biometric authentication isolated to the main actor for `LAContext` safety.
@MainActor
protocol Authenticator: AnyObject {
    /// Prompts with an already-localized reason supplied by the caller.
    func authenticate(reason: String) async -> AuthOutcome
    /// Successful context available to the next Secure Enclave operation.
    var lastAuthenticatedContext: LAContext? { get }
    var isBiometric: Bool { get }
}

/// Touch ID through LocalAuthentication.
@MainActor
final class BiometricAuthenticator: Authenticator {
    private(set) var lastAuthenticatedContext: LAContext?
    let isBiometric = true

    static func isAvailable() -> Bool {
        var error: NSError?
        return LAContext().canEvaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics, error: &error)
    }

    func authenticate(reason: String) async -> AuthOutcome {
        let context = LAContext()
        context.localizedFallbackTitle = ""   // biometrics only, no password fallback UI
        var error: NSError?
        guard context.canEvaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            return .denied
        }
        let ok: Bool = await withCheckedContinuation { continuation in
            context.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics, localizedReason: reason
            ) { success, _ in
                continuation.resume(returning: success)
            }
        }
        if ok { lastAuthenticatedContext = context }
        return ok ? .approved : .denied
    }
}

/// Development authenticator that approves without biometrics.
@MainActor
final class DevAuthenticator: Authenticator {
    let lastAuthenticatedContext: LAContext? = nil
    let isBiometric = false

    func authenticate(reason: String) async -> AuthOutcome {
        // Match the asynchronous transition used by the biometric authenticator.
        try? await Task.sleep(for: .milliseconds(250))
        return .approved
    }
}

/// Debug-only headless authenticator. Skips Touch ID for integration tests.
@MainActor
final class AutoApproveAuthenticator: Authenticator {
    // Headless mode has no authenticated LocalAuthentication context.
    let lastAuthenticatedContext: LAContext? = nil
    let isBiometric = false
    func authenticate(reason: String) async -> AuthOutcome { .approved }
}

/// Rejects biometric operations when Touch ID is unavailable in release builds.
@MainActor
final class DenyingAuthenticator: Authenticator {
    let lastAuthenticatedContext: LAContext? = nil
    let isBiometric = false
    func authenticate(reason: String) async -> AuthOutcome { .denied }
}

enum AuthenticatorFactory {
    @MainActor
    static func make() -> any Authenticator {
        if BiometricAuthenticator.isAvailable() { return BiometricAuthenticator() }
        // Debug builds support previews without Touch ID. Release builds reject.
        #if DEBUG
        return DevAuthenticator()
        #else
        return DenyingAuthenticator()
        #endif
    }
}
