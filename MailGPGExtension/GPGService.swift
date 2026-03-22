// GPGService.swift
// MailGPGExtension (extension only)

import Foundation

// MARK: - HostAppReachability

/// Thread-safe shared state tracking whether the GPG host app is reachable.
/// `nil` = not yet checked, `true` = confirmed, `false` = unreachable.
/// Updated by GPGService after ping attempts and connection changes;
/// read by MessageSecurityHandler to drive the compose button indicator.
final class HostAppReachability: @unchecked Sendable {
    static let shared = HostAppReachability()
    private let lock = NSLock()
    private var _isAvailable: Bool?
    private var _isChecking = false

    var isAvailable: Bool? {
        get { lock.lock(); defer { lock.unlock() }; return _isAvailable }
        set { lock.lock(); defer { lock.unlock() }; _isAvailable = newValue; _isChecking = false }
    }

    /// Atomically claim the "checking" slot. Returns `true` if this caller
    /// should perform the ping; `false` if another caller is already doing it.
    func beginCheckIfNeeded() -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard _isAvailable == nil, !_isChecking else { return false }
        _isChecking = true
        return true
    }
}

// MARK: - GPGService

/// The public API surface for GPG operations inside the Mail extension.
///
/// All methods are `async throws` — callers just `await` them like any
/// other async Swift call. Internally this wraps the XPC callback protocol.
///
/// ## Usage
///     let signed = try await GPGService.shared.sign(data: body, signerKeyID: keyID)
actor GPGService {

    static let shared = GPGService()

    private let connection = GPGServiceConnection()

    private init() {
        // Permanently wire connection availability changes to HostAppReachability.
        // true  = connect() called optimistically → nil (re-checking, not confirmed yet)
        // false = connection failed / host app quit → false (confirmed unavailable)
        connection.onAvailabilityChanged = { available in
            HostAppReachability.shared.isAvailable = available ? nil : false
        }
    }

    // MARK: - Diagnostics

    /// Calls the host app and returns its GPG version string.
    /// A successful result confirms the full XPC round-trip is working.
    func ping() async throws -> String {
        let proxy = try connection.proxy()

        // Save the existing availability callback so we can restore it after.
        let savedHandler = connection.onAvailabilityChanged

        // When XPC drops an in-flight reply block (connection invalidated before
        // the host app replies), withCheckedThrowingContinuation leaks its
        // continuation. Fix: hook into onAvailabilityChanged so that if the
        // connection dies before the reply arrives, we resume with an error.
        // OneShotRelay ensures only one resume regardless of which path fires first.
        let result = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<String, Error>) in
            let relay = OneShotRelay(continuation)

            connection.onAvailabilityChanged = { [savedHandler] available in
                savedHandler?(available)
                if !available {
                    relay.resume(throwing: GPGXPCError.make(.hostAppNotRunning,
                        message: "MailGPG host app is not running. Please open it to enable GPG operations."))
                }
            }

            proxy.ping { version, error in
                if let error { relay.resume(throwing: error); return }
                relay.resume(returning: version ?? "(no version returned)")
            }
        }

        // Back on the actor's executor — restore the permanent handler and
        // mark the host app as confirmed available.
        connection.onAvailabilityChanged = savedHandler
        HostAppReachability.shared.isAvailable = true
        return result
    }

    // MARK: - Outgoing

    func sign(data: Data, signerKeyID: String) async throws -> Data {
        let proxy = try connection.proxy()
        return try await withCheckedThrowingContinuation { continuation in
            proxy.sign(data: data, signerKeyID: signerKeyID) { result, error in
                continuation.resume(with: result, error: error)
            }
        }
    }

    func encrypt(data: Data, recipientFingerprints: [String]) async throws -> Data {
        let proxy = try connection.proxy()
        return try await withCheckedThrowingContinuation { continuation in
            proxy.encrypt(data: data, recipientFingerprints: recipientFingerprints) { result, error in
                continuation.resume(with: result, error: error)
            }
        }
    }

    func signAndEncrypt(data: Data, signerKeyID: String,
                        recipientFingerprints: [String]) async throws -> Data {
        let proxy = try connection.proxy()
        return try await withCheckedThrowingContinuation { continuation in
            proxy.signAndEncrypt(data: data, signerKeyID: signerKeyID,
                                 recipientFingerprints: recipientFingerprints) { result, error in
                continuation.resume(with: result, error: error)
            }
        }
    }

    // MARK: - Incoming

    func decrypt(data: Data) async throws -> (plaintext: Data, status: SecurityStatus) {
        let proxy = try connection.proxy()
        return try await withCheckedThrowingContinuation { continuation in
            proxy.decrypt(data: data) { plaintextData, statusJSON, error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                // Both values must be present on success.
                guard let plaintextData, let statusJSON else {
                    continuation.resume(throwing: GPGXPCError.make(.encodingFailed))
                    return
                }
                do {
                    let status = try xpcDecode(SecurityStatus.self, from: statusJSON)
                    continuation.resume(returning: (plaintextData, status))
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    func verify(data: Data, signature: Data) async throws -> SecurityStatus {
        let proxy = try connection.proxy()
        return try await withCheckedThrowingContinuation { continuation in
            proxy.verify(data: data, signature: signature) { statusJSON, error in
                if let error { continuation.resume(throwing: error); return }
                guard let statusJSON else {
                    continuation.resume(throwing: GPGXPCError.make(.encodingFailed))
                    return
                }
                continuation.resume(with: statusJSON, as: SecurityStatus.self)
            }
        }
    }

    // MARK: - Key management

    func lookupKey(email: String) async throws -> KeyInfo? {
        let proxy = try connection.proxy()
        return try await withCheckedThrowingContinuation { continuation in
            proxy.lookupKey(email: email) { keyInfoJSON, error in
                if let error { continuation.resume(throwing: error); return }
                // nil data with no error means the key simply doesn't exist.
                guard let keyInfoJSON else {
                    continuation.resume(returning: Optional<KeyInfo>.none)
                    return
                }
                do {
                    continuation.resume(returning: try xpcDecode(KeyInfo.self, from: keyInfoJSON))
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    func listSecretKeys() async throws -> [KeyInfo] {
        let proxy = try connection.proxy()
        return try await withCheckedThrowingContinuation { continuation in
            proxy.listSecretKeys { keyListJSON, error in
                if let error { continuation.resume(throwing: error); return }
                guard let keyListJSON else {
                    continuation.resume(returning: [])
                    return
                }
                continuation.resume(with: keyListJSON, as: [KeyInfo].self)
            }
        }
    }

    func importKey(armoredKey: String) async throws -> KeyInfo {
        let proxy = try connection.proxy()
        return try await withCheckedThrowingContinuation { continuation in
            proxy.importKey(armoredKey: armoredKey) { keyInfoJSON, error in
                if let error { continuation.resume(throwing: error); return }
                guard let keyInfoJSON else {
                    continuation.resume(throwing: GPGXPCError.make(.encodingFailed))
                    return
                }
                continuation.resume(with: keyInfoJSON, as: KeyInfo.self)
            }
        }
    }

    func listPublicKeys() async throws -> [KeyInfo] {
        let proxy = try connection.proxy()
        return try await withCheckedThrowingContinuation { continuation in
            proxy.listPublicKeys { keyListJSON, error in
                if let error { continuation.resume(throwing: error); return }
                guard let keyListJSON else {
                    continuation.resume(returning: [])
                    return
                }
                continuation.resume(with: keyListJSON, as: [KeyInfo].self)
            }
        }
    }

    func deleteKey(fingerprint: String) async throws {
        let proxy = try connection.proxy()
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            proxy.deleteKey(fingerprint: fingerprint) { error in
                if let error { continuation.resume(throwing: error); return }
                continuation.resume()
            }
        }
    }

    func setTrust(fingerprint: String, level: TrustLevel) async throws {
        let proxy = try connection.proxy()
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            proxy.setTrust(fingerprint: fingerprint, level: level.rawValue) { error in
                if let error { continuation.resume(throwing: error); return }
                continuation.resume()
            }
        }
    }

    // MARK: - Default signing key (UserDefaults, no XPC needed)

    private static let defaults = UserDefaults(suiteName: "group.com.mahaupt.mailgpg")

    func getDefaultSigningKey() -> String? {
        Self.defaults?.string(forKey: "defaultSigningKeyFingerprint")
    }

    func setDefaultSigningKey(_ fingerprint: String?) {
        Self.defaults?.set(fingerprint, forKey: "defaultSigningKeyFingerprint")
    }
}

// MARK: - Continuation helpers

/// Makes resuming a continuation from an XPC reply block more concise.
private extension CheckedContinuation where T == Data, E == Error {
    func resume(with result: Data?, error: Error?) {
        if let error { resume(throwing: error); return }
        guard let result else { resume(throwing: GPGXPCError.make(.encodingFailed)); return }
        resume(returning: result)
    }
}

private extension CheckedContinuation where E == Error, T: Decodable {
    /// Decode JSON data and resume the continuation with the decoded value.
    func resume(with data: Data, as type: T.Type) {
        do {
            resume(returning: try xpcDecode(type, from: data))
        } catch {
            resume(throwing: error)
        }
    }
}

// MARK: - OneShotRelay

/// Thread-safe wrapper around a CheckedContinuation that guarantees exactly
/// one resume call even when two paths race (XPC reply vs. connection drop).
/// Used exclusively by ping() to avoid continuation leaks when the host app
/// is not running and XPC drops the reply block.
private final class OneShotRelay<T: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var done = false
    private let continuation: CheckedContinuation<T, Error>

    init(_ continuation: CheckedContinuation<T, Error>) {
        self.continuation = continuation
    }

    func resume(returning value: T) {
        lock.lock(); defer { lock.unlock() }
        guard !done else { return }
        done = true
        continuation.resume(returning: value)
    }

    func resume(throwing error: Error) {
        lock.lock(); defer { lock.unlock() }
        guard !done else { return }
        done = true
        continuation.resume(throwing: error)
    }
}
