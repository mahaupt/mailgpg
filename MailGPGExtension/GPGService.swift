// GPGService.swift
// MailGPGExtension (extension only)

import Foundation
import os

private let log = Logger(subsystem: "com.mahaupt.mailgpg", category: "xpc")

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
        // Seed default keyservers into the shared UserDefaults container so the
        // host app can read them without duplicating the list.
        if (Self.defaults?.stringArray(forKey: "keyservers") ?? []).isEmpty {
            Self.defaults?.set(Self.defaultKeyservers, forKey: "keyservers")
        }
        // Permanently wire connection availability changes to HostAppReachability.
        // true  = connect() called optimistically → nil (re-checking, not confirmed yet)
        // false = connection failed / host app quit → false (confirmed unavailable)
        connection.onAvailabilityChanged = { available in
            HostAppReachability.shared.isAvailable = available ? nil : false
        }
    }

    // MARK: - XPC call plumbing

    /// Perform one XPC call such that the awaiting continuation is GUARANTEED to
    /// resume, even when NSXPC drops the method's reply block.
    ///
    /// NSXPC delivers call failures (connection interrupted, host app relaunched,
    /// unimplemented selector, …) to the proxy's error handler INSTEAD of the
    /// reply block. A continuation whose only resume path is the reply block
    /// therefore leaks on any such failure — and `decodedMessage` then blocks its
    /// bridging semaphore forever, wedging Mail's entire decode pipeline behind
    /// it ("every mail loads forever"). ping() carried a workaround for this for
    /// a while; this helper is that fix applied to every call: the proxy is
    /// created per call, its error handler resumes the same OneShotRelay the
    /// reply block uses, and the relay makes the two paths race safely.
    private func call<T: Sendable>(
        _ body: (GPGXPCProtocol, OneShotRelay<T>) -> Void
    ) async throws -> T {
        try await withCheckedThrowingContinuation { continuation in
            let relay = OneShotRelay(continuation)
            do {
                let proxy = try connection.proxy { error in
                    relay.resume(throwing: error)
                }
                body(proxy, relay)
            } catch {
                relay.resume(throwing: error)
            }
        }
    }

    // MARK: - Diagnostics

    /// Calls the host app and returns its GPG version string.
    /// A successful result confirms the full XPC round-trip is working.
    func ping() async throws -> String {
        let version: String = try await call { proxy, relay in
            proxy.ping { version, error in
                if let error { relay.resume(throwing: error); return }
                relay.resume(returning: version ?? "(no version returned)")
            }
        }
        // Mark the host app as confirmed available.
        HostAppReachability.shared.isAvailable = true
        return version
    }

    /// Returns a full snapshot of the GPG environment on the host machine.
    func getSystemStatus() async throws -> SystemStatus {
        try await call { proxy, relay in
            proxy.getSystemStatus { statusJSON, error in
                if let error { relay.resume(throwing: error); return }
                guard let statusJSON else {
                    relay.resume(throwing: GPGXPCError.make(.encodingFailed)); return
                }
                relay.resume(with: statusJSON, as: SystemStatus.self)
            }
        }
    }

    /// Write `pinentry-mac` to `gpg-agent.conf` and restart the agent.
    func fixPinentry() async throws {
        try await call { (proxy, relay: OneShotRelay<Void>) in
            proxy.fixPinentry { error in
                if let error { relay.resume(throwing: error); return }
                relay.resume(returning: ())
            }
        }
    }

    // MARK: - Outgoing

    func sign(data: Data, signerKeyID: String) async throws -> Data {
        try await call { proxy, relay in
            proxy.sign(data: data, signerKeyID: signerKeyID) { result, error in
                relay.resume(with: result, error: error)
            }
        }
    }

    func encrypt(data: Data, recipientFingerprints: [String]) async throws -> Data {
        try await call { proxy, relay in
            proxy.encrypt(data: data, recipientFingerprints: recipientFingerprints) { result, error in
                relay.resume(with: result, error: error)
            }
        }
    }

    func signAndEncrypt(data: Data, signerKeyID: String,
                        recipientFingerprints: [String]) async throws -> Data {
        try await call { proxy, relay in
            proxy.signAndEncrypt(data: data, signerKeyID: signerKeyID,
                                 recipientFingerprints: recipientFingerprints) { result, error in
                relay.resume(with: result, error: error)
            }
        }
    }

    // MARK: - Incoming

    func decrypt(data: Data) async throws -> (plaintext: Data, status: SecurityStatus) {
        try await call { proxy, relay in
            proxy.decrypt(data: data) { plaintextData, statusJSON, error in
                if let error {
                    relay.resume(throwing: error)
                    return
                }
                // Both values must be present on success.
                guard let plaintextData, let statusJSON else {
                    relay.resume(throwing: GPGXPCError.make(.encodingFailed))
                    return
                }
                do {
                    let status = try xpcDecode(SecurityStatus.self, from: statusJSON)
                    relay.resume(returning: (plaintextData, status))
                } catch {
                    relay.resume(throwing: error)
                }
            }
        }
    }

    func verify(data: Data, signature: Data) async throws -> SecurityStatus {
        try await call { proxy, relay in
            proxy.verify(data: data, signature: signature) { statusJSON, error in
                if let error { relay.resume(throwing: error); return }
                guard let statusJSON else {
                    relay.resume(throwing: GPGXPCError.make(.encodingFailed))
                    return
                }
                relay.resume(with: statusJSON, as: SecurityStatus.self)
            }
        }
    }

    // MARK: - Key management

    func lookupKey(email: String) async throws -> KeyInfo? {
        try await call { proxy, relay in
            proxy.lookupKey(email: email) { keyInfoJSON, error in
                if let error { relay.resume(throwing: error); return }
                // nil data with no error means the key simply doesn't exist.
                guard let keyInfoJSON else {
                    relay.resume(returning: Optional<KeyInfo>.none)
                    return
                }
                do {
                    relay.resume(returning: try xpcDecode(KeyInfo.self, from: keyInfoJSON))
                } catch {
                    relay.resume(throwing: error)
                }
            }
        }
    }

    /// All usable public keys for `email`, so a correspondent who publishes more than
    /// one key gets a PKESK packet for each — you cannot know which one they can
    /// actually decrypt with.
    ///
    /// Falls back to the single-key `lookupKey` when the host app is older than this
    /// extension: an unimplemented selector surfaces through
    /// `remoteObjectProxyWithErrorHandler` as NSCocoaErrorDomain 4099.
    func lookupKeys(email: String) async throws -> [KeyInfo] {
        do {
            return try await call { proxy, relay in
                proxy.lookupKeys(email: email) { keyListJSON, error in
                    if let error { relay.resume(throwing: error); return }
                    // nil data with no error means no key exists for this address.
                    guard let keyListJSON else {
                        relay.resume(returning: [])
                        return
                    }
                    relay.resume(with: keyListJSON, as: [KeyInfo].self)
                }
            }
        } catch let error as NSError where error.domain == NSCocoaErrorDomain && error.code == 4099 {
            log.info("lookupKeys unavailable on the host app — falling back to lookupKey")
            return try await lookupKey(email: email).map { [$0] } ?? []
        }
    }

    func listSecretKeys() async throws -> [KeyInfo] {
        try await call { proxy, relay in
            proxy.listSecretKeys { keyListJSON, error in
                if let error { relay.resume(throwing: error); return }
                guard let keyListJSON else {
                    relay.resume(returning: [])
                    return
                }
                relay.resume(with: keyListJSON, as: [KeyInfo].self)
            }
        }
    }

    func importKey(armoredKey: String) async throws -> KeyInfo {
        try await call { proxy, relay in
            proxy.importKey(armoredKey: armoredKey) { keyInfoJSON, error in
                if let error { relay.resume(throwing: error); return }
                guard let keyInfoJSON else {
                    relay.resume(throwing: GPGXPCError.make(.encodingFailed))
                    return
                }
                relay.resume(with: keyInfoJSON, as: KeyInfo.self)
            }
        }
    }

    func listPublicKeys() async throws -> [KeyInfo] {
        try await call { proxy, relay in
            proxy.listPublicKeys { keyListJSON, error in
                if let error { relay.resume(throwing: error); return }
                guard let keyListJSON else {
                    relay.resume(returning: [])
                    return
                }
                relay.resume(with: keyListJSON, as: [KeyInfo].self)
            }
        }
    }

    func deleteKey(fingerprint: String) async throws {
        try await call { (proxy, relay: OneShotRelay<Void>) in
            proxy.deleteKey(fingerprint: fingerprint) { error in
                if let error { relay.resume(throwing: error); return }
                relay.resume(returning: ())
            }
        }
    }

    func lsignKey(fingerprint: String) async throws {
        try await call { (proxy, relay: OneShotRelay<Void>) in
            proxy.lsignKey(fingerprint: fingerprint) { error in
                if let error { relay.resume(throwing: error); return }
                relay.resume(returning: ())
            }
        }
    }

    func setTrust(fingerprint: String, level: TrustLevel) async throws {
        try await call { (proxy, relay: OneShotRelay<Void>) in
            proxy.setTrust(fingerprint: fingerprint, level: level.rawValue) { error in
                if let error { relay.resume(throwing: error); return }
                relay.resume(returning: ())
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

    // MARK: - Per-address signing key overrides (UserDefaults, no XPC needed)

    /// Pins a specific secret key to a specific From address.
    ///
    /// Auto-matching by address is ambiguous whenever an identity has more than one
    /// currently-valid key (an RSA and an ECC key on the same address is a common
    /// setup), so an explicit per-identity pin is required, not merely nice to have.
    /// Selection happens entirely extension-side in `selectSigningKey`, so this needs
    /// no XPC method — just the shared app-group suite, same as the keyserver list.
    ///
    /// Keys are bare lowercased addresses; values are uppercase 40-char fingerprints.
    /// `nonisolated` because both the encode path and the SwiftUI pickers read it
    /// synchronously.
    nonisolated func getSigningKeyOverrides() -> [String: String] {
        Self.defaults?.dictionary(forKey: "signingKeyOverrides") as? [String: String] ?? [:]
    }

    /// Pin `address` to `fingerprint`, or clear the pin when `fingerprint` is `nil`.
    nonisolated func setSigningKeyOverride(address: String, fingerprint: String?) {
        var overrides = getSigningKeyOverrides()
        let key = address.lowercased()
        if let fingerprint {
            overrides[key] = fingerprint.uppercased()
        } else {
            overrides.removeValue(forKey: key)
        }
        Self.defaults?.set(overrides, forKey: "signingKeyOverrides")
    }

    // MARK: - Keyservers (UserDefaults, no XPC needed)

    static let defaultKeyservers = [
        "hkps://keys.openpgp.org",
        "hkps://keys.mailvelope.com",
        "hkps://keyserver.ubuntu.com",
    ]

    nonisolated func getKeyservers() -> [String] {
        Self.defaults?.stringArray(forKey: "keyservers") ?? Self.defaultKeyservers
    }

    nonisolated func setKeyservers(_ servers: [String]) {
        Self.defaults?.set(servers, forKey: "keyservers")
    }
}

// MARK: - OneShotRelay

/// Thread-safe wrapper around a CheckedContinuation that guarantees exactly
/// one resume call even when two paths race (XPC reply vs. connection drop).
/// Every XPC method goes through one of these via `GPGService.call` — the
/// proxy's error handler and the reply block resume the same relay, so a
/// dropped reply block can no longer leak the continuation.
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

// MARK: - Relay helpers

/// Makes resuming a relay from an XPC reply block more concise.
private extension OneShotRelay where T == Data {
    func resume(with result: Data?, error: Error?) {
        if let error { resume(throwing: error); return }
        guard let result else { resume(throwing: GPGXPCError.make(.encodingFailed)); return }
        resume(returning: result)
    }
}

private extension OneShotRelay where T: Decodable {
    /// Decode JSON data and resume the relay with the decoded value.
    func resume(with data: Data, as type: T.Type) {
        do {
            resume(returning: try xpcDecode(type, from: data))
        } catch {
            resume(throwing: error)
        }
    }
}
