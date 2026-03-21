// GPGService.swift
// MailGPGExtension (extension only)

import Foundation

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

    // MARK: - Diagnostics

    /// Calls the host app and returns its GPG version string.
    /// A successful result confirms the full XPC round-trip is working.
    func ping() async throws -> String {
        let proxy = try connection.proxy()
        return try await withCheckedThrowingContinuation { continuation in
            proxy.ping { version, error in
                if let error { continuation.resume(throwing: error); return }
                continuation.resume(returning: version ?? "(no version returned)")
            }
        }
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
