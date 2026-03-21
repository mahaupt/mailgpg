// SecurityStatus.swift
// MailGPGExtension

/// A single PGP signer attached to a message.
struct Signer: Equatable, Codable {
    /// The email address associated with the signing key.
    let email: String
    /// Short key ID shown in the UI (last 8 hex chars of the fingerprint).
    let keyID: String
    /// Full 40-char hex fingerprint.
    let fingerprint: String
    /// Owner-trust level of this key in the local GPG keychain.
    let trustLevel: TrustLevel
    /// Convenience: true when trust is full or ultimate.
    var trusted: Bool { trustLevel == .full || trustLevel == .ultimate }
}

/// The PGP security state of a received message.
enum SecurityStatus: Equatable, Codable {
    /// Message was encrypted. May also carry verified signatures.
    case encrypted(signers: [Signer])
    /// Message was not encrypted but carries one or more valid signatures.
    case signed(signers: [Signer])
    /// A signature was present but verification failed (e.g. tampered content).
    case signatureInvalid(reason: String)
    /// The message was encrypted but we could not decrypt it.
    case decryptionFailed(reason: String)
    /// Signed or encrypted with a key we don't have locally and couldn't fetch.
    case keyNotFound(keyID: String)
    /// No PGP content detected.
    case plain
}
