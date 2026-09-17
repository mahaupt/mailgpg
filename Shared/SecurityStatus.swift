// SecurityStatus.swift
// MailGPGExtension

import Foundation

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

/// Which keys a message was encrypted to, and which of ours opened it.
///
/// Carried alongside the status so a failed decrypt can say *which* key it needed
/// rather than only that it failed — with two keys per address (one RSA, one ECC)
/// "encrypted to a key you don't have" is the single most useful signal there is.
///
/// Every field is optional on the wire: an extension paired with a host app that
/// predates these status parsers must still decode the status it is sent.
struct DecryptionDetails: Equatable, Codable {
    /// Key IDs from `ENC_TO` — every key the message was encrypted to.
    var encryptedToKeyIDs: [String] = []
    /// Fingerprint from `DECRYPTION_KEY` — the key of ours that actually opened it.
    var decryptionKeyFingerprint: String? = nil
    /// Key IDs from `NO_SECKEY` — encrypted to these, but we hold no secret key.
    var missingSecretKeyIDs: [String] = []
    /// `true` when the failure is transient and worth retrying: the gpg-agent
    /// died mid-operation (GPG Suite's shutdown-gpg-agent kills it on sleep/lock)
    /// or the user dismissed the pinentry prompt. The extension must NOT cache a
    /// permanent failure placeholder for these — the next attempt can succeed.
    var transient: Bool? = nil

    var isEmpty: Bool {
        encryptedToKeyIDs.isEmpty && decryptionKeyFingerprint == nil && missingSecretKeyIDs.isEmpty
    }

    enum CodingKeys: String, CodingKey {
        case encryptedToKeyIDs, decryptionKeyFingerprint, missingSecretKeyIDs, transient
    }

    init(encryptedToKeyIDs: [String] = [],
         decryptionKeyFingerprint: String? = nil,
         missingSecretKeyIDs: [String] = [],
         transient: Bool? = nil) {
        self.encryptedToKeyIDs = encryptedToKeyIDs
        self.decryptionKeyFingerprint = decryptionKeyFingerprint
        self.missingSecretKeyIDs = missingSecretKeyIDs
        self.transient = transient
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        encryptedToKeyIDs = try c.decodeIfPresent([String].self, forKey: .encryptedToKeyIDs) ?? []
        decryptionKeyFingerprint = try c.decodeIfPresent(String.self, forKey: .decryptionKeyFingerprint)
        missingSecretKeyIDs = try c.decodeIfPresent([String].self, forKey: .missingSecretKeyIDs) ?? []
        transient = try c.decodeIfPresent(Bool.self, forKey: .transient)
    }
}

/// The PGP security state of a received message.
enum SecurityStatus: Equatable, Codable {
    /// Message was encrypted. May also carry verified signatures.
    case encrypted(signers: [Signer], details: DecryptionDetails = DecryptionDetails())
    /// Message was not encrypted but carries one or more valid signatures.
    case signed(signers: [Signer])
    /// A signature was present but verification failed (e.g. tampered content).
    case signatureInvalid(reason: String)
    /// The message was encrypted but we could not decrypt it.
    /// `details` names the keys involved so the user can tell a missing key from a
    /// malformed MIME part.
    case decryptionFailed(reason: String, details: DecryptionDetails = DecryptionDetails())
    /// Signed or encrypted with a key we don't have locally and couldn't fetch.
    case keyNotFound(keyID: String)
    /// No PGP content detected.
    case plain

    // MARK: - Codable

    // Hand-written, but deliberately byte-compatible with what Swift used to
    // synthesize: a single-key object named after the case, whose value is keyed by
    // the associated-value labels. Keeping that layout means a host app built before
    // `details` existed still produces JSON this decodes — the synthesized decoder
    // would reject it, because synthesis ignores default values.
    enum CodingKeys: String, CodingKey {
        case encrypted, signed, signatureInvalid, decryptionFailed, keyNotFound, plain
    }
    private enum SignersKeys: String, CodingKey { case signers, details }
    private enum ReasonKeys:  String, CodingKey { case reason, details }
    private enum KeyIDKeys:   String, CodingKey { case keyID }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .encrypted(let signers, let details):
            var n = c.nestedContainer(keyedBy: SignersKeys.self, forKey: .encrypted)
            try n.encode(signers, forKey: .signers)
            try n.encode(details, forKey: .details)
        case .signed(let signers):
            var n = c.nestedContainer(keyedBy: SignersKeys.self, forKey: .signed)
            try n.encode(signers, forKey: .signers)
        case .signatureInvalid(let reason):
            var n = c.nestedContainer(keyedBy: ReasonKeys.self, forKey: .signatureInvalid)
            try n.encode(reason, forKey: .reason)
        case .decryptionFailed(let reason, let details):
            var n = c.nestedContainer(keyedBy: ReasonKeys.self, forKey: .decryptionFailed)
            try n.encode(reason, forKey: .reason)
            try n.encode(details, forKey: .details)
        case .keyNotFound(let keyID):
            var n = c.nestedContainer(keyedBy: KeyIDKeys.self, forKey: .keyNotFound)
            try n.encode(keyID, forKey: .keyID)
        case .plain:
            _ = c.nestedContainer(keyedBy: KeyIDKeys.self, forKey: .plain)
        }
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        if let n = try? c.nestedContainer(keyedBy: SignersKeys.self, forKey: .encrypted) {
            self = .encrypted(signers: try n.decode([Signer].self, forKey: .signers),
                              details: try n.decodeIfPresent(DecryptionDetails.self, forKey: .details)
                                       ?? DecryptionDetails())
        } else if let n = try? c.nestedContainer(keyedBy: SignersKeys.self, forKey: .signed) {
            self = .signed(signers: try n.decode([Signer].self, forKey: .signers))
        } else if let n = try? c.nestedContainer(keyedBy: ReasonKeys.self, forKey: .signatureInvalid) {
            self = .signatureInvalid(reason: try n.decode(String.self, forKey: .reason))
        } else if let n = try? c.nestedContainer(keyedBy: ReasonKeys.self, forKey: .decryptionFailed) {
            self = .decryptionFailed(reason: try n.decode(String.self, forKey: .reason),
                                     details: try n.decodeIfPresent(DecryptionDetails.self, forKey: .details)
                                              ?? DecryptionDetails())
        } else if let n = try? c.nestedContainer(keyedBy: KeyIDKeys.self, forKey: .keyNotFound) {
            self = .keyNotFound(keyID: try n.decode(String.self, forKey: .keyID))
        } else if c.contains(.plain) {
            self = .plain
        } else {
            throw DecodingError.dataCorrupted(.init(
                codingPath: decoder.codingPath,
                debugDescription: "Unrecognised SecurityStatus case"))
        }
    }
}

// MARK: - PGP content sniff

/// Result of the cheap byte-level scan that decides whether a raw RFC 2822 message
/// is worth handing to GPG at all. Shared so the extension's decode path and the
/// unit tests classify messages with exactly the same logic.
struct PGPContentSniff {
    /// `multipart/encrypted` + `application/pgp-encrypted` in the header block (RFC 3156).
    let isMIMEEncrypted: Bool
    /// `multipart/signed` + `application/pgp-signature` in the header block (RFC 3156).
    let isMIMESigned: Bool
    /// An armored PGP MESSAGE block anywhere in the body — literal or base64-encoded.
    let isInlinePGP: Bool
    /// An armored PGP SIGNED MESSAGE block anywhere in the body.
    let isInlineSigned: Bool

    var isEncrypted: Bool { isMIMEEncrypted || isInlinePGP }
    var isSigned: Bool { isMIMESigned || isInlineSigned }
}

/// Classify a raw message as PGP-encrypted / PGP-signed / neither.
///
/// - Parameters:
///   - lowercasedHeaderBlock: the message's RFC 2822 header block, lowercased.
///     Passed in (rather than derived here) so the caller keeps sole ownership of
///     the header/body split logic.
///   - rawMessage: the complete raw message, scanned as bytes so large bodies
///     never pay for a String conversion.
///
/// Besides the literal armor markers, this also scans for the base64 encoding of
/// `-----BEGIN PGP MESSAGE-----`. PGP "partitioned" mail (gpg4o, PGP Desktop and
/// other Outlook/Exchange gateways) is a plain `multipart/mixed` whose text part
/// carries the armor under `Content-Transfer-Encoding: base64` — the literal
/// marker never appears in the raw bytes, so such mail used to sniff as "not PGP"
/// and was never offered to GPG at all. The armor header is 27 bytes — a whole
/// number of base64 triples — so its 36-char encoding is exact and independent of
/// the bytes that follow; and since the armor starts the part (offset 0 in the
/// base64 stream), the 76-column line wrapping cannot split it.
func sniffPGPContent(lowercasedHeaderBlock preview: String, rawMessage data: Data) -> PGPContentSniff {
    let isMIMEEncrypted = preview.contains("multipart/encrypted")
                       && preview.contains("application/pgp-encrypted")
    let isMIMESigned = preview.contains("multipart/signed")
                    && preview.contains("application/pgp-signature")

    // When the header block already classifies the message (RFC 3156 either way),
    // the body is never scanned: the MIME verdict decides the decode path
    // regardless of what an inline scan could add. The body scans below only run
    // when the headers say nothing — which includes all ordinary non-PGP mail, so
    // they stay cheap byte searches (no String conversion of the body).
    if isMIMEEncrypted || isMIMESigned {
        return PGPContentSniff(isMIMEEncrypted: isMIMEEncrypted, isMIMESigned: isMIMESigned,
                               isInlinePGP: false, isInlineSigned: false)
    }

    let inlineMessageMarker = Data("-----BEGIN PGP MESSAGE-----".utf8)
    let inlineSignedMarker  = Data("-----BEGIN PGP SIGNED MESSAGE-----".utf8)
    let base64MessageMarker = Data("LS0tLS1CRUdJTiBQR1AgTUVTU0FHRS0tLS0t".utf8)

    return PGPContentSniff(
        isMIMEEncrypted: false,
        isMIMESigned: false,
        isInlinePGP: data.range(of: inlineMessageMarker) != nil
                  || data.range(of: base64MessageMarker) != nil,
        isInlineSigned: data.range(of: inlineSignedMarker) != nil)
}
