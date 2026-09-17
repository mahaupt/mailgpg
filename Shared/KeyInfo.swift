// KeyInfo.swift
// Shared — add to both MailGPG and MailGPGExtension targets

import Foundation

/// Metadata about a single GPG key (public or secret).
///
/// `Codable` so it can be JSON-encoded and sent as `Data` over XPC.
/// `Identifiable` so SwiftUI lists can use it directly.
struct KeyInfo: Codable, Identifiable, Equatable {
    /// Full 40-character hex fingerprint — the stable, unique identifier.
    let fingerprint: String

    /// Last 8 hex characters of the fingerprint. Shown in the UI.
    let keyID: String

    /// Primary email address associated with this key.
    /// This is the address from the *first* (primary) non-revoked User ID.
    let email: String

    /// Every non-revoked User ID address on this key, lowercased and de-duplicated,
    /// in UID order. A key can carry several addresses (e.g. work + private), and
    /// any of them is a legitimate match for a `From:` or `To:` header.
    ///
    /// Optional on the wire — see `init(from:)`.
    let emails: [String]

    /// Human-readable name from the key's User ID packet.
    let name: String

    /// Owner-trust level (field 8): how much GPG trusts this key owner to certify others.
    let trustLevel: TrustLevel

    /// Calculated validity (field 1): whether this key is considered valid based on
    /// local signatures (`lsign`) and web-of-trust calculations. Use this for the trust badge.
    let validity: TrustLevel

    /// Whether this key has been verified (full or ultimate validity). Convenience accessor.
    var trusted: Bool { validity == .full || validity == .ultimate }

    /// Whether a secret (private) key is available for this fingerprint.
    /// `true` means we can sign or decrypt with this key.
    let hasSecretKey: Bool

    /// Expiry date, or `nil` if the key never expires.
    let expiresAt: Date?

    /// Whether this key has been revoked by its owner.
    /// A revoked key must not be used for encryption or signing.
    let isRevoked: Bool

    // `Identifiable` — SwiftUI needs a stable `id` property.
    var id: String { fingerprint }

    /// Addresses to match a From/To header against. Falls back to `email` so a host
    /// app that predates multi-UID parsing degrades instead of matching nothing.
    var normalizedEmails: [String] { emails.isEmpty ? [email.lowercased()] : emails }

    // MARK: - Codable

    // Explicit keys + a hand-written decoder so `emails` is *optional on the wire*.
    // `KeyInfo` crosses XPC as JSON, and during development the extension is routinely
    // paired with a host app binary that predates multi-UID parsing. `decodeIfPresent`
    // makes that combination degrade to single-address matching instead of failing to
    // decode the whole key list. `encode(to:)` stays synthesized.
    enum CodingKeys: String, CodingKey {
        case fingerprint, keyID, email, emails, name
        case trustLevel, validity, hasSecretKey, expiresAt, isRevoked
    }

    init(fingerprint: String,
         keyID: String,
         email: String,
         emails: [String] = [],
         name: String,
         trustLevel: TrustLevel,
         validity: TrustLevel,
         hasSecretKey: Bool,
         expiresAt: Date?,
         isRevoked: Bool) {
        self.fingerprint  = fingerprint
        self.keyID        = keyID
        self.email        = email
        self.emails       = emails
        self.name         = name
        self.trustLevel   = trustLevel
        self.validity     = validity
        self.hasSecretKey = hasSecretKey
        self.expiresAt    = expiresAt
        self.isRevoked    = isRevoked
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        fingerprint  = try c.decode(String.self,     forKey: .fingerprint)
        keyID        = try c.decode(String.self,     forKey: .keyID)
        email        = try c.decode(String.self,     forKey: .email)
        emails       = try c.decodeIfPresent([String].self, forKey: .emails) ?? []
        name         = try c.decode(String.self,     forKey: .name)
        trustLevel   = try c.decode(TrustLevel.self, forKey: .trustLevel)
        validity     = try c.decode(TrustLevel.self, forKey: .validity)
        hasSecretKey = try c.decode(Bool.self,       forKey: .hasSecretKey)
        expiresAt    = try c.decodeIfPresent(Date.self, forKey: .expiresAt)
        isRevoked    = try c.decode(Bool.self,       forKey: .isRevoked)
    }
}

// MARK: - Signing key selection

/// Choose which secret key should sign (and be the encrypt-to-self recipient for)
/// a message sent from `senderAddress`.
///
/// This lives here, next to `KeyInfo`, rather than in the Mail extension for two
/// reasons: `Shared/` is on both targets, and only `Shared/` + `MailGPG/` are
/// reachable from `MailGPGTests` — anything under `MailGPGExtension/` cannot be
/// unit-tested at all.
///
/// Precedence, highest first:
///  1. **Per-address override** — an explicit pin from Key Management. Honoured only
///     while the pinned key is still usable; a pin on a key that has since expired
///     falls through rather than failing the send.
///  2. **Address match on any UID** — the key actually belongs to the From address.
///     When several usable keys carry that address (the RSA + ECC case), the global
///     default key breaks the tie, otherwise keyring order does.
///  3. **Global default key** — the user's explicit "sign with this" choice.
///  4. **First usable key** — the historical behaviour, kept as a last resort.
///
/// Deliberately pure: no `UserDefaults`, no XPC, and `now` is injected so the
/// expiry filter is testable. The revoked/expired filter lives here too, so
/// "usable" cannot drift apart from the tests that pin this behaviour down.
///
/// - Parameters:
///   - senderAddress: the bare `From` address (no display name). Case-insensitive.
///   - keys: secret keys in keyring order, as returned by `--list-secret-keys`.
///   - overrides: bare lowercased address → 40-char fingerprint.
///   - defaultFingerprint: the global default signing key, if one is set.
func selectSigningKey(senderAddress: String,
                      from keys: [KeyInfo],
                      overrides: [String: String] = [:],
                      defaultFingerprint: String? = nil,
                      now: Date = Date()) -> KeyInfo? {
    let usable = keys.filter { !$0.isRevoked && ($0.expiresAt.map { $0 > now } ?? true) }
    guard !usable.isEmpty else { return nil }

    let sender = senderAddress.lowercased()
    let defaultKey = defaultFingerprint.flatMap { fp in
        usable.first { $0.fingerprint.caseInsensitiveCompare(fp) == .orderedSame }
    }

    // 1. Per-address override — only if the pinned key is still usable.
    if let pinned = overrides[sender],
       let key = usable.first(where: { $0.fingerprint.caseInsensitiveCompare(pinned) == .orderedSame }) {
        return key
    }

    // 2. Address match on any non-revoked UID of the key.
    let matches = usable.filter { $0.normalizedEmails.contains(sender) }
    if !matches.isEmpty {
        // Ambiguous (e.g. one RSA and one ECC key for the same address): prefer the
        // global default if it is one of the matches, otherwise take keyring order.
        if let defaultKey, matches.contains(where: { $0.fingerprint == defaultKey.fingerprint }) {
            return defaultKey
        }
        return matches.first
    }

    // 3. Global default, 4. first usable key.
    return defaultKey ?? usable.first
}
