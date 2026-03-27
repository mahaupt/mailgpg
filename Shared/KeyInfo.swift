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
    let email: String

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
}
