// TrustLevel.swift
// Shared — add to both MailGPG and MailGPGExtension targets

import Foundation

/// A GPG trust/validity level.
///
/// Used for two distinct purposes:
/// - **Owner trust** (field 8 in `gpg --with-colons`): how much you trust a key
///   *owner* to certify other keys in the web of trust. Stored in `KeyInfo.trustLevel`.
/// - **Calculated validity** (field 1): whether GPG considers a key valid, based on
///   local signatures (`lsign`) and web-of-trust calculations. Stored in `KeyInfo.validity`.
enum TrustLevel: String, Codable, CaseIterable {
    case unknown  = "?"   // GPG: ?
    case none     = "-"   // GPG: -
    case marginal = "m"   // GPG: m
    case full     = "f"   // GPG: f
    case ultimate = "u"   // GPG: u

    /// Label used in the owner-trust picker.
    var displayName: String {
        switch self {
        case .unknown:  return "Not Set"
        case .none:     return "Do Not Trust"
        case .marginal: return "Marginal"
        case .full:     return "Full"
        case .ultimate: return "Ultimate (my key)"
        }
    }

    /// Value used in GPG `--import-ownertrust` colon format (2–6).
    var gpgOwntrustValue: Int {
        switch self {
        case .unknown:  return 2
        case .none:     return 3
        case .marginal: return 4
        case .full:     return 5
        case .ultimate: return 6
        }
    }
}
