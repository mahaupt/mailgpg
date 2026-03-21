// TrustLevel.swift
// Shared — add to both MailGPG and MailGPGExtension targets

import Foundation

/// The owner-trust level of a GPG key in the local keychain.
///
/// Maps directly to the validity field in `gpg --with-colons` output.
enum TrustLevel: String, Codable, CaseIterable {
    case unknown  = "?"   // GPG validity: ?
    case none     = "-"   // GPG validity: -
    case marginal = "m"   // GPG validity: m
    case full     = "f"   // GPG validity: f
    case ultimate = "u"   // GPG validity: u

    /// Human-readable label shown in UI pickers.
    var displayName: String {
        switch self {
        case .unknown:  return "Unknown"
        case .none:     return "None"
        case .marginal: return "Marginal"
        case .full:     return "Full"
        case .ultimate: return "Ultimate"
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
