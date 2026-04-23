// GPGServiceImpl+Parsing.swift
// MailGPG (host app only)

import Foundation

extension GPGServiceImpl {

    // MARK: - Colon-format key parser

    /// Parse the output of `gpg --with-colons [--list-keys | --list-secret-keys]`
    /// into an array of `KeyInfo` values.
    ///
    /// GPG's colon format (documented in `doc/DETAILS` in the GPG source):
    ///   type:validity:keylen:algo:keyid:created:expires:...:uid-or-fingerprint:
    ///
    /// Record types we care about:
    ///   sec / pub  — primary key line (starts a new key block)
    ///   fpr        — fingerprint (field 9)
    ///   uid        — user-id "Name (comment) <email>" (field 9)
    func parseColonOutput(_ output: String, wantSecretKeys: Bool) -> [KeyInfo] {
        var results: [KeyInfo] = []
        var inKey      = false
        var fingerprint = ""
        var keyID      = ""
        var validity   = ""   // field[1]: calculated key validity — used only for isRevoked
        var ownertrust = ""   // field[8]: explicitly-set owner trust — source of TrustLevel
        var expiry     = ""

        for raw in output.components(separatedBy: "\n") {
            let line = raw.hasSuffix("\r") ? String(raw.dropLast()) : raw
            let f    = line.components(separatedBy: ":")
            guard let type = f.first else { continue }

            switch type {
            case "sec"  where wantSecretKeys,   // secret key available locally
                 "sec#" where wantSecretKeys,    // stub only — key lives on smartcard/YubiKey
                 "pub"  where !wantSecretKeys:
                inKey       = true
                keyID       = f.count > 4 ? f[4] : ""
                validity    = f.count > 1 ? f[1] : ""
                ownertrust  = f.count > 8 ? f[8] : ""
                expiry      = f.count > 6 ? f[6] : ""
                fingerprint = ""

            case "pub" where wantSecretKeys:
                // A bare `pub` record inside --list-secret-keys output means
                // we've moved past the secret key block — stop collecting.
                inKey = false

            case "fpr" where inKey && fingerprint.isEmpty:
                fingerprint = f.count > 9 ? f[9] : ""

            case "uid" where inKey && !fingerprint.isEmpty:
                let uid = f.count > 9 ? f[9] : ""
                let (name, email) = parseUID(uid)
                let fp  = fingerprint
                let kid = fp.count >= 8 ? String(fp.suffix(8)) : keyID
                // GPG timestamps are Unix epoch strings; empty string means "no expiry".
                let expiryDate: Date? = Double(expiry).map { Date(timeIntervalSince1970: $0) }
                // GPG ownertrust field uses 'n' (not trusted) which has no direct rawValue
                // in TrustLevel — map it to .none explicitly.
                let trust: TrustLevel = ownertrust == "n" ? .none
                                      : TrustLevel(rawValue: ownertrust) ?? .unknown
                let validityLevel: TrustLevel = validity == "n" ? .none
                                              : TrustLevel(rawValue: validity) ?? .unknown
                results.append(KeyInfo(
                    fingerprint: fp,
                    keyID:       kid,
                    email:       email,
                    name:        name,
                    trustLevel:  trust,
                    validity:    validityLevel,
                    hasSecretKey: wantSecretKeys,
                    expiresAt:   expiryDate,
                    isRevoked:   validity == "r"
                ))
                inKey = false  // take only the first uid per primary key

            default: break
            }
        }
        return results
    }

    /// Parse a GPG user-ID string in the form `"Name (comment) <email>"`.
    func parseUID(_ uid: String) -> (name: String, email: String) {
        if let lt = uid.lastIndex(of: "<"),
           let gt = uid.lastIndex(of: ">"), lt < gt {
            let email = String(uid[uid.index(after: lt)..<gt])
            var name  = String(uid[..<lt]).trimmingCharacters(in: .whitespaces)
            // Drop "(comment)" portion if present.
            if let paren = name.firstIndex(of: "(") {
                name = String(name[..<paren]).trimmingCharacters(in: .whitespaces)
            }
            return (name, email)
        }
        return (uid, "")
    }

    // MARK: - GPG status parsers

    /// Parse the `[GNUPG:]` status lines that GPG writes when `--status-fd 2`
    /// is used during decryption. Returns a `SecurityStatus` describing what happened.
    ///
    /// Key status tokens:
    ///   DECRYPTION_OKAY           — successfully decrypted
    ///   GOODSIG <keyID> <name>    — a valid signature was found
    ///   BADSIG  <keyID> <name>    — signature present but invalid (tampered?)
    ///   NO_PUBKEY <keyID>         — can't verify: public key not in keychain
    func parseDecryptStatus(stderr: String) -> SecurityStatus {
        var pending: [(email: String, keyID: String)] = []
        var fingerprintByKeyID: [String: String] = [:]  // keyID → full fingerprint from VALIDSIG
        var lastKeyID: String? = nil
        var isEncrypted = false

        for line in stderr.components(separatedBy: "\n") {
            if line.contains("[GNUPG:] DECRYPTION_OKAY") {
                isEncrypted = true
            } else if line.contains("[GNUPG:] GOODSIG") {
                let p = line.components(separatedBy: " ")
                if p.count >= 4 {
                    let keyID = p[2]
                    // GOODSIG name field is the full UID string "Name <email>"
                    let (_, email) = parseUID(p[3...].joined(separator: " "))
                    pending.append((email: email, keyID: keyID))
                    lastKeyID = keyID
                }
            } else if line.contains("[GNUPG:] VALIDSIG"), let kid = lastKeyID {
                let p = line.components(separatedBy: " ")
                if p.count >= 3 { fingerprintByKeyID[kid] = p[2] }
                lastKeyID = nil
            } else if line.contains("[GNUPG:] BADSIG") {
                let p = line.components(separatedBy: " ")
                let keyID = p.count >= 3 ? p[2] : "unknown"
                return .signatureInvalid(reason: "Bad signature from key \(keyID)")
            } else if line.contains("[GNUPG:] NO_PUBKEY") {
                let p = line.components(separatedBy: " ")
                let keyID = p.count >= 3 ? p[2] : "unknown"
                return .keyNotFound(keyID: keyID)
            }
        }

        let signers = pending.map { s in
            Signer(email: s.email, keyID: s.keyID,
                   fingerprint: fingerprintByKeyID[s.keyID] ?? s.keyID,
                   trustLevel: .unknown)
        }
        if isEncrypted { return .encrypted(signers: signers) }
        if !signers.isEmpty { return .signed(signers: signers) }
        return .plain
    }

    /// Parse status lines from `gpg --verify --status-fd 1`.
    func parseVerifyStatus(stdout: String, stderr: String) -> SecurityStatus {
        let combined = stdout + "\n" + stderr
        var keyID: String? = nil
        var name: String? = nil
        var fingerprint: String? = nil

        for line in combined.components(separatedBy: "\n") {
            if line.contains("[GNUPG:] GOODSIG") {
                let p = line.components(separatedBy: " ")
                if p.count >= 4 {
                    keyID = p[2]
                    // GOODSIG name field is the full UID string "Name <email>"
                    let (_, email) = parseUID(p[3...].joined(separator: " "))
                    name = email.isEmpty ? p[3...].joined(separator: " ") : email
                }
            } else if line.contains("[GNUPG:] VALIDSIG"), keyID != nil {
                let p = line.components(separatedBy: " ")
                if p.count >= 3 { fingerprint = p[2] }
            } else if line.contains("[GNUPG:] BADSIG") {
                let p = line.components(separatedBy: " ")
                let kid = p.count >= 3 ? p[2] : "unknown"
                return .signatureInvalid(reason: "Bad signature from key \(kid)")
            } else if line.contains("[GNUPG:] NO_PUBKEY") {
                let p = line.components(separatedBy: " ")
                let kid = p.count >= 3 ? p[2] : "unknown"
                return .keyNotFound(keyID: kid)
            }
        }

        if let keyID, let name {
            let fp = fingerprint ?? keyID
            return .signed(signers: [Signer(email: name, keyID: keyID, fingerprint: fp, trustLevel: .unknown)])
        }
        // Fallback: check human-readable stderr
        if stderr.lowercased().contains("good signature") { return .signed(signers: []) }
        return .signatureInvalid(reason: stderr.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    /// Look up each signer's trust level in the local keyring and return an
    /// updated `SecurityStatus` with the real `trustLevel` filled in.
    /// Falls back to `.unknown` for any key that can't be found locally.
    func enrichWithTrust(_ status: SecurityStatus) -> SecurityStatus {
        func trust(forFingerprint fp: String) -> TrustLevel {
            guard let fp = try? validatedKeyIdentifier(fp, fieldName: "fingerprint", allowShort: false)
            else { return .unknown }
            guard let (out, _, code) = try? gpg(["--list-keys", "--with-colons",
                                                  "--fixed-list-mode", fp]),
                  code == 0 else { return .unknown }
            // Use validity (lsign/web-of-trust result) rather than ownertrust so the
            // trust badge in the UI reflects whether the key has actually been verified.
            return parseColonOutput(String(data: out, encoding: .utf8) ?? "",
                                    wantSecretKeys: false).first?.validity ?? .unknown
        }
        func enrich(_ signers: [Signer]) -> [Signer] {
            signers.map { Signer(email: $0.email, keyID: $0.keyID,
                                 fingerprint: $0.fingerprint,
                                 trustLevel: trust(forFingerprint: $0.fingerprint)) }
        }
        switch status {
        case .encrypted(let signers): return .encrypted(signers: enrich(signers))
        case .signed(let signers):    return .signed(signers: enrich(signers))
        default:                      return status
        }
    }

    /// Extract the sender's email address from a raw RFC 2822 message's `From:` header.
    /// Handles both `"Name <email>"` and plain `"email"` forms.
    func extractFromEmail(from data: Data) -> String? {
        let str = String(data: data, encoding: .utf8) ?? ""
        for line in str.components(separatedBy: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard trimmed.lowercased().hasPrefix("from:") else { continue }
            let value = String(trimmed.dropFirst(5)).trimmingCharacters(in: .whitespaces)
            if let lt = value.firstIndex(of: "<"), let gt = value.firstIndex(of: ">"), lt < gt {
                return String(value[value.index(after: lt)..<gt])
            }
            if value.contains("@") { return value }
        }
        return nil
    }

    /// Extract the fingerprint from `[GNUPG:] IMPORT_OK <flags> <fingerprint>` status output.
    func parseImportedFingerprint(from statusOutput: String) -> String? {
        for line in statusOutput.components(separatedBy: "\n") {
            if line.contains("[GNUPG:] IMPORT_OK") {
                let p = line.components(separatedBy: " ")
                if p.count >= 4 { return p[3] }
            }
        }
        return nil
    }
}
