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
    ///   sec / sec# / pub  — primary key line (starts a new key block)
    ///   fpr               — fingerprint (field 9)
    ///   uid               — user-id "Name (comment) <email>" (field 9)
    ///   sub / ssb         — subkey; ends the primary key's UID region
    ///
    /// A key block runs until the *next* primary-key record (or end of input), not
    /// until its first `uid`: keys routinely carry several addresses (work + private,
    /// or one key shared across two mail accounts), and every one of them is a valid
    /// match for a `From:`/`To:` header. Collecting them all is what makes
    /// `selectSigningKey` able to pick a key by identity.
    func parseColonOutput(_ output: String, wantSecretKeys: Bool) -> [KeyInfo] {
        var results: [KeyInfo] = []
        var inKey      = false
        var collectingUIDs = false   // false once a sub/ssb record is seen
        var fingerprint = ""
        var keyID      = ""
        var validity   = ""   // field[1]: calculated key validity — used only for isRevoked
        var ownertrust = ""   // field[8]: explicitly-set owner trust — source of TrustLevel
        var expiry     = ""
        // Every UID on the current key, with the validity GPG reported for it.
        var uids: [(name: String, email: String, valid: Bool)] = []

        /// Emit the key block accumulated so far. Deferred until the block actually
        /// ends so every UID on the key is already collected.
        func flush() {
            defer {
                inKey = false
                collectingUIDs = false
                fingerprint = ""
                uids = []
            }
            // Prefer a still-valid UID for the display name/address, but fall back to
            // the first UID of any validity so a fully revoked key is still reported
            // (the UI needs it to show "REVOKED" rather than silently omitting it).
            guard inKey, !fingerprint.isEmpty,
                  let primary = uids.first(where: { $0.valid }) ?? uids.first else { return }

            let kid = fingerprint.count >= 8 ? String(fingerprint.suffix(8)) : keyID
            // GPG timestamps are Unix epoch strings; empty string means "no expiry".
            let expiryDate: Date? = Double(expiry).map { Date(timeIntervalSince1970: $0) }
            // GPG ownertrust field uses 'n' (not trusted) which has no direct rawValue
            // in TrustLevel — map it to .none explicitly.
            let trust: TrustLevel = ownertrust == "n" ? .none
                                  : TrustLevel(rawValue: ownertrust) ?? .unknown
            let validityLevel: TrustLevel = validity == "n" ? .none
                                          : TrustLevel(rawValue: validity) ?? .unknown

            // Only still-valid UIDs are matchable: a retired address must not win a
            // From-header match. Lowercase + de-duplicate here (not in parseUID) so the
            // raw UID parser stays a pure string split and `email` keeps its own casing.
            var seen = Set<String>()
            let addresses = uids.filter { $0.valid }
                                .map { $0.email.lowercased() }
                                .filter { !$0.isEmpty && seen.insert($0).inserted }

            results.append(KeyInfo(
                fingerprint: fingerprint,
                keyID:       kid,
                email:       primary.email,
                emails:      addresses,
                name:        primary.name,
                trustLevel:  trust,
                validity:    validityLevel,
                hasSecretKey: wantSecretKeys,
                expiresAt:   expiryDate,
                isRevoked:   validity == "r"
            ))
        }

        for raw in output.components(separatedBy: "\n") {
            let line = raw.hasSuffix("\r") ? String(raw.dropLast()) : raw
            let f    = line.components(separatedBy: ":")
            guard let type = f.first else { continue }

            switch type {
            case "sec"  where wantSecretKeys,   // secret key available locally
                 "sec#" where wantSecretKeys,    // stub only — key lives on smartcard/YubiKey
                 "pub"  where !wantSecretKeys:
                flush()                          // close the previous block, if any
                inKey          = true
                collectingUIDs = true
                keyID          = f.count > 4 ? f[4] : ""
                validity       = f.count > 1 ? f[1] : ""
                ownertrust     = f.count > 8 ? f[8] : ""
                expiry         = f.count > 6 ? f[6] : ""

            case "pub" where wantSecretKeys:
                // A bare `pub` record inside --list-secret-keys output means
                // we've moved past the secret key block — close it and stop.
                flush()

            case "fpr" where inKey && fingerprint.isEmpty:
                fingerprint = f.count > 9 ? f[9] : ""

            case "sub", "ssb":
                // Subkeys carry their own fpr/uid-shaped records. Stop collecting so
                // nothing from the subkey region is attributed to the primary key.
                collectingUIDs = false

            case "uid" where inKey && collectingUIDs && !fingerprint.isEmpty:
                let (name, email) = parseUID(f.count > 9 ? f[9] : "")
                guard !email.isEmpty || !name.isEmpty else { break }
                // r = revoked, e = expired, i = invalid, d = disabled.
                let uidValidity = f.count > 1 ? f[1] : ""
                uids.append((name: name, email: email,
                             valid: !["r", "e", "i", "d"].contains(uidValidity)))

            default: break
            }
        }
        flush()   // end of input closes the last block
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
    /// Signature tokens:
    ///   GOODSIG <keyID> <name>    — a valid signature was found
    ///   VALIDSIG <fpr> …          — full fingerprint for the preceding GOODSIG
    ///   BADSIG  <keyID> <name>    — signature present but invalid (tampered?)
    ///   NO_PUBKEY <keyID>         — can't verify: public key not in keychain
    ///
    /// Decryption tokens — these are what make a failure diagnosable rather than
    /// just "it didn't work":
    ///   ENC_TO <keyid> <algo> <hidden>   — every key the message was encrypted to
    ///   NO_SECKEY <keyid>                — encrypted to that key, we don't hold it
    ///   DECRYPTION_KEY <fpr> <fpr> <ot>  — the key of ours that opened the message
    ///   DECRYPTION_OKAY                  — decryption succeeded
    ///   DECRYPTION_FAILED                — decryption problem. gpg emits this
    ///     *alongside* DECRYPTION_OKAY on an MDC/integrity failure and still writes
    ///     the plaintext to stdout, so treating OKAY alone as success would hand
    ///     tampered plaintext back to Mail as a good decrypt.
    func parseDecryptStatus(stderr: String) -> SecurityStatus {
        var pending: [(email: String, keyID: String)] = []
        var fingerprintByKeyID: [String: String] = [:]  // keyID → full fingerprint from VALIDSIG
        var lastKeyID: String? = nil
        var isEncrypted = false
        var decryptionFailed = false
        var details = DecryptionDetails()
        var signatureFailure: SecurityStatus? = nil
        var failureCode: UInt32? = nil

        /// Whitespace-split of a `[GNUPG:] TOKEN arg…` line, starting at `[GNUPG:]`.
        func fields(_ line: String) -> [String] {
            line.components(separatedBy: " ").filter { !$0.isEmpty }
        }

        for line in stderr.components(separatedBy: "\n") {
            let p = fields(line)
            if line.contains("[GNUPG:] DECRYPTION_OKAY") {
                isEncrypted = true
            } else if line.contains("[GNUPG:] DECRYPTION_FAILED") {
                decryptionFailed = true
            } else if line.contains("[GNUPG:] ENC_TO") {
                // Collects detail only: ENC_TO says the message was encrypted to this
                // key, NOT that we opened it. `isEncrypted` stays driven by
                // DECRYPTION_OKAY alone, otherwise a message we failed to decrypt
                // would report as successfully encrypted-and-read.
                if p.count >= 3, !details.encryptedToKeyIDs.contains(p[2]) {
                    details.encryptedToKeyIDs.append(p[2])
                }
            } else if line.contains("[GNUPG:] NO_SECKEY") {
                if p.count >= 3, !details.missingSecretKeyIDs.contains(p[2]) {
                    details.missingSecretKeyIDs.append(p[2])
                }
            } else if line.contains("[GNUPG:] DECRYPTION_KEY") {
                if p.count >= 3 { details.decryptionKeyFingerprint = p[2] }
            } else if line.contains("[GNUPG:] GOODSIG") {
                if p.count >= 4 {
                    let keyID = p[2]
                    // GOODSIG name field is the full UID string "Name <email>"
                    let (_, email) = parseUID(p[3...].joined(separator: " "))
                    pending.append((email: email, keyID: keyID))
                    lastKeyID = keyID
                }
            } else if line.contains("[GNUPG:] VALIDSIG"), let kid = lastKeyID {
                if p.count >= 3 { fingerprintByKeyID[kid] = p[2] }
                lastKeyID = nil
            } else if line.contains("[GNUPG:] BADSIG") {
                // Don't return early: a later DECRYPTION_FAILED or the ENC_TO list is
                // still worth collecting. Remember the verdict and decide at the end.
                let keyID = p.count >= 3 ? p[2] : "unknown"
                signatureFailure = signatureFailure
                    ?? .signatureInvalid(reason: "Bad signature from key \(keyID)")
            } else if line.contains("[GNUPG:] NO_PUBKEY") {
                let keyID = p.count >= 3 ? p[2] : "unknown"
                signatureFailure = signatureFailure ?? .keyNotFound(keyID: keyID)
            } else if line.contains("[GNUPG:] FAILURE") || line.contains("[GNUPG:] ERROR") {
                // "[GNUPG:] FAILURE decrypt 83886179" — the number is a full
                // gpg-error value (source << 24 | code). Keep the FIRST one; later
                // FAILURE lines repeat the same root cause.
                if p.count >= 4, let n = UInt32(p[3]) { failureCode = failureCode ?? n }
            }
        }

        // A decryption problem outranks any signature verdict: without plaintext
        // there is nothing for a signature to be about.
        if decryptionFailed {
            details.transient = Self.isTransientGPGError(failureCode)
            return .decryptionFailed(reason: Self.decryptionFailureReason(details: details),
                                     details: details)
        }
        // Encrypted to keys we don't hold, and no DECRYPTION_OKAY. (A NO_SECKEY
        // alongside a successful decrypt is normal and not a failure: it just means
        // the message was also encrypted to a key of ours we no longer hold.)
        if !details.missingSecretKeyIDs.isEmpty && !isEncrypted {
            return .decryptionFailed(reason: Self.decryptionFailureReason(details: details),
                                     details: details)
        }
        if let signatureFailure { return signatureFailure }

        let signers = pending.map { s in
            Signer(email: s.email, keyID: s.keyID,
                   fingerprint: fingerprintByKeyID[s.keyID] ?? s.keyID,
                   trustLevel: .unknown)
        }
        if isEncrypted { return .encrypted(signers: signers, details: details) }
        if !signers.isEmpty { return .signed(signers: signers) }
        return .plain
    }

    /// Whether a gpg-error value from a `[GNUPG:] FAILURE …` / `ERROR …` status
    /// line describes a TRANSIENT condition rather than a property of the message.
    ///
    /// Transient means: retrying the exact same operation can succeed — the
    /// gpg-agent died mid-operation (GPG Suite's shutdown-gpg-agent kills the
    /// agent on sleep/lock; gpg restarts it on the next run) or the user
    /// dismissed the pinentry prompt. These must never be recorded as permanent
    /// failures of the message. Matching the numeric code keeps this
    /// locale-independent — gpg's human-readable stderr is localized.
    static func isTransientGPGError(_ fullCode: UInt32?) -> Bool {
        guard let fullCode else { return false }
        // Full gpg-error values are (source << 24 | code); the low 16 bits are
        // the error code proper.
        switch fullCode & 0xFFFF {
        case 99, 198:    // GPG_ERR_CANCELED / FULLY_CANCELED — pinentry dismissed
            return true
        case 16383:      // GPG_ERR_EOF — agent connection died mid-operation
            return true
        case 190, 191:   // GPG_ERR_NO_AGENT / GPG_ERR_AGENT — agent unreachable
            return true
        case 257...281:  // GPG_ERR_ASS_* — Assuan IPC layer (agent socket) errors
            return true
        default:
            return false
        }
    }

    /// Turn the collected status details into a sentence the user can act on.
    static func decryptionFailureReason(details: DecryptionDetails, gpgStderr: String? = nil) -> String {
        if !details.missingSecretKeyIDs.isEmpty {
            let list = details.missingSecretKeyIDs.joined(separator: ", ")
            var reason = "This message was encrypted to a key you don't have "
                       + "(secret key missing for \(list))."
            if details.encryptedToKeyIDs.count > details.missingSecretKeyIDs.count {
                reason += " It was encrypted to \(details.encryptedToKeyIDs.count) key(s) "
                        + "in total: \(details.encryptedToKeyIDs.joined(separator: ", "))."
            }
            return reason
        }
        if !details.encryptedToKeyIDs.isEmpty {
            return "Decryption failed. The message was encrypted to: "
                 + details.encryptedToKeyIDs.joined(separator: ", ") + "."
        }
        if let gpgStderr, !gpgStderr.isEmpty {
            return "Decryption failed: \(gpgStderr.trimmingCharacters(in: .whitespacesAndNewlines))"
        }
        return "Decryption failed and gpg gave no reason."
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
        case .encrypted(let signers, let details):
            return .encrypted(signers: enrich(signers), details: details)
        case .signed(let signers):
            return .signed(signers: enrich(signers))
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
