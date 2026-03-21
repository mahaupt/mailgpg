// GPGServiceImpl.swift
// MailGPG (host app only)

import Foundation
import os

private let log = Logger(subsystem: "com.mahaupt.mailgpg", category: "gpg")

/// Implements `GPGXPCProtocol` — the actual GPG operations run here in the
/// unsandboxed host app, which is allowed to spawn subprocesses.
///
/// One instance is created per incoming XPC connection by `GPGServiceListener`.
final class GPGServiceImpl: NSObject, GPGXPCProtocol {

    // MARK: - Subprocess helper

    /// Runs the GPG binary with `args`, optionally piping `input` to stdin.
    /// Returns (stdout bytes, stderr string, exit code).
    ///
    /// Why separate stdout and stderr?
    /// - stdout carries the actual output (plaintext, signature, key listings).
    /// - stderr carries human-readable progress and error messages from GPG.
    /// - When we pass `--status-fd 2`, GPG also writes machine-readable
    ///   `[GNUPG:]` status lines to stderr, which we parse for signer info.
    private func gpg(_ args: [String], input: Data? = nil) throws -> (stdout: Data, stderr: String, exitCode: Int32) {
        let path = try GPGLocator.locate()
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        // --no-tty: never attempt to open or read from a TTY.
        // Without this a background process with no terminal can hang waiting
        // for input that will never come.
        process.arguments = ["--no-tty"] + args

        // Strip the Xcode dylib injection var so GPG doesn't choke on it.
        // Also clear GPG_TTY — we're a GUI app with no terminal; pinentry-mac
        // doesn't need it, and a stale value confuses pinentry-curses.
        var env = ProcessInfo.processInfo.environment
        env.removeValue(forKey: "DYLD_INSERT_LIBRARIES")
        env.removeValue(forKey: "GPG_TTY")
        process.environment = env

        let outPipe = Pipe()
        let errPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError  = errPipe

        if let input {
            let inPipe = Pipe()
            process.standardInput = inPipe
            try process.run()
            inPipe.fileHandleForWriting.write(input)
            inPipe.fileHandleForWriting.closeFile()   // signal EOF to GPG
        } else {
            try process.run()
        }
        process.waitUntilExit()

        let stdout  = outPipe.fileHandleForReading.readDataToEndOfFile()
        let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
        return (stdout, String(data: errData, encoding: .utf8) ?? "", process.terminationStatus)
    }

    // MARK: - RFC 2822 / MIME helpers

    /// Split a raw RFC 2822 message into its header block (as String) and body (as Data).
    /// The separator between headers and body is either CRLFCRLF or LFLF.
    private func splitMessage(_ data: Data) -> (headers: String, body: Data) {
        for sep in ["\r\n\r\n", "\n\n"].compactMap({ $0.data(using: .utf8) }) {
            if let r = data.range(of: sep) {
                return (String(data: data[..<r.lowerBound], encoding: .utf8) ?? "",
                        Data(data[r.upperBound...]))
            }
        }
        return (String(data: data, encoding: .utf8) ?? "", Data())
    }

    /// Detect whether a string uses CRLF or LF line endings.
    private func lineEnding(in text: String) -> String {
        text.contains("\r\n") ? "\r\n" : "\n"
    }

    /// Remove a named header (and any folded continuation lines) from a header block.
    /// Preserves the original line ending style.
    private func removeHeader(_ name: String, from headers: String) -> String {
        let eol = lineEnding(in: headers)
        let lines = headers.components(separatedBy: "\n").map {
            $0.hasSuffix("\r") ? String($0.dropLast()) : $0
        }
        let prefix = name.lowercased() + ":"
        var out: [String] = []
        var skipping = false
        for line in lines {
            if line.lowercased().hasPrefix(prefix) {
                skipping = true
            } else if skipping && (line.hasPrefix(" ") || line.hasPrefix("\t")) {
                // continuation of the removed header — skip
            } else {
                skipping = false
                out.append(line)
            }
        }
        return out.joined(separator: eol)
    }

    /// Replace (or append) a named header in a block of RFC 2822 headers.
    /// Handles folded (multi-line) header values by skipping continuation lines.
    /// Preserves the original line ending style.
    private func setHeader(_ name: String, to value: String, in headers: String) -> String {
        let eol = lineEnding(in: headers)
        let lines = headers.components(separatedBy: "\n").map {
            $0.hasSuffix("\r") ? String($0.dropLast()) : $0
        }
        let prefix = name.lowercased() + ":"
        var out: [String] = []
        var replaced = false
        var skipContinuation = false

        for line in lines {
            if line.lowercased().hasPrefix(prefix) {
                if !replaced {
                    out.append("\(name): \(value)")
                    replaced = true
                }
                skipContinuation = true
            } else if skipContinuation && (line.hasPrefix(" ") || line.hasPrefix("\t")) {
                // fold continuation of the header we just replaced — drop it
            } else {
                skipContinuation = false
                out.append(line)
            }
        }
        if !replaced { out.append("\(name): \(value)") }
        return out.joined(separator: eol)
    }

    // MARK: - PGP/MIME builders (RFC 3156)

    /// Wrap original message in a PGP/MIME multipart/signed envelope.
    ///
    /// Structure (RFC 3156 §5):
    ///   Content-Type: multipart/signed; micalg="pgp-sha256";
    ///                 protocol="application/pgp-signature"
    ///   --BOUNDARY
    ///   <original body>
    ///   --BOUNDARY
    ///   Content-Type: application/pgp-signature
    ///   <detached signature>
    ///   --BOUNDARY--
    /// Build the first MIME body part for a multipart/signed message.
    /// This is the content that gets signed with `gpg --detach-sign`.
    /// RFC 3156 §5: the signature covers the complete first MIME part
    /// (part headers + blank line + body), NOT just the message body text.
    private func buildSignedPart(rawHeaders: String, body: Data) -> String {
        let eol = lineEnding(in: rawHeaders)
        let origCT  = foldedHeaderValue("content-type", in: rawHeaders)
                   ?? "text/plain; charset=utf-8"
        let origCTE = foldedHeaderValue("content-transfer-encoding", in: rawHeaders)
        let bodyStr = String(data: body, encoding: .utf8) ?? ""

        var part = "Content-Type: \(origCT)" + eol
        if let cte = origCTE {
            part += "Content-Transfer-Encoding: \(cte)" + eol
        }
        part += eol + bodyStr
        return part
    }

    private func buildSignedMessage(original: Data, signedPart: String, signature: Data) -> Data {
        let boundary = "MailGPGSig_\(UUID().uuidString.replacingOccurrences(of: "-", with: ""))"
        let (rawHeaders, _) = splitMessage(original)

        // Detect line ending style from the original message — Mail.app uses LF (\n),
        // not CRLF (\r\n). Returning mismatched line endings crashes Mail's MIME parser.
        let eol = lineEnding(in: rawHeaders)
        let origCTE = foldedHeaderValue("content-transfer-encoding", in: rawHeaders)
        let sigStr  = String(data: signature, encoding: .utf8) ?? ""

        // MEEncodedOutgoingMessage.rawData must be a complete RFC 2822 message.
        // Strategy: start with the original envelope headers and:
        //   1. Replace Content-Type with our multipart/signed type (and new boundary).
        //   2. Remove Content-Transfer-Encoding from the top level (it now lives inside
        //      the first signed sub-part).
        //   3. Strip our internal X-Mailgpg-* headers so they don't appear in the wire msg.
        //   4. Ensure MIME-Version: 1.0 is present.
        var headers = setHeader(
            "Content-Type",
            to: "multipart/signed; micalg=\"pgp-sha256\";" +
                " protocol=\"application/pgp-signature\"; boundary=\"\(boundary)\"",
            in: rawHeaders)
        if origCTE != nil {
            headers = removeHeader("content-transfer-encoding", from: headers)
        }
        headers = removeHeader("x-mailgpg-sign",      from: headers)
        headers = removeHeader("x-mailgpg-encrypt",   from: headers)
        headers = removeHeader("x-mailgpg-sessionid", from: headers)
        if foldedHeaderValue("mime-version", in: headers) == nil {
            headers += eol + "MIME-Version: 1.0"
        }

        // Assemble the full RFC 2822 message: updated headers + blank line + MIME body.
        // The signedPart is placed byte-for-byte as the first MIME part — this is the
        // exact content the detached signature was computed over.
        let mime = headers + eol +
            eol +
            "--\(boundary)" + eol +
            signedPart + eol +
            "--\(boundary)" + eol +
            "Content-Type: application/pgp-signature; name=\"signature.asc\"" + eol +
            "Content-Disposition: attachment; filename=\"signature.asc\"" + eol +
            eol +
            sigStr + eol +
            "--\(boundary)--" + eol

        log.info("buildSignedMessage: eol=\(eol == "\r\n" ? "CRLF" : "LF") signedPartLen=\(signedPart.count) sigLen=\(signature.count) totalLen=\(mime.count)")
        return mime.data(using: .utf8) ?? Data()
    }

    /// Wrap original message in a PGP/MIME multipart/encrypted envelope.
    ///
    /// Structure (RFC 3156 §4):
    ///   Content-Type: multipart/encrypted;
    ///                 protocol="application/pgp-encrypted"
    ///   --BOUNDARY
    ///   Content-Type: application/pgp-encrypted
    ///   Version: 1
    ///   --BOUNDARY
    ///   Content-Type: application/octet-stream
    ///   <encrypted payload>
    ///   --BOUNDARY--
    private func buildEncryptedMessage(original: Data, encrypted: Data) -> Data {
        let boundary = "MailGPGEnc_\(UUID().uuidString.replacingOccurrences(of: "-", with: ""))"
        let (rawHeaders, _) = splitMessage(original)
        let eol = lineEnding(in: rawHeaders)
        let origCTE = foldedHeaderValue("content-transfer-encoding", in: rawHeaders)
        let encStr = String(data: encrypted, encoding: .utf8) ?? ""

        // Build full RFC 2822 message with updated envelope headers.
        var headers = setHeader(
            "Content-Type",
            to: "multipart/encrypted;" +
                " protocol=\"application/pgp-encrypted\"; boundary=\"\(boundary)\"",
            in: rawHeaders)
        if origCTE != nil {
            headers = removeHeader("content-transfer-encoding", from: headers)
        }
        headers = removeHeader("x-mailgpg-sign",      from: headers)
        headers = removeHeader("x-mailgpg-encrypt",   from: headers)
        headers = removeHeader("x-mailgpg-sessionid", from: headers)
        if foldedHeaderValue("mime-version", in: headers) == nil {
            headers += eol + "MIME-Version: 1.0"
        }

        let mime = headers + eol +
            eol +
            "--\(boundary)" + eol +
            "Content-Type: application/pgp-encrypted" + eol +
            "Content-Disposition: attachment" + eol +
            eol +
            "Version: 1" + eol +
            eol +
            "--\(boundary)" + eol +
            "Content-Type: application/octet-stream; name=\"encrypted.asc\"" + eol +
            "Content-Disposition: inline; filename=\"encrypted.asc\"" + eol +
            eol +
            encStr + eol +
            "--\(boundary)--" + eol

        return mime.data(using: .utf8) ?? Data()
    }

    /// Extract a header value from a block of RFC 2822 headers, collecting
    /// folded (multi-line) continuation lines.
    private func foldedHeaderValue(_ name: String, in headers: String) -> String? {
        let lines = headers.components(separatedBy: "\n").map {
            $0.hasSuffix("\r") ? String($0.dropLast()) : $0
        }
        let prefix = name.lowercased() + ":"
        var result: String? = nil
        for (i, line) in lines.enumerated() {
            if result != nil {
                if line.hasPrefix(" ") || line.hasPrefix("\t") {
                    result! += " " + line.trimmingCharacters(in: .whitespaces)
                } else {
                    break
                }
            } else if line.lowercased().hasPrefix(prefix) {
                result = String(line.dropFirst(prefix.count)).trimmingCharacters(in: .whitespaces)
                // peek at the next line for continuations
                if i + 1 < lines.count,
                   lines[i + 1].hasPrefix(" ") || lines[i + 1].hasPrefix("\t") {
                    continue  // will be picked up in the next iteration
                }
                break
            }
        }
        return result
    }

    /// Extract the raw PGP ciphertext from an incoming message so GPG can decrypt it.
    /// Handles both multipart/encrypted (RFC 3156) and inline PGP.
    private func extractPGPPayload(from data: Data) -> Data {
        guard let str = String(data: data, encoding: .utf8) else { return data }

        // ── multipart/encrypted ──────────────────────────────────────────────
        if str.contains("multipart/encrypted") {
            // Find the boundary value — may be quoted or unquoted.
            var boundary: String? = nil
            if let s = str.range(of: "boundary=\""),
               let e = str.range(of: "\"", range: s.upperBound..<str.endIndex) {
                boundary = String(str[s.upperBound..<e.lowerBound])
            } else if let s = str.range(of: "boundary=") {
                let rest = String(str[s.upperBound...])
                let end  = rest.firstIndex(where: { ";,\r\n \t".contains($0) })
                boundary = end.map { String(rest[..<$0]) } ?? rest
            }

            if let b = boundary {
                let delim = "--" + b
                let parts = str.components(separatedBy: delim)
                // parts: [preamble, version-part, encrypted-part, epilogue]
                if parts.count >= 3 {
                    let encPart = parts[2]
                    for sep in ["\r\n\r\n", "\n\n"] {
                        if let bodyStart = encPart.range(of: sep) {
                            let pgp = String(encPart[bodyStart.upperBound...])
                                .trimmingCharacters(in: .whitespacesAndNewlines)
                            return pgp.data(using: .utf8) ?? data
                        }
                    }
                }
            }
        }

        // ── inline PGP ───────────────────────────────────────────────────────
        if let start = str.range(of: "-----BEGIN PGP MESSAGE-----"),
           let end   = str.range(of: "-----END PGP MESSAGE-----") {
            let endIdx = str.index(end.upperBound, offsetBy: 0)
            return String(str[start.lowerBound..<endIdx]).data(using: .utf8) ?? data
        }

        return data
    }

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
    private func parseColonOutput(_ output: String, wantSecretKeys: Bool) -> [KeyInfo] {
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
                results.append(KeyInfo(
                    fingerprint: fp,
                    keyID:       kid,
                    email:       email,
                    name:        name,
                    trustLevel:  trust,
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
    private func parseUID(_ uid: String) -> (name: String, email: String) {
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
    private func parseDecryptStatus(stderr: String) -> SecurityStatus {
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
                    let name  = p[3...].joined(separator: " ")
                    pending.append((email: name, keyID: keyID))
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
    private func parseVerifyStatus(stdout: String, stderr: String) -> SecurityStatus {
        let combined = stdout + "\n" + stderr
        var keyID: String? = nil
        var name: String? = nil
        var fingerprint: String? = nil

        for line in combined.components(separatedBy: "\n") {
            if line.contains("[GNUPG:] GOODSIG") {
                let p = line.components(separatedBy: " ")
                if p.count >= 4 {
                    keyID = p[2]
                    name  = p[3...].joined(separator: " ")
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
    private func enrichWithTrust(_ status: SecurityStatus) -> SecurityStatus {
        func trust(forFingerprint fp: String) -> TrustLevel {
            guard let (out, _, code) = try? gpg(["--list-keys", "--with-colons",
                                                  "--fixed-list-mode", fp]),
                  code == 0 else { return .unknown }
            return parseColonOutput(String(data: out, encoding: .utf8) ?? "",
                                    wantSecretKeys: false).first?.trustLevel ?? .unknown
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
    private func extractFromEmail(from data: Data) -> String? {
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
    private func parseImportedFingerprint(from statusOutput: String) -> String? {
        for line in statusOutput.components(separatedBy: "\n") {
            if line.contains("[GNUPG:] IMPORT_OK") {
                let p = line.components(separatedBy: " ")
                if p.count >= 4 { return p[3] }
            }
        }
        return nil
    }

    // MARK: - Error helpers

    /// Maps GPG sign/encrypt stderr to a user-readable message.
    /// Detects the "unusable secret key" case that occurs when a YubiKey or
    /// OpenPGP smartcard key stub can't be accessed via scdaemon.
    private func signError(code: Int32, stderr: String) -> String {
        log.error("signError: exit=\(code) stderr=\(stderr)")
        let lower = stderr.lowercased()
        if lower.contains("unusable") || lower.contains("unbrauchbar") {
            if lower.contains("public") || lower.contains("öffentlich") {
                return "Cannot encrypt: a recipient's public key is unusable (revoked or expired). " +
                       "(gpg: \(stderr.trimmingCharacters(in: .whitespacesAndNewlines)))"
            }
            return "Cannot sign: the secret key is not accessible. " +
                   "If your key is on a YubiKey or smartcard, make sure it is inserted. " +
                   "(gpg: \(stderr.trimmingCharacters(in: .whitespacesAndNewlines)))"
        }
        return "gpg sign failed (exit \(code)): \(stderr)"
    }

    // MARK: - Diagnostics

    func ping(reply: @escaping (String?, Error?) -> Void) {
        do {
            let path    = try GPGLocator.locate()
            let version = try GPGLocator.version(at: path)
            reply(version, nil)
        } catch {
            reply(nil, GPGXPCError.make(.gpgNotFound, message: error.localizedDescription))
        }
    }

    // MARK: - Outgoing

    func sign(data: Data, signerKeyID: String,
              reply: @escaping (Data?, Error?) -> Void) {
        log.info("sign: keyID=\(signerKeyID) dataSize=\(data.count)")
        do {
            try GPGAgent.ensureRunning()
            log.info("sign: gpg-agent running, polling card-status…")
            _ = try? gpg(["--card-status"])
            let (rawHeaders, body) = splitMessage(data)

            // RFC 3156 §5: the detached signature must cover the complete first
            // MIME body part (Content-Type headers + blank line + body text),
            // not just the raw body text.
            let signedPart = buildSignedPart(rawHeaders: rawHeaders, body: body)
            // RFC 3156 requires signing the canonical CRLF form of the content.
            // Mail.app gives us LF internally, but SMTP transport will convert
            // LF→CRLF. Thunderbird verifies the CRLF bytes it receives, so we
            // must sign the CRLF version. The email is still built with LF (for
            // Mail.app compatibility) — SMTP transport restores the CRLF.
            let crlfSignedPart = signedPart
                .replacingOccurrences(of: "\r\n", with: "\n")
                .replacingOccurrences(of: "\n", with: "\r\n")
            guard let signedPartData = crlfSignedPart.data(using: .utf8) else {
                throw GPGXPCError.make(.encodingFailed, message: "Could not encode signed part")
            }
            log.info("sign: signed part size=\(signedPartData.count) bytes (CRLF canonical), invoking gpg --detach-sign…")
            let (sigData, stderr, code) = try gpg(
                ["--detach-sign", "--armor", "--batch", "--yes",
                 "--local-user", signerKeyID],
                input: signedPartData)
            if code == 0 {
                log.info("sign: succeeded, sig size=\(sigData.count) bytes")
                reply(buildSignedMessage(original: data, signedPart: signedPart, signature: sigData), nil)
            } else {
                let msg = signError(code: code, stderr: stderr)
                log.error("sign: gpg failed — \(msg)")
                throw GPGXPCError.make(.gpgFailed, message: msg)
            }
        } catch {
            log.error("sign: error — \(error.localizedDescription)")
            reply(nil, error as NSError)
        }
    }

    func encrypt(data: Data, recipientFingerprints: [String],
                 reply: @escaping (Data?, Error?) -> Void) {
        do {
            try GPGAgent.ensureRunning()
            let (_, body) = splitMessage(data)
            // --trust-model always: don't prompt about key trust during batch operations.
            // Each recipient gets a --recipient argument.
            var args = ["--encrypt", "--armor", "--batch", "--yes",
                        "--trust-model", "always"]
            for fp in recipientFingerprints { args += ["--recipient", fp] }
            let (encData, stderr, code) = try gpg(args, input: body)
            guard code == 0 else {
                throw GPGXPCError.make(.gpgFailed,
                    message: "gpg encrypt failed (exit \(code)): \(stderr)")
            }
            reply(buildEncryptedMessage(original: data, encrypted: encData), nil)
        } catch {
            reply(nil, error as NSError)
        }
    }

    func signAndEncrypt(data: Data, signerKeyID: String,
                        recipientFingerprints: [String],
                        reply: @escaping (Data?, Error?) -> Void) {
        do {
            try GPGAgent.ensureRunning()
            log.info("signAndEncrypt: polling card-status…")
            let cardResult = try? gpg(["--card-status"])
            log.info("signAndEncrypt: card-status exit=\(cardResult?.exitCode ?? -1)")
            let (_, body) = splitMessage(data)
            // --sign --encrypt in one pass: the signature is embedded inside
            // the encrypted envelope, so the recipient can verify after decrypting.
            var args = ["--sign", "--encrypt", "--armor", "--batch", "--yes",
                        "--trust-model", "always", "--local-user", signerKeyID]
            for fp in recipientFingerprints { args += ["--recipient", fp] }
            log.info("signAndEncrypt: gpg args=\(args.joined(separator: " "))")
            let (encData, stderr, code) = try gpg(args, input: body)
            guard code == 0 else {
                throw GPGXPCError.make(.gpgFailed, message: signError(code: code, stderr: stderr))
            }
            reply(buildEncryptedMessage(original: data, encrypted: encData), nil)
        } catch {
            reply(nil, error as NSError)
        }
    }

    // MARK: - Incoming

    func decrypt(data: Data,
                 reply: @escaping (Data?, Data?, Error?) -> Void) {
        do {
            try GPGAgent.ensureRunning()
            let payload = extractPGPPayload(from: data)
            // --status-fd 2: write [GNUPG:] machine-readable lines to stderr
            // so we can parse signer info without polluting stdout (plaintext).
            let (plaintext, stderr, code) = try gpg(
                ["--decrypt", "--batch", "--yes", "--status-fd", "2"],
                input: payload)
            // GPG exits non-zero (2) when the embedded signature can't be
            // verified (e.g. sender's public key not in keychain), even though
            // decryption itself succeeded. Treat DECRYPTION_OKAY as the
            // authoritative success indicator and only hard-fail if we got
            // neither that status nor a zero exit.
            let decryptionOkay = stderr.contains("[GNUPG:] DECRYPTION_OKAY")
            guard code == 0 || decryptionOkay else {
                throw GPGXPCError.make(.gpgFailed,
                    message: "gpg decrypt failed (exit \(code)): \(stderr)")
            }
            var status = parseDecryptStatus(stderr: stderr)

            // If the embedded signature couldn't be verified due to a missing
            // public key, try to fetch the sender's key and re-run the decrypt
            // so we get a real GOODSIG/BADSIG result.
            // Strategy 1: resolve by email via WKD/keyserver (prefers WKD,
            //             which is more authoritative and doesn't require a keyID).
            // Strategy 2: recv-keys by the key ID reported in NO_PUBKEY
            //             (direct keyserver fetch, works when WKD isn't available).
            if case .keyNotFound(let missingKeyID) = status {
                var keyFetched = false

                if let senderEmail = extractFromEmail(from: data) {
                    log.info("decrypt: NO_PUBKEY — trying WKD/keyserver for \(senderEmail)")
                    keyFetched = (try? resolveKey(email: senderEmail)) != nil
                }

                if !keyFetched && missingKeyID != "unknown" {
                    log.info("decrypt: NO_PUBKEY — trying recv-keys for \(missingKeyID)")
                    let (_, _, recvCode) = try gpg([
                        "--recv-keys",
                        "--keyserver-options", "timeout=10",
                        missingKeyID
                    ])
                    keyFetched = recvCode == 0
                }

                if keyFetched {
                    let (_, stderr2, _) = try gpg(
                        ["--decrypt", "--batch", "--yes", "--status-fd", "2"],
                        input: payload)
                    status = parseDecryptStatus(stderr: stderr2)
                    log.info("decrypt: re-verify after key fetch → \(String(describing: status))")
                }
            }

            // MEDecodedMessage requires a complete RFC 2822 message (headers + body).
            // GPG only returns the decrypted payload bytes; we must reconstruct
            // the full message from the outer envelope headers.
            let reconstructed = reconstructDecryptedMessage(original: data, plaintext: plaintext)
            reply(reconstructed, try xpcEncode(enrichWithTrust(status)), nil)
        } catch {
            reply(nil, nil, error as NSError)
        }
    }

    /// Reconstruct a complete RFC 2822 message from the outer encrypted envelope
    /// and the decrypted payload. `MEDecodedMessage` requires a full RFC 2822
    /// message, not just the raw decrypted bytes.
    ///
    /// We handle two formats:
    ///  • Full inner MIME entity (RFC 3156-compliant, used by Thunderbird etc.):
    ///    the decrypted bytes start with MIME headers (e.g. Content-Type:) followed
    ///    by a blank line and the body. We extract those headers and use them.
    ///  • Body-only (used by our own outgoing messages):
    ///    the decrypted bytes are the raw body with no headers. We default to
    ///    text/plain and use the raw bytes as the body.
    private func reconstructDecryptedMessage(original: Data, plaintext: Data) -> Data {
        let (outerHeaders, _) = splitMessage(original)
        let eol = lineEnding(in: outerHeaders)
        let plaintextStr = String(data: plaintext, encoding: .utf8) ?? ""

        var contentType = "text/plain; charset=utf-8"
        var contentTransferEncoding: String? = nil
        var body = plaintextStr

        // Check whether the decrypted content is itself a complete MIME entity.
        for sep in ["\r\n\r\n", "\n\n"] {
            if let range = plaintextStr.range(of: sep) {
                let innerHeaders = String(plaintextStr[..<range.lowerBound])
                if innerHeaders.lowercased().contains("content-type:") {
                    if let ct = foldedHeaderValue("content-type", in: innerHeaders) {
                        contentType = ct
                    }
                    contentTransferEncoding = foldedHeaderValue("content-transfer-encoding", in: innerHeaders)
                    body = String(plaintextStr[range.upperBound...])
                    log.info("decrypt: inner MIME entity detected, content-type=\(contentType)")
                }
                break
            }
        }

        // Build the reconstructed RFC 2822 message using the outer envelope headers,
        // replacing the multipart/encrypted wrapper with the decrypted content type.
        var headers = removeHeader("content-type", from: outerHeaders)
        headers = removeHeader("content-transfer-encoding", from: headers)
        headers = removeHeader("x-mailgpg-sessionid", from: headers)
        headers = setHeader("Content-Type", to: contentType, in: headers)
        if let cte = contentTransferEncoding {
            headers = setHeader("Content-Transfer-Encoding", to: cte, in: headers)
        }
        if foldedHeaderValue("mime-version", in: headers) == nil {
            headers += eol + "MIME-Version: 1.0"
        }

        let fullMessage = headers + eol + eol + body
        log.info("decrypt: reconstructed \(fullMessage.count) bytes (plaintext was \(plaintext.count) bytes)")
        return fullMessage.data(using: .utf8) ?? plaintext
    }

    func verify(data: Data, signature: Data,
                reply: @escaping (Data?, Error?) -> Void) {
        try? GPGAgent.ensureRunning()
        // `gpg --verify` requires the signature and data as *files*, not stdin.
        // We write them to the system temp directory and clean up afterward.
        let tmp     = FileManager.default.temporaryDirectory
        let dataURL = tmp.appendingPathComponent(UUID().uuidString)
        let sigURL  = tmp.appendingPathComponent(UUID().uuidString + ".asc")
        defer {
            try? FileManager.default.removeItem(at: dataURL)
            try? FileManager.default.removeItem(at: sigURL)
        }
        do {
            try data.write(to: dataURL)
            try signature.write(to: sigURL)

            // --status-fd 1: [GNUPG:] lines go to stdout so we can capture them cleanly.
            let gpgPath = try GPGLocator.locate()
            let process = Process()
            process.executableURL = URL(fileURLWithPath: gpgPath)
            process.arguments = ["--verify", "--batch", "--status-fd", "1",
                                  sigURL.path, dataURL.path]
            var env = ProcessInfo.processInfo.environment
            env.removeValue(forKey: "DYLD_INSERT_LIBRARIES")
            process.environment = env
            let outPipe = Pipe()
            let errPipe = Pipe()
            process.standardOutput = outPipe
            process.standardError  = errPipe
            try process.run()
            process.waitUntilExit()

            let stdout = String(data: outPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            let stderr = String(data: errPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            let status = enrichWithTrust(parseVerifyStatus(stdout: stdout, stderr: stderr))
            reply(try xpcEncode(status), nil)
        } catch {
            reply(nil, GPGXPCError.make(.gpgFailed, message: error.localizedDescription))
        }
    }

    // MARK: - Key management

    func lookupKey(email: String,
                   reply: @escaping (Data?, Error?) -> Void) {
        do {
            if let key = try resolveKey(email: email) {
                reply(try xpcEncode(key), nil)
            } else {
                reply(nil, nil)
            }
        } catch {
            reply(nil, GPGXPCError.make(.gpgFailed, message: error.localizedDescription))
        }
    }

    /// Resolve a key for `email`: checks the local keyring first, then falls
    /// back to WKD and keyserver lookup (which auto-imports on success).
    /// Returns the best usable key, or `nil` if none was found.
    private func resolveKey(email: String) throws -> KeyInfo? {
        // ── Fast path: local keyring ─────────────────────────────────────
        let (localOut, _, localCode) = try gpg(
            ["--list-keys", "--with-colons", "--fixed-list-mode", email])
        if localCode == 0 {
            let keys = parseColonOutput(String(data: localOut, encoding: .utf8) ?? "",
                                        wantSecretKeys: false)
            let usable = keys.filter { !$0.isRevoked && ($0.expiresAt.map { $0 > Date() } ?? true) }
            if let key = usable.first ?? keys.first(where: { !$0.isRevoked }) {
                return key
            }
        }

        // ── Slow path: WKD then keyserver ────────────────────────────────
        // --locate-keys finds a key by e-mail address and imports it automatically.
        // --auto-key-locate controls the lookup order:
        //   wkd       = Web Key Directory (HTTPS, served by the recipient's domain)
        //   keyserver = configured keyserver, defaults to keys.openpgp.org
        // --keyserver-options timeout=10: abort keyserver requests after 10 s so
        //   we don't block the compose panel indefinitely on a slow/dead server.
        // --no-auto-check-trustdb: skip trust-DB rebuild (saves ~1 s per lookup).
        let (remoteOut, _, remoteCode) = try gpg([
            "--locate-keys",
            "--auto-key-locate", "wkd,keyserver",
            "--keyserver-options", "timeout=10",
            "--no-auto-check-trustdb",
            "--with-colons",
            "--fixed-list-mode",
            email
        ])
        guard remoteCode == 0 else { return nil }
        let remoteKeys = parseColonOutput(String(data: remoteOut, encoding: .utf8) ?? "",
                                          wantSecretKeys: false)
        let usableRemote = remoteKeys.filter { !$0.isRevoked && ($0.expiresAt.map { $0 > Date() } ?? true) }
        return usableRemote.first ?? remoteKeys.first(where: { !$0.isRevoked })
    }

    func listSecretKeys(reply: @escaping (Data?, Error?) -> Void) {
        do {
            let (out, _, _) = try gpg(
                ["--list-secret-keys", "--with-colons", "--fixed-list-mode"])
            let keys = parseColonOutput(String(data: out, encoding: .utf8) ?? "",
                                        wantSecretKeys: true)
            log.info("listSecretKeys: found \(keys.count) key(s): \(keys.map { "\($0.keyID)(\($0.email)) revoked=\($0.isRevoked)" }.joined(separator: ", "))")
            reply(try xpcEncode(keys), nil)
        } catch {
            log.error("listSecretKeys: error — \(error.localizedDescription)")
            reply(nil, GPGXPCError.make(.gpgFailed, message: error.localizedDescription))
        }
    }

    func listPublicKeys(reply: @escaping (Data?, Error?) -> Void) {
        do {
            let (out, _, _) = try gpg(
                ["--list-keys", "--with-colons", "--fixed-list-mode"])
            let keys = parseColonOutput(String(data: out, encoding: .utf8) ?? "",
                                        wantSecretKeys: false)
            log.info("listPublicKeys: found \(keys.count) key(s)")
            reply(try xpcEncode(keys), nil)
        } catch {
            log.error("listPublicKeys: error — \(error.localizedDescription)")
            reply(nil, GPGXPCError.make(.gpgFailed, message: error.localizedDescription))
        }
    }

    func deleteKey(fingerprint: String,
                   reply: @escaping (Error?) -> Void) {
        do {
            let (_, stderr, code) = try gpg(
                ["--batch", "--yes", "--delete-keys", fingerprint])
            guard code == 0 else {
                throw GPGXPCError.make(.gpgFailed,
                    message: "gpg delete-keys failed: \(stderr)")
            }
            log.info("deleteKey: deleted \(fingerprint)")
            reply(nil)
        } catch {
            log.error("deleteKey: error — \(error.localizedDescription)")
            reply(error as NSError)
        }
    }

    func setTrust(fingerprint: String,
                  level: String,
                  reply: @escaping (Error?) -> Void) {
        guard let trustLevel = TrustLevel(rawValue: level) else {
            reply(GPGXPCError.make(.encodingFailed,
                message: "Unknown trust level: \(level)"))
            return
        }
        // --import-ownertrust reads "<fingerprint>:<numeric value>:\n" lines.
        // Writing to a temp file is more reliable than stdin when GPG runs
        // non-interactively (some builds ignore stdin with --no-tty).
        let ownertrustLine = "\(fingerprint):\(trustLevel.gpgOwntrustValue):\n"
        let tmpURL = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("mailgpg-ownertrust-\(UUID().uuidString).txt")
        do {
            try ownertrustLine.write(to: tmpURL, atomically: true, encoding: .utf8)
            defer { try? FileManager.default.removeItem(at: tmpURL) }

            let (_, importStderr, importCode) = try gpg(
                ["--batch", "--import-ownertrust", tmpURL.path])
            log.info("setTrust import: code=\(importCode) stderr=\(importStderr)")
            guard importCode == 0 else {
                throw GPGXPCError.make(.gpgFailed,
                    message: "gpg import-ownertrust failed (code \(importCode)): \(importStderr)")
            }

            // Recompute the trust database so that --list-keys reflects the
            // new ownertrust immediately (without this, 'gpg -k' still shows the
            // old calculated validity until GPG decides to rebuild on its own).
            let (_, checkStderr, checkCode) = try gpg(["--batch", "--check-trustdb"])
            if checkCode != 0 {
                log.warning("setTrust check-trustdb: code=\(checkCode) stderr=\(checkStderr)")
            }

            log.info("setTrust: \(fingerprint) → \(level)")
            reply(nil)
        } catch {
            log.error("setTrust: error — \(error.localizedDescription)")
            reply(error as NSError)
        }
    }

    func importKey(armoredKey: String,
                   reply: @escaping (Data?, Error?) -> Void) {
        guard let keyData = armoredKey.data(using: .utf8) else {
            reply(nil, GPGXPCError.make(.encodingFailed)); return
        }
        do {
            // --status-fd 1: IMPORT_OK lines go to stdout so we can parse the fingerprint.
            let (statusOut, stderr, code) = try gpg(
                ["--import", "--batch", "--yes", "--status-fd", "1"],
                input: keyData)
            guard code == 0 else {
                throw GPGXPCError.make(.gpgFailed, message: "gpg import failed: \(stderr)")
            }
            let statusStr = String(data: statusOut, encoding: .utf8) ?? ""
            guard let fingerprint = parseImportedFingerprint(from: statusStr) else {
                throw GPGXPCError.make(.encodingFailed,
                    message: "Could not determine imported key fingerprint")
            }
            // Fetch full KeyInfo for the freshly-imported key.
            let (listOut, _, _) = try gpg(
                ["--list-keys", "--with-colons", "--fixed-list-mode", fingerprint])
            let keys = parseColonOutput(String(data: listOut, encoding: .utf8) ?? "",
                                        wantSecretKeys: false)
            guard let key = keys.first else {
                throw GPGXPCError.make(.keyNotFound, message: "Imported key not found in keyring")
            }
            reply(try xpcEncode(key), nil)
        } catch {
            reply(nil, error as NSError)
        }
    }
}
