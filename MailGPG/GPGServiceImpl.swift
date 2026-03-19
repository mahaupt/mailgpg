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
    private func buildSignedMessage(original: Data, signature: Data) -> Data {
        let boundary = "MailGPGSig_\(UUID().uuidString.replacingOccurrences(of: "-", with: ""))"
        let (rawHeaders, body) = splitMessage(original)

        // Detect line ending style from the original message — Mail.app uses LF (\n),
        // not CRLF (\r\n). Returning mismatched line endings crashes Mail's MIME parser.
        let eol = lineEnding(in: rawHeaders)

        // Extract the original body-part Content-Type and transfer encoding so we can
        // reproduce them inside the signed MIME envelope.
        let origCT  = foldedHeaderValue("content-type", in: rawHeaders)
                   ?? "text/plain; charset=utf-8"
        let origCTE = foldedHeaderValue("content-transfer-encoding", in: rawHeaders)

        let bodyStr = String(data: body,      encoding: .utf8) ?? ""
        let sigStr  = String(data: signature, encoding: .utf8) ?? ""

        // Build the body part headers for the first signed sub-part.
        var bodyPartHeaders = "Content-Type: \(origCT)" + eol
        if let cte = origCTE {
            bodyPartHeaders += "Content-Transfer-Encoding: \(cte)" + eol
        }

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
        let mime = headers + eol +
            eol +
            "--\(boundary)" + eol +
            bodyPartHeaders +
            eol +
            bodyStr + eol +
            "--\(boundary)" + eol +
            "Content-Type: application/pgp-signature; name=\"signature.asc\"" + eol +
            "Content-Disposition: attachment; filename=\"signature.asc\"" + eol +
            eol +
            sigStr + eol +
            "--\(boundary)--" + eol

        log.info("buildSignedMessage: eol=\(eol == "\r\n" ? "CRLF" : "LF") origCT=\(origCT) origCTE=\(origCTE ?? "(none)") bodyLen=\(body.count) sigLen=\(signature.count) totalLen=\(mime.count)")
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
        var validity   = ""
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
                results.append(KeyInfo(
                    fingerprint: fp,
                    keyID:       kid,
                    email:       email,
                    name:        name,
                    trusted:     ["u", "f"].contains(validity),
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
        var signers: [Signer] = []
        var isEncrypted = false

        for line in stderr.components(separatedBy: "\n") {
            if line.contains("[GNUPG:] DECRYPTION_OKAY") {
                isEncrypted = true
            } else if line.contains("[GNUPG:] GOODSIG") {
                let p = line.components(separatedBy: " ")
                if p.count >= 4 {
                    let keyID = p[2]
                    let name  = p[3...].joined(separator: " ")
                    signers.append(Signer(email: name, keyID: keyID, fingerprint: keyID, trusted: true))
                }
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

        if isEncrypted { return .encrypted(signers: signers) }
        if !signers.isEmpty { return .signed(signers: signers) }
        return .plain
    }

    /// Parse status lines from `gpg --verify --status-fd 1`.
    private func parseVerifyStatus(stdout: String, stderr: String) -> SecurityStatus {
        let combined = stdout + "\n" + stderr
        for line in combined.components(separatedBy: "\n") {
            if line.contains("[GNUPG:] GOODSIG") {
                let p = line.components(separatedBy: " ")
                if p.count >= 4 {
                    let keyID = p[2]
                    let name  = p[3...].joined(separator: " ")
                    return .signed(signers: [Signer(email: name, keyID: keyID, fingerprint: keyID, trusted: true)])
                }
                return .signed(signers: [])
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
        // Fallback: check human-readable stderr
        if stderr.lowercased().contains("good signature") { return .signed(signers: []) }
        return .signatureInvalid(reason: stderr.trimmingCharacters(in: .whitespacesAndNewlines))
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
        let lower = stderr.lowercased()
        if lower.contains("unusable") || lower.contains("unbrauchbar") {
            return "Cannot sign: the secret key is not accessible. " +
                   "If your key is on a YubiKey or smartcard, make sure it is inserted."
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
            let (_, body) = splitMessage(data)
            log.info("sign: body size=\(body.count) bytes, invoking gpg --detach-sign…")
            let (sigData, stderr, code) = try gpg(
                ["--detach-sign", "--armor", "--batch", "--yes",
                 "--local-user", signerKeyID],
                input: body)
            if code == 0 {
                log.info("sign: succeeded, sig size=\(sigData.count) bytes")
                reply(buildSignedMessage(original: data, signature: sigData), nil)
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
            _ = try? gpg(["--card-status"])
            let (_, body) = splitMessage(data)
            // --sign --encrypt in one pass: the signature is embedded inside
            // the encrypted envelope, so the recipient can verify after decrypting.
            var args = ["--sign", "--encrypt", "--armor", "--batch", "--yes",
                        "--trust-model", "always", "--local-user", signerKeyID]
            for fp in recipientFingerprints { args += ["--recipient", fp] }
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
            guard code == 0 else {
                throw GPGXPCError.make(.gpgFailed,
                    message: "gpg decrypt failed (exit \(code)): \(stderr)")
            }
            let status = parseDecryptStatus(stderr: stderr)
            reply(plaintext, try xpcEncode(status), nil)
        } catch {
            reply(nil, nil, error as NSError)
        }
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
            let status = parseVerifyStatus(stdout: stdout, stderr: stderr)
            reply(try xpcEncode(status), nil)
        } catch {
            reply(nil, GPGXPCError.make(.gpgFailed, message: error.localizedDescription))
        }
    }

    // MARK: - Key management

    func lookupKey(email: String,
                   reply: @escaping (Data?, Error?) -> Void) {
        do {
            // ── Fast path: local keyring ─────────────────────────────────────
            // --list-keys returns immediately; no network involved.
            let (localOut, _, localCode) = try gpg(
                ["--list-keys", "--with-colons", "--fixed-list-mode", email])
            if localCode == 0 {
                let keys = parseColonOutput(String(data: localOut, encoding: .utf8) ?? "",
                                            wantSecretKeys: false)
                if let key = keys.first {
                    reply(try xpcEncode(key), nil)
                    return
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
            guard remoteCode == 0 else { reply(nil, nil); return }
            let remoteKeys = parseColonOutput(String(data: remoteOut, encoding: .utf8) ?? "",
                                              wantSecretKeys: false)
            if let key = remoteKeys.first {
                reply(try xpcEncode(key), nil)
            } else {
                reply(nil, nil)
            }
        } catch {
            reply(nil, GPGXPCError.make(.gpgFailed, message: error.localizedDescription))
        }
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
