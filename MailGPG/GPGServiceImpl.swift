// GPGServiceImpl.swift
// MailGPG (host app only)

import Foundation
import os

let log = Logger(subsystem: "com.mahaupt.mailgpg", category: "gpg")

/// Implements `GPGXPCProtocol` — the actual GPG operations run here in the
/// unsandboxed host app, which is allowed to spawn subprocesses.
///
/// One instance is created per incoming XPC connection by `GPGServiceListener`.
final class GPGServiceImpl: NSObject, GPGXPCProtocol {

    /// When non-nil, all GPG subprocesses run with `GNUPGHOME` set to this path
    /// instead of the user's default `~/.gnupg`. Intended for testing only.
    let gnupgHome: String?

    init(gnupgHome: String? = nil) {
        self.gnupgHome = gnupgHome
        super.init()
    }

    private static let defaults = UserDefaults(suiteName: "group.com.mahaupt.mailgpg")

    /// Returns the current keyserver list from shared UserDefaults.
    /// The extension seeds the defaults on first launch, so this should never be empty.
    func currentKeyservers() -> [String] {
        Self.defaults?.stringArray(forKey: "keyservers") ?? []
    }

    // MARK: - Subprocess helper

    /// Runs the GPG binary with `args`, optionally piping `input` to stdin.
    /// Returns (stdout bytes, stderr string, exit code).
    ///
    /// Why separate stdout and stderr?
    /// - stdout carries the actual output (plaintext, signature, key listings).
    /// - stderr carries human-readable progress and error messages from GPG.
    /// - When we pass `--status-fd 2`, GPG also writes machine-readable
    ///   `[GNUPG:]` status lines to stderr, which we parse for signer info.
    func gpg(_ args: [String], input: Data? = nil) throws -> (stdout: Data, stderr: String, exitCode: Int32) {
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
        if let home = gnupgHome { env["GNUPGHOME"] = home }
        process.environment = env

        let outPipe = Pipe()
        let errPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError  = errPipe

        if let input {
            let inPipe = Pipe()
            process.standardInput = inPipe
            try process.run()
            // Write stdin on a background thread to avoid deadlock: if the input
            // is larger than the pipe buffer (~64 KB), the write blocks until GPG
            // consumes some data. GPG in turn may block writing to stdout/stderr
            // once *their* pipe buffers fill. Reading stdout/stderr below on this
            // thread breaks the cycle.
            DispatchQueue.global(qos: .userInitiated).async {
                inPipe.fileHandleForWriting.write(input)
                inPipe.fileHandleForWriting.closeFile()   // signal EOF to GPG
            }
        } else {
            try process.run()
        }

        // Read stdout and stderr concurrently BEFORE waitUntilExit to prevent
        // deadlock. Both pipes have ~64 KB buffers; if either fills, GPG blocks.
        // Reading them sequentially can still deadlock when GPG writes to the
        // pipe we're not currently draining. Reading in parallel avoids this.
        var stdout  = Data()
        var errData = Data()
        let group = DispatchGroup()
        group.enter()
        DispatchQueue.global(qos: .userInitiated).async {
            stdout = outPipe.fileHandleForReading.readDataToEndOfFile()
            group.leave()
        }
        group.enter()
        DispatchQueue.global(qos: .userInitiated).async {
            errData = errPipe.fileHandleForReading.readDataToEndOfFile()
            group.leave()
        }
        group.wait()
        process.waitUntilExit()
        return (stdout, String(data: errData, encoding: .utf8) ?? "", process.terminationStatus)
    }

    // MARK: - RFC 2822 / MIME helpers — see GPGServiceImpl+MIME.swift
    // MARK: - Colon-format key parser + GPG status parsers — see GPGServiceImpl+Parsing.swift

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

    func getSystemStatus(reply: @escaping (Data?, Error?) -> Void) {
        // GPG binary
        let gpgPath    = try? GPGLocator.locate()
        let gpgVersion = gpgPath.flatMap { try? GPGLocator.version(at: $0) }

        // gpg-agent
        let agentRunning = (try? GPGAgent.ensureRunning()) ?? false

        // Pinentry
        let pinentry = GPGAgent.checkPinentry()
        let state: SystemStatus.PinentryState
        var configuredPath: String?
        var availablePath: String?
        switch pinentry {
        case .ok(let path):
            state = .ok
            configuredPath = path
        case .fixable(let path):
            state = .fixable
            availablePath = path
        case .nonMac(let configured, let fix):
            state = .nonMac
            configuredPath = configured
            availablePath = fix
        case .notInstalled:
            state = .notInstalled
        }

        let status = SystemStatus(
            gpgPath: gpgPath,
            gpgVersion: gpgVersion,
            agentRunning: agentRunning,
            pinentryState: state,
            pinentryConfiguredPath: configuredPath,
            pinentryAvailablePath: availablePath
        )
        do {
            reply(try xpcEncode(status), nil)
        } catch {
            reply(nil, error)
        }
    }

    func fixPinentry(reply: @escaping (Error?) -> Void) {
        guard let path = GPGAgent.availableMacPinentry else {
            reply(GPGXPCError.make(.gpgNotFound,
                message: "No pinentry-mac binary found. Install it via Homebrew: brew install pinentry-mac"))
            return
        }
        do {
            try GPGAgent.configurePinentry(path: path)
            reply(nil)
        } catch {
            reply(error)
        }
    }

    // MARK: - Outgoing

    func sign(data: Data, signerKeyID: String,
              reply: @escaping (Data?, Error?) -> Void) {
        log.info("sign: keyID=\(signerKeyID) dataSize=\(data.count)")
        do {
            if gnupgHome == nil { try GPGAgent.ensureRunning() }
            let cardCode = (try? gpg(["--card-status"]))?.exitCode ?? -1
            log.info("sign: card-status exit=\(cardCode)")
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
            log.error("sign: error — \(error.localizedDescription, privacy: .public)")
            reply(nil, error as NSError)
        }
    }

    func encrypt(data: Data, recipientFingerprints: [String],
                 reply: @escaping (Data?, Error?) -> Void) {
        do {
            if gnupgHome == nil { try GPGAgent.ensureRunning() }
            let (rawHeaders, body) = splitMessage(data)
            let innerMIME = buildInnerMIMEEntity(rawHeaders: rawHeaders, body: body)
            // --trust-model always: don't prompt about key trust during batch operations.
            // Each recipient gets a --recipient argument.
            var args = ["--encrypt", "--armor", "--batch", "--yes",
                        "--trust-model", "always"]
            for fp in recipientFingerprints { args += ["--recipient", fp] }
            let (encData, stderr, code) = try gpg(args, input: innerMIME)
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
            if gnupgHome == nil { try GPGAgent.ensureRunning() }
            log.info("signAndEncrypt: polling card-status…")
            let cardResult = try? gpg(["--card-status"])
            log.info("signAndEncrypt: card-status exit=\(cardResult?.exitCode ?? -1)")
            let (rawHeaders, body) = splitMessage(data)
            let innerMIME = buildInnerMIMEEntity(rawHeaders: rawHeaders, body: body)
            // --sign --encrypt in one pass: the signature is embedded inside
            // the encrypted envelope, so the recipient can verify after decrypting.
            var args = ["--sign", "--encrypt", "--armor", "--batch", "--yes",
                        "--trust-model", "always", "--local-user", signerKeyID]
            for fp in recipientFingerprints { args += ["--recipient", fp] }
            log.info("signAndEncrypt: gpg args=\(args.joined(separator: " "))")
            let (encData, stderr, code) = try gpg(args, input: innerMIME)
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
            if gnupgHome == nil { try GPGAgent.ensureRunning() }
            // Decode quoted-printable body before extraction so GPG receives clean PGP armor.
            let (rawHdrs, bodyBytes) = splitMessage(data)
            let cte = foldedHeaderValue("content-transfer-encoding", in: rawHdrs)?
                .lowercased().trimmingCharacters(in: .whitespaces)
            let processedData: Data
            if cte == "quoted-printable", let bodyStr = String(data: bodyBytes, encoding: .utf8) {
                let eol = lineEnding(in: rawHdrs)
                processedData = (rawHdrs + eol + eol + decodeQuotedPrintable(bodyStr)).data(using: .utf8) ?? data
            } else {
                processedData = data
            }
            let payload = extractPGPPayload(from: processedData)
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
            if case .keyNotFound(let missingKeyID) = status {
                let senderEmail = extractFromEmail(from: data)
                let fallbackKeyID = missingKeyID != "unknown" ? missingKeyID : nil
                let keyFetched = (try? resolveKey(email: senderEmail, keyID: fallbackKeyID)) != nil

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
            env.removeValue(forKey: "GPG_TTY")
            if let home = gnupgHome { env["GNUPGHOME"] = home }
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

    // MARK: - Key management — see GPGServiceImpl+KeyManagement.swift

}
