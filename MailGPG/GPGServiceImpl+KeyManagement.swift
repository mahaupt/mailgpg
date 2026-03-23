// GPGServiceImpl+KeyManagement.swift
// MailGPG (host app only)

import Foundation
import os

extension GPGServiceImpl {

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

    /// Resolve a key by email address and/or key ID.
    ///
    /// Lookup order:
    ///   1. Local keyring by email (fast, no network)
    ///   2. WKD + default keyserver by email (`--locate-keys`)
    ///   3. Each extra keyserver by email (`--locate-keys --keyserver <url>`)
    ///   4. Each keyserver by key ID (`--recv-keys`) — only when `keyID` is given
    ///
    /// Returns the best usable key found, or `nil` if none was found.
    /// Keys are auto-imported by GPG on steps 2–4.
    func resolveKey(email: String? = nil, keyID: String? = nil) throws -> KeyInfo? {
        // ── Step 1: local keyring by email ───────────────────────────────
        if let email {
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

            // ── Step 2: WKD + default keyserver by email ─────────────────
            // --locate-keys finds a key by e-mail address and auto-imports it.
            // --auto-key-locate order:
            //   wkd       = Web Key Directory (HTTPS from recipient's domain)
            //   keyserver = configured keyserver, defaults to keys.openpgp.org
            // --keyserver-options timeout=10: don't block indefinitely.
            // --no-auto-check-trustdb: skip trust-DB rebuild (~1 s saved).
            let (remoteOut, _, remoteCode) = try gpg([
                "--keyserver", defaultKeyserver,
                "--locate-keys",
                "--auto-key-locate", "wkd,keyserver",
                "--keyserver-options", "timeout=10",
                "--no-auto-check-trustdb",
                "--with-colons",
                "--fixed-list-mode",
                email
            ])
            if remoteCode == 0 {
                let keys = parseColonOutput(String(data: remoteOut, encoding: .utf8) ?? "",
                                            wantSecretKeys: false)
                let usable = keys.filter { !$0.isRevoked && ($0.expiresAt.map { $0 > Date() } ?? true) }
                if let key = usable.first ?? keys.first(where: { !$0.isRevoked }) {
                    return key
                }
            }

            // ── Step 3: extra keyservers by email ─────────────────────────
            for ks in extraKeyservers {
                let (ksOut, _, ksCode) = try gpg([
                    "--keyserver", ks,
                    "--locate-keys",
                    "--auto-key-locate", "keyserver",
                    "--keyserver-options", "timeout=10",
                    "--no-auto-check-trustdb",
                    "--with-colons",
                    "--fixed-list-mode",
                    email
                ])
                guard ksCode == 0 else { continue }
                let keys = parseColonOutput(String(data: ksOut, encoding: .utf8) ?? "",
                                            wantSecretKeys: false)
                let usable = keys.filter { !$0.isRevoked && ($0.expiresAt.map { $0 > Date() } ?? true) }
                if let key = usable.first ?? keys.first(where: { !$0.isRevoked }) {
                    log.info("resolveKey: found via \(ks) for \(email)")
                    return key
                }
            }
        }

        // ── Step 4: recv-keys by key ID across all keyservers ────────────
        // --recv-keys produces no colon output, so after a successful import
        // do a local --list-keys to get a proper KeyInfo to return.
        if let keyID {
            for ks in [defaultKeyserver] + extraKeyservers {
                var args = ["--keyserver", ks, "--recv-keys", "--keyserver-options", "timeout=10"]
                args.append(keyID)
                guard (try gpg(args)).exitCode == 0 else { continue }
                log.info("resolveKey: recv-keys succeeded for \(keyID) on \(ks ?? "default")")
                let (listOut, _, _) = try gpg(
                    ["--list-keys", "--with-colons", "--fixed-list-mode", keyID])
                let keys = parseColonOutput(String(data: listOut, encoding: .utf8) ?? "",
                                            wantSecretKeys: false)
                return keys.first
            }
        }

        return nil
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
