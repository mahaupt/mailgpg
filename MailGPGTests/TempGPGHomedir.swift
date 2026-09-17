// TempGPGHomedir.swift
// MailGPGTests – test infrastructure

import Foundation
import XCTest
@testable import MailGPG

/// An isolated GPG homedir in a temp directory, pre-populated with a single
/// no-passphrase RSA test key pair. Used by integration tests so they never
/// touch the user's real ~/.gnupg.
///
/// Usage:
///   override func setUpWithError() throws {
///       homedir = try TempGPGHomedir()
///       svc = GPGServiceImpl(gnupgHome: homedir.path)
///   }
///   override func tearDownWithError() throws { homedir = nil }
///
/// deinit kills the gpg-agent for this homedir and removes the directory.
final class TempGPGHomedir {

    /// Absolute path to the isolated homedir.
    let path: String
    /// Full 40-character fingerprint of the primary (RSA) test key.
    private(set) var fingerprint: String = ""
    /// Full 40-character fingerprint of the SECOND key on the same address.
    ///
    /// Two currently-valid keys for one identity (typically an RSA and an ECC key) is
    /// what makes auto-matching by address ambiguous, so the tests need a keyring
    /// that actually exhibits it.
    private(set) var secondFingerprint: String = ""
    /// Email address used for both test keys.
    let email = "mailgpg-test@example.com"

    init() throws {
        // Use /tmp (not NSTemporaryDirectory) to keep the path short.
        // macOS Unix domain socket paths are limited to ~104 chars.
        // NSTemporaryDirectory() resolves to /var/folders/…/T/ (~60 chars),
        // which leaves no room for the UUID + "/S.gpg-agent" suffix.
        let url = URL(fileURLWithPath: "/tmp")
            .appendingPathComponent("gpg-\(UUID().uuidString.prefix(8))")
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        // GPG requires 0700 on the homedir or it refuses to use it.
        try FileManager.default.setAttributes([.posixPermissions: 0o700],
                                               ofItemAtPath: url.path)
        self.path = url.path

        // allow-loopback-pinentry: prevents GPG from ever opening a GUI passphrase
        // dialog. Combined with %no-protection keys, no pinentry is ever invoked.
        try "allow-loopback-pinentry\n".write(
            toFile: url.appendingPathComponent("gpg-agent.conf").path,
            atomically: true, encoding: .utf8)

        fingerprint = try generateTestKey()
        secondFingerprint = try generateSecondTestKey()
    }

    deinit {
        killAgent()
        try? FileManager.default.removeItem(atPath: path)
    }

    // MARK: - Setup helpers

    private func generateTestKey() throws -> String {
        let batch = """
            %echo Generating MailGPG integration-test key
            Key-Type: RSA
            Key-Length: 2048
            Subkey-Type: RSA
            Subkey-Length: 2048
            Name-Real: MailGPG Test
            Name-Email: \(email)
            Expire-Date: 0
            %no-protection
            %commit
            """
        let batchURL = URL(fileURLWithPath: path).appendingPathComponent("keygen.batch")
        try batch.write(to: batchURL, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: batchURL) }

        let (_, stderr, code) = try run(["--batch", "--gen-key", batchURL.path])
        guard code == 0 else {
            throw NSError(domain: "TempGPGHomedir", code: Int(code), userInfo: [
                NSLocalizedDescriptionKey: "Key generation failed (exit \(code)): \(stderr)"
            ])
        }
        return try extractFingerprint(for: email)
    }

    /// A second, ECC key on the SAME address as the first.
    private func generateSecondTestKey() throws -> String {
        let batch = """
            %echo Generating MailGPG integration-test key 2 (ECC)
            Key-Type: EDDSA
            Key-Curve: ed25519
            Subkey-Type: ECDH
            Subkey-Curve: cv25519
            Name-Real: MailGPG Test ECC
            Name-Email: \(email)
            Expire-Date: 0
            %no-protection
            %commit
            """
        let batchURL = URL(fileURLWithPath: path).appendingPathComponent("keygen2.batch")
        try batch.write(to: batchURL, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: batchURL) }

        let (_, stderr, code) = try run(["--batch", "--gen-key", batchURL.path])
        guard code == 0 else {
            throw NSError(domain: "TempGPGHomedir", code: Int(code), userInfo: [
                NSLocalizedDescriptionKey: "Second key generation failed (exit \(code)): \(stderr)"
            ])
        }
        // Both keys share an address, so select by fingerprint difference rather than
        // by email — --list-keys returns them in keyring order, not creation order.
        // Only PRIMARY key fingerprints count: gpg emits an `fpr` record for every
        // subkey as well, and picking one of those yields a fingerprint that has no
        // secret-key entry of its own.
        let (out, _, _) = try run(["--list-keys", "--with-colons", "--fixed-list-mode", email])
        let text = String(data: out, encoding: .utf8) ?? ""
        var primaryFingerprints: [String] = []
        var expectingPrimaryFpr = false
        for line in text.split(separator: "\n") {
            let f = line.split(separator: ":", omittingEmptySubsequences: false)
            switch f.first {
            case "pub":
                expectingPrimaryFpr = true
            case "fpr" where expectingPrimaryFpr:
                if f.count >= 10, f[9].count == 40 { primaryFingerprints.append(String(f[9])) }
                expectingPrimaryFpr = false
            case "sub":
                expectingPrimaryFpr = false
            default:
                break
            }
        }
        guard let second = primaryFingerprints.first(where: { $0 != fingerprint }) else {
            throw NSError(domain: "TempGPGHomedir", code: -1, userInfo: [
                NSLocalizedDescriptionKey: "Second key fingerprint not found"
            ])
        }
        return second
    }

    private func extractFingerprint(for email: String) throws -> String {
        let (out, _, _) = try run(["--list-keys", "--with-colons", "--fixed-list-mode", email])
        let text = String(data: out, encoding: .utf8) ?? ""
        for line in text.split(separator: "\n") {
            let fields = line.split(separator: ":", omittingEmptySubsequences: false)
            if fields.first == "fpr", fields.count >= 10 {
                let fp = String(fields[9])
                if !fp.isEmpty { return fp }
            }
        }
        throw NSError(domain: "TempGPGHomedir", code: -1, userInfo: [
            NSLocalizedDescriptionKey: "Could not extract fingerprint for \(email)"
        ])
    }

    private func killAgent() {
        guard let gpgPath = try? GPGLocator.locate() else { return }
        let gpgconfPath = URL(fileURLWithPath: gpgPath)
            .deletingLastPathComponent()
            .appendingPathComponent("gpgconf").path
        guard FileManager.default.isExecutableFile(atPath: gpgconfPath) else { return }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: gpgconfPath)
        p.arguments = ["--homedir", path, "--kill", "gpg-agent"]
        p.environment = makeEnv()
        p.standardOutput = FileHandle.nullDevice
        p.standardError  = FileHandle.nullDevice
        try? p.run()
        p.waitUntilExit()
    }

    // MARK: - GPG subprocess runner

    /// Run a GPG command inside this homedir. Returns (stdout, stderr, exitCode).
    /// Used by test fixtures for setup/teardown operations outside of GPGServiceImpl.
    func run(_ args: [String], input: Data? = nil) throws -> (Data, String, Int32) {
        let gpgPath = try GPGLocator.locate()
        let process = Process()
        process.executableURL = URL(fileURLWithPath: gpgPath)
        process.arguments = ["--no-tty"] + args
        process.environment = makeEnv()

        let outPipe = Pipe()
        let errPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError  = errPipe

        if let input {
            let inPipe = Pipe()
            process.standardInput = inPipe
            try process.run()
            DispatchQueue.global().async {
                inPipe.fileHandleForWriting.write(input)
                inPipe.fileHandleForWriting.closeFile()
            }
        } else {
            try process.run()
        }

        // Read stdout and stderr concurrently to prevent pipe-buffer deadlock.
        var stdout  = Data()
        var errData = Data()
        let group   = DispatchGroup()
        group.enter()
        DispatchQueue.global().async {
            stdout = outPipe.fileHandleForReading.readDataToEndOfFile()
            group.leave()
        }
        group.enter()
        DispatchQueue.global().async {
            errData = errPipe.fileHandleForReading.readDataToEndOfFile()
            group.leave()
        }
        group.wait()
        process.waitUntilExit()

        return (stdout, String(data: errData, encoding: .utf8) ?? "", process.terminationStatus)
    }

    private func makeEnv() -> [String: String] {
        var env = ProcessInfo.processInfo.environment
        env["GNUPGHOME"] = path
        env.removeValue(forKey: "DYLD_INSERT_LIBRARIES")
        env.removeValue(forKey: "GPG_TTY")
        return env
    }
}
