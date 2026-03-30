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
    /// Full 40-character fingerprint of the generated test key.
    private(set) var fingerprint: String = ""
    /// Email address used for the test key.
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
