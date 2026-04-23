// GPGAgent.swift
// MailGPG (host app only)

import Foundation

/// Manages the gpg-agent lifecycle and pinentry configuration.
///
/// gpg-agent is the long-running daemon that:
///  - caches passphrases so the user isn't prompted on every operation
///  - communicates with smartcard daemons (scdaemon) for YubiKey / OpenPGP card
///  - delegates PIN / passphrase prompts to a `pinentry` program
///
/// On macOS, `pinentry-mac` is the native GUI pinentry. Without it, GPG falls
/// back to `pinentry-curses` which needs a terminal — and silently hangs in a
/// background app like ours.
struct GPGAgent {

    // MARK: - Tool path helper

    /// Returns the path to a GPG-suite companion binary (e.g. `gpgconf`)
    /// by replacing the `gpg` filename in the located GPG binary's directory.
    static func toolPath(_ name: String) throws -> String {
        let gpg = try GPGLocator.locate()
        return URL(fileURLWithPath: gpg)
            .deletingLastPathComponent()
            .appendingPathComponent(name)
            .path
    }

    // MARK: - Agent lifecycle

    /// Ensure gpg-agent is running. Safe to call repeatedly — `gpgconf --launch`
    /// is a no-op when the agent is already up.
    ///
    /// Call this before any GPG operation that may need a passphrase or card PIN
    /// so the agent socket exists before GPG tries to connect to it.
    @discardableResult
    static func ensureRunning() throws -> Bool {
        let gpgconf = try toolPath("gpgconf")
        guard FileManager.default.isExecutableFile(atPath: gpgconf) else {
            // Older GPG without gpgconf — agent auto-starts on first use.
            return false
        }
        return run(gpgconf, args: ["--launch", "gpg-agent"])
    }

    /// Kill the running agent and start a fresh one.
    /// Required after writing changes to gpg-agent.conf.
    static func restart() throws {
        let gpgconf = try toolPath("gpgconf")
        run(gpgconf, args: ["--kill", "gpg-agent"])
        try ensureRunning()
    }

    // MARK: - Pinentry configuration

    /// The URL of `~/.gnupg/gpg-agent.conf` (or `$GNUPGHOME/gpg-agent.conf`).
    static var agentConfURL: URL {
        let base = ProcessInfo.processInfo.environment["GNUPGHOME"]
            ?? (NSHomeDirectory() as NSString).appendingPathComponent(".gnupg")
        return URL(fileURLWithPath: base).appendingPathComponent("gpg-agent.conf")
    }

    /// Known locations for `pinentry-mac` — the native macOS pinentry GUI.
    static let macPinentryPaths = [
        "/opt/homebrew/bin/pinentry-mac",
        "/usr/local/bin/pinentry-mac",
        "/usr/local/MacGPG2/libexec/pinentry-mac.app/Contents/MacOS/pinentry-mac",
        "/Applications/GPG Keychain.app/Contents/Resources/pinentry-mac",
    ]

    /// The first `pinentry-mac` binary found on this machine, or `nil`.
    static var availableMacPinentry: String? {
        macPinentryPaths.first { FileManager.default.isExecutableFile(atPath: $0) }
    }

    /// The current pinentry configuration state.
    enum PinentryStatus: Equatable {
        /// A macOS-native pinentry is configured and the file exists. ✅
        case ok(path: String)
        /// A non-GUI pinentry is configured (e.g. pinentry-curses). Will hang. ⚠️
        case nonMac(configured: String, fix: String?)
        /// No `pinentry-program` line in the config; macOS pinentry available. ⚠️
        case fixable(path: String)
        /// No config line and no macOS pinentry found anywhere. ❌
        case notInstalled
    }

    /// Read `gpg-agent.conf` and classify the current pinentry setup.
    static func checkPinentry() -> PinentryStatus {
        let content = (try? String(contentsOf: agentConfURL, encoding: .utf8)) ?? ""

        for line in content.components(separatedBy: "\n") {
            let t = line.trimmingCharacters(in: .whitespaces)
            guard !t.hasPrefix("#"), t.hasPrefix("pinentry-program") else { continue }
            let path = String(t.dropFirst("pinentry-program".count)).trimmingCharacters(in: .whitespaces)
            let isMac = path.contains("pinentry-mac") || path.contains("pinentry-touchid")
            if isMac && FileManager.default.isExecutableFile(atPath: path) {
                return .ok(path: path)
            }
            return .nonMac(configured: path, fix: availableMacPinentry)
        }

        // No pinentry-program line at all.
        if let available = availableMacPinentry { return .fixable(path: available) }
        return .notInstalled
    }

    /// Write `pinentry-program <path>` to `gpg-agent.conf` and restart the agent.
    static func configurePinentry(path: String) throws {
        guard !path.contains("\n"), !path.contains("\r"), path.hasPrefix("/") else {
            throw GPGXPCError.make(.encodingFailed, message: "Invalid pinentry path")
        }

        // Read existing config (or start fresh).
        var lines = (try? String(contentsOf: agentConfURL, encoding: .utf8))?
            .components(separatedBy: "\n") ?? []

        // Remove any existing pinentry-program line (active or commented).
        lines = lines.filter {
            !$0.trimmingCharacters(in: .whitespaces)
                .lowercased().hasPrefix("pinentry-program")
        }
        lines.append("pinentry-program \(path)")

        // Ensure ~/.gnupg exists.
        try FileManager.default.createDirectory(
            at: agentConfURL.deletingLastPathComponent(),
            withIntermediateDirectories: true)

        try lines.joined(separator: "\n")
            .write(to: agentConfURL, atomically: true, encoding: .utf8)

        try restart()
    }

    // MARK: - Private helpers

    @discardableResult
    private static func run(_ executable: String, args: [String]) -> Bool {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: executable)
        p.arguments = args
        var env = ProcessInfo.processInfo.environment
        env.removeValue(forKey: "DYLD_INSERT_LIBRARIES")
        p.environment = env
        p.standardOutput = FileHandle.nullDevice
        p.standardError  = FileHandle.nullDevice
        try? p.run()
        p.waitUntilExit()
        return p.terminationStatus == 0
    }
}
