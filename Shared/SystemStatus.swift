// SystemStatus.swift
// Shared — add to both MailGPG and MailGPGExtension targets

/// A snapshot of the GPG environment on the host machine.
/// JSON-encoded for XPC transport.
struct SystemStatus: Codable {

    // MARK: - GPG binary

    /// Absolute path to the GPG binary found on this machine, or `nil` if not found.
    let gpgPath: String?
    /// First line of `gpg --version`, e.g. "gpg (GnuPG) 2.4.7". `nil` if GPG not found.
    let gpgVersion: String?

    // MARK: - gpg-agent

    /// Whether gpg-agent is currently running (confirmed by `gpgconf --launch`).
    let agentRunning: Bool

    // MARK: - Pinentry

    enum PinentryState: String, Codable {
        /// A macOS-native pinentry is configured and the binary exists. ✅
        case ok
        /// No `pinentry-program` line in the config; `pinentry-mac` is available
        /// and can be configured automatically. ⚠️
        case fixable
        /// A non-GUI pinentry is configured (e.g. `pinentry-curses`). Will hang
        /// in a background app. A fix may or may not be available. ⚠️
        case nonMac
        /// No config line and no macOS pinentry found anywhere. ❌
        case notInstalled
    }

    /// Current pinentry configuration state.
    let pinentryState: PinentryState
    /// The pinentry path currently written in `gpg-agent.conf`, if any.
    let pinentryConfiguredPath: String?
    /// The path to `pinentry-mac` that can be used for an automatic fix, if available.
    let pinentryAvailablePath: String?
}
