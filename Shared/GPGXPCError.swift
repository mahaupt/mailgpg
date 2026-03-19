// GPGXPCError.swift
// Shared — add to both MailGPG and MailGPGExtension targets

import Foundation

/// The error domain used for all XPC bridge errors.
let GPGXPCErrorDomain = "com.mahaupt.mailgpg.xpc"

/// Typed error codes that cross the XPC boundary.
///
/// XPC only speaks `NSError`, so we represent errors as integer codes
/// in a shared domain. Both sides use `GPGXPCError.make(_:)` to create
/// errors and `GPGXPCError(nsError:)` to read them back.
enum GPGXPCError: Int, Error {
    /// The host app is not running — the user must open MailGPG first.
    case hostAppNotRunning  = 1
    /// GPG binary not found at any known path on this machine.
    case gpgNotFound        = 2
    /// GPG ran but exited with a non-zero status. The error's
    /// `localizedDescription` contains the stderr output.
    case gpgFailed          = 3
    /// The requested key was not found locally or on the keyserver.
    case keyNotFound        = 4
    /// JSON encoding or decoding failed on one side of the bridge.
    case encodingFailed     = 5

    /// Create an `NSError` suitable for sending through XPC.
    static func make(_ code: GPGXPCError, message: String? = nil) -> NSError {
        var info: [String: Any] = [:]
        if let message {
            info[NSLocalizedDescriptionKey] = message
        }
        return NSError(domain: GPGXPCErrorDomain, code: code.rawValue, userInfo: info)
    }

    /// Read an `NSError` that came back through XPC.
    /// Returns `nil` if the error belongs to a different domain.
    init?(nsError: Error) {
        let ns = nsError as NSError
        guard ns.domain == GPGXPCErrorDomain,
              let code = GPGXPCError(rawValue: ns.code) else { return nil }
        self = code
    }
}
