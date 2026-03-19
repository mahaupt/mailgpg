// GPGXPCProtocol.swift
// Shared — add to both MailGPG and MailGPGExtension targets

import Foundation

/// The XPC interface between the sandboxed Mail extension and the host app.
///
/// ## Why `@objc`?
/// XPC is a C-level IPC mechanism. Swift's type system doesn't map directly
/// onto it — only Objective-C types do. Marking the protocol `@objc` tells
/// Swift to expose it through the Objective-C runtime, which XPC can inspect
/// and serialize.
///
/// ## Why `Data` instead of `SecurityStatus` / `KeyInfo` directly?
/// XPC can only send a limited set of types across process boundaries:
/// `String`, `Int`, `Bool`, `Data`, `Array`, `Dictionary`, `NSError`, and
/// a few others. Our custom Swift types (`SecurityStatus`, `KeyInfo`) don't
/// qualify. The solution: JSON-encode them into `Data` on one side, send
/// the raw bytes, and JSON-decode on the other side.
///
/// ## Why completion handlers instead of `async`?
/// XPC predates Swift concurrency. The underlying `NSXPCConnection` API
/// only supports completion-handler-style callbacks. We'll wrap these in
/// `async/await` in `GPGService.swift` (extension side only).
@objc protocol GPGXPCProtocol {

    // MARK: - Diagnostics

    /// Round-trip test. The host app replies with its GPG version string,
    /// or an error if GPG isn't found. Use this to verify the XPC bridge works.
    func ping(reply: @escaping (_ gpgVersion: String?, Error?) -> Void)

    // MARK: - Outgoing (signing / encryption)

    /// Sign `data` using the secret key identified by `signerKeyID`.
    /// The reply is a PGP/MIME detached signature block.
    func sign(
        data: Data,
        signerKeyID: String,
        reply: @escaping (Data?, Error?) -> Void
    )

    /// Encrypt `data` for the given recipient fingerprints.
    /// The reply is the PGP-encrypted payload.
    func encrypt(
        data: Data,
        recipientFingerprints: [String],
        reply: @escaping (Data?, Error?) -> Void
    )

    /// Sign and encrypt in one step.
    func signAndEncrypt(
        data: Data,
        signerKeyID: String,
        recipientFingerprints: [String],
        reply: @escaping (Data?, Error?) -> Void
    )

    // MARK: - Incoming (decryption / verification)

    /// Decrypt `data`. Returns two values in the reply:
    /// - `plaintextData`: the decrypted message bytes
    /// - `statusJSON`: a JSON-encoded `SecurityStatus` describing the result
    func decrypt(
        data: Data,
        reply: @escaping (_ plaintextData: Data?, _ statusJSON: Data?, Error?) -> Void
    )

    /// Verify a detached PGP signature.
    /// Returns a JSON-encoded `SecurityStatus` in the reply.
    func verify(
        data: Data,
        signature: Data,
        reply: @escaping (_ statusJSON: Data?, Error?) -> Void
    )

    // MARK: - Key management

    /// Look up a key for `email`. Checks the local keychain first; falls back
    /// to the keyserver if not found. Returns a JSON-encoded `KeyInfo`, or
    /// `nil` data (+ no error) when the key genuinely doesn't exist anywhere.
    func lookupKey(
        email: String,
        reply: @escaping (_ keyInfoJSON: Data?, Error?) -> Void
    )

    /// List all secret keys available for signing.
    /// Returns a JSON-encoded `[KeyInfo]`.
    func listSecretKeys(
        reply: @escaping (_ keyListJSON: Data?, Error?) -> Void
    )

    /// Import an ASCII-armored public key into the local keychain.
    /// Returns a JSON-encoded `KeyInfo` for the imported key.
    func importKey(
        armoredKey: String,
        reply: @escaping (_ keyInfoJSON: Data?, Error?) -> Void
    )
}

// MARK: - JSON helpers

/// Convenience for encoding a `Codable` value to `Data`.
/// Used on the host-app side before sending a reply.
func xpcEncode<T: Encodable>(_ value: T) throws -> Data {
    do {
        return try JSONEncoder().encode(value)
    } catch {
        throw GPGXPCError.make(.encodingFailed, message: "Encode failed: \(error)")
    }
}

/// Convenience for decoding a `Codable` value from `Data`.
/// Used on the extension side after receiving a reply.
func xpcDecode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
    do {
        return try JSONDecoder().decode(type, from: data)
    } catch {
        throw GPGXPCError.make(.encodingFailed, message: "Decode failed: \(error)")
    }
}
