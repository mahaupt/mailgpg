// DecryptionFailureLog.swift
// MailGPGExtension

import Foundation

/// A bounded, in-memory record of recent decryption failures, rendered by
/// `DiagnosticsView`.
///
/// Why this exists: `decodedMessage` returning `nil` is how MailKit is told "not my
/// message", and it is also what every decrypt error used to collapse into. That made
/// a missing secret key, a malformed MIME part and a gpg crash completely
/// indistinguishable — there was no way to tell which of them was behind a mail that
/// wouldn't open. Recording the reason and the key IDs gpg named costs nothing and
/// carries no risk to Mail, unlike surfacing a failure through `MEDecodedMessage`.
///
/// Deliberately memory-only: this is diagnostic data about encrypted mail, and it
/// should not outlive the extension process or reach disk.
final class DecryptionFailureLog: @unchecked Sendable {

    static let shared = DecryptionFailureLog()

    struct Entry: Identifiable {
        let id = UUID()
        let date: Date
        /// Message-Id where available, else the UUID header, else "(unknown message)".
        let messageID: String
        let subject: String?
        let reason: String
        /// Key IDs from `ENC_TO` — every key the message was encrypted to.
        let encryptedToKeyIDs: [String]
        /// Key IDs from `NO_SECKEY` — encrypted to these, but we hold no secret key.
        let missingSecretKeyIDs: [String]
    }

    /// Enough to cover a diagnosis session without letting the buffer grow unbounded.
    private static let limit = 25

    private let lock = NSLock()
    private var entries: [Entry] = []

    /// Most recent first.
    var recent: [Entry] {
        lock.lock(); defer { lock.unlock() }
        return entries.reversed()
    }

    func record(messageID: String?,
                subject: String?,
                reason: String,
                details: DecryptionDetails = DecryptionDetails(),
                date: Date = Date()) {
        let entry = Entry(date: date,
                          messageID: messageID ?? "(unknown message)",
                          subject: subject,
                          reason: reason,
                          encryptedToKeyIDs: details.encryptedToKeyIDs,
                          missingSecretKeyIDs: details.missingSecretKeyIDs)
        lock.lock()
        entries.append(entry)
        if entries.count > Self.limit { entries.removeFirst(entries.count - Self.limit) }
        lock.unlock()
    }

    func clear() {
        lock.lock(); entries.removeAll(); lock.unlock()
    }
}
