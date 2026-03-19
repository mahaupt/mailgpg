// MessageSecurityHandler.swift
// MailGPGExtension

import MailKit
import os

private let log = Logger(subsystem: "com.mahaupt.mailgpg", category: "encode")

class MessageSecurityHandler: NSObject, MEMessageSecurityHandler {

    static let shared = MessageSecurityHandler()

    // MARK: - Encoding (outgoing)

    func getEncodingStatus(for message: MEMessage, composeContext: MEComposeContext, completionHandler: @escaping (MEOutgoingMessageEncodingStatus) -> Void) {
        let state = sessionState(for: message)

        let allRecipients = message.toAddresses + message.ccAddresses + message.bccAddresses
        let failingAddresses: [MEEmailAddress] = allRecipients.filter { address in
            state?.recipientKeyStatus[address.rawString.lowercased()] == .notFound
        }

        completionHandler(MEOutgoingMessageEncodingStatus(
            canSign: true,
            canEncrypt: state?.canEncrypt ?? false,
            securityError: nil,
            addressesFailingEncryption: failingAddresses
        ))
    }

    func encode(_ message: MEMessage, composeContext: MEComposeContext, completionHandler: @escaping (MEMessageEncodingResult) -> Void) {
        let shouldSign    = header("x-mailgpg-sign",    in: message) == "1"
        let shouldEncrypt = header("x-mailgpg-encrypt", in: message) == "1"
        let allHeaders    = message.headers?.keys.sorted().joined(separator: ", ") ?? "(nil)"

        log.debug("encode called — shouldSign=\(shouldSign) shouldEncrypt=\(shouldEncrypt) headers=[\(allHeaders)]")

        guard shouldSign || shouldEncrypt else {
            log.info("encode: no sign/encrypt requested — passing through unchanged")
            completionHandler(MEMessageEncodingResult(encodedMessage: nil, signingError: nil, encryptionError: nil))
            return
        }

        guard let body = message.rawData else {
            log.error("encode: message.rawData is nil — cannot sign/encrypt")
            completionHandler(MEMessageEncodingResult(encodedMessage: nil, signingError: nil, encryptionError: nil))
            return
        }

        let rawPreview = String(data: body.prefix(400), encoding: .utf8) ?? "(non-utf8)"
        log.info("encode: rawData size=\(body.count) bytes, sender=\(message.fromAddress.rawString), preview=\(rawPreview)")

        let senderEmail  = message.fromAddress.rawString.lowercased()
        let fingerprints = sessionState(for: message)?.recipientKeys.values.map(\.fingerprint) ?? []

        Task {
            do {
                let encodedData: MEEncodedOutgoingMessage

                if shouldSign {
                    log.info("encode: fetching secret keys via XPC…")
                    let secretKeys = try await GPGService.shared.listSecretKeys()
                    log.info("encode: got \(secretKeys.count) secret key(s): \(secretKeys.map { "\($0.keyID)(\($0.email)) revoked=\($0.isRevoked)" }.joined(separator: ", "))")

                    let usable = secretKeys.filter { !$0.isRevoked && $0.expiresAt.map { $0 > Date() } ?? true }
                    log.info("encode: \(usable.count) usable key(s) after filtering revoked/expired")

                    guard let signerKey = usable.first(where: { $0.email.lowercased() == senderEmail })
                                      ?? usable.first else {
                        log.error("encode: no usable secret key found for sender \(senderEmail)")
                        completionHandler(MEMessageEncodingResult(
                            encodedMessage: nil,
                            signingError: GPGXPCError.make(.keyNotFound, message: "No secret key found for \(senderEmail)"),
                            encryptionError: nil))
                        return
                    }

                    log.info("encode: signing with key \(signerKey.keyID) (\(signerKey.email))")

                    if shouldEncrypt {
                        log.info("encode: sign+encrypt to \(fingerprints.count) recipient(s)")
                        encodedData = MEEncodedOutgoingMessage(
                            rawData: try await GPGService.shared.signAndEncrypt(
                                data: body, signerKeyID: signerKey.keyID,
                                recipientFingerprints: fingerprints),
                            isSigned: true, isEncrypted: true)
                        log.info("encode: sign+encrypt succeeded")
                    } else {
                        encodedData = MEEncodedOutgoingMessage(
                            rawData: try await GPGService.shared.sign(
                                data: body, signerKeyID: signerKey.keyID),
                            isSigned: true, isEncrypted: false)
                        log.info("encode: sign succeeded")
                    }
                } else {
                    log.info("encode: encrypt-only to \(fingerprints.count) recipient(s)")
                    encodedData = MEEncodedOutgoingMessage(
                        rawData: try await GPGService.shared.encrypt(
                            data: body, recipientFingerprints: fingerprints),
                        isSigned: false, isEncrypted: true)
                    log.info("encode: encrypt succeeded")
                }

                let preview = String(data: encodedData.rawData.prefix(300), encoding: .utf8) ?? "(non-utf8)"
                log.info("encode: encoded \(encodedData.rawData.count) bytes — first 300: \(preview)")
                log.info("encode: calling completionHandler with \(encodedData.rawData.count) bytes")
                completionHandler(MEMessageEncodingResult(encodedMessage: encodedData, signingError: nil, encryptionError: nil))

            } catch {
                log.error("encode: failed — \(error.localizedDescription)")
                let nsError = error as NSError
                completionHandler(MEMessageEncodingResult(
                    encodedMessage: nil,
                    signingError: shouldSign ? nsError : nil,
                    encryptionError: shouldEncrypt ? nsError : nil))
            }
        }
    }

    // MARK: - Session lookup

    /// Finds the ComposeSessionState for an outgoing message by reading the
    /// X-MailGPG-SessionID header that ComposeSessionHandler injects.
    /// Falls back to singleActiveState so single-window use always works.
    /// Uses case-insensitive lookup because Mail normalises header capitalisation.
    private func sessionState(for message: MEMessage) -> ComposeSessionState? {
        if let idString = header("x-mailgpg-sessionid", in: message),
           let uuid = UUID(uuidString: idString) {
            return ComposeStateStore.shared.state(for: uuid)
        }
        return ComposeStateStore.shared.singleActiveState
    }

    /// Case-insensitive header lookup.
    /// Mail normalises header key capitalisation (RFC 2822 keys are case-insensitive),
    /// so direct dictionary access by the original key name is unreliable.
    private func header(_ name: String, in message: MEMessage) -> String? {
        guard let headers = message.headers else { return nil }
        guard let key = headers.keys.first(where: { $0.lowercased() == name }) else { return nil }
        return headers[key]?.first
    }

    // MARK: - Decoding (incoming)

    func decodedMessage(forMessageData data: Data) -> MEDecodedMessage? {
        // Quick pre-check: only process messages that look like PGP content.
        // Returning nil for everything else tells Mail "not my message" and avoids:
        //   • unnecessary XPC round-trips for plaintext mail
        //   • calling gpg --decrypt on multipart/signed mails we just sent, which
        //     would produce a spurious "decryption failed" banner in Sent
        let preview = String(data: data.prefix(4096), encoding: .utf8) ?? ""
        let isEncrypted = preview.contains("multipart/encrypted") ||
                          preview.contains("BEGIN PGP MESSAGE")
        let isSigned    = preview.contains("multipart/signed") ||
                          preview.contains("BEGIN PGP SIGNED MESSAGE")

        log.debug("decodedMessage: \(data.count) bytes — encrypted=\(isEncrypted) signed=\(isSigned)")

        guard isEncrypted else {
            // Signed-only (multipart/signed) and plain messages: return nil so Mail
            // renders them natively.  We do NOT call gpg --decrypt on signed-only mail
            // because (a) it fails, and (b) returning a decryptionFailed MEDecodedMessage
            // with the raw multipart/signed data causes Mail to crash.
            // TODO Step 9: call gpg --verify for multipart/signed to show a verified banner.
            log.debug("decodedMessage: not encrypted — returning nil")
            return nil
        }

        // MailKit requires this method to be synchronous, but our GPG calls are async.
        // We bridge with a DispatchSemaphore: a detached Task does the async work on its
        // own thread, signals when done, and the calling thread waits.
        // Using Task.detached avoids blocking a thread the cooperative executor might need.
        var result: MEDecodedMessage? = nil
        let semaphore = DispatchSemaphore(value: 0)

        Task.detached {
            do {
                let (plaintext, status) = try await GPGService.shared.decrypt(data: data)
                log.debug("decodedMessage: decrypt succeeded, status=\(String(describing: status))")
                result = Self.makeDecodedMessage(data: plaintext, status: status)
            } catch let error as NSError {
                log.error("decodedMessage: decrypt error — \(error.localizedDescription)")
                switch GPGXPCError(nsError: error) {
                case .gpgFailed:
                    // GPG ran but failed (e.g. wrong key, corrupted data) — surface the error.
                    result = Self.makeDecodedMessage(
                        data: data,
                        status: .decryptionFailed(reason: error.localizedDescription))
                default:
                    // Host app not running, GPG not found, or not a GPG message — pass through.
                    result = nil
                }
            }
            semaphore.signal()
        }

        semaphore.wait()
        return result
    }

    static nonisolated func makeDecodedMessage(data: Data, status: SecurityStatus) -> MEDecodedMessage? {
        let meSigners: [MEMessageSigner] = {
            switch status {
            case .signed(let signers), .encrypted(let signers):
                return signers.map {
                    MEMessageSigner(emailAddresses: [MEEmailAddress(rawString: $0.email)], signatureLabel: $0.keyID, context: nil)
                }
            default: return []
            }
        }()

        let securityInfo = MEMessageSecurityInformation(
            signers: meSigners,
            isEncrypted: { if case .encrypted = status { return true }; return false }(),
            signingError: { if case .signatureInvalid(let r) = status { return NSError(domain: "MailGPG", code: 1, userInfo: [NSLocalizedDescriptionKey: r]) }; return nil }(),
            encryptionError: { if case .decryptionFailed(let r) = status { return NSError(domain: "MailGPG", code: 2, userInfo: [NSLocalizedDescriptionKey: r]) }; return nil }()
        )

        let context = try? JSONEncoder().encode(status)
        return MEDecodedMessage(data: data, securityInformation: securityInfo, context: context)
    }

    // MARK: - UI

    func extensionViewController(signers messageSigners: [MEMessageSigner]) -> MEExtensionViewController? {
        // Try to decode the full status from the context Data attached to each signer.
        // (We encode SecurityStatus as JSON context in makeDecodedMessage.)
        if let context = messageSigners.first?.context,
           let status = try? JSONDecoder().decode(SecurityStatus.self, from: context) {
            return SecurityDetailViewController(status: status)
        }
        // Fallback: build a .signed status from the signer labels MailKit provides.
        let signers = messageSigners.compactMap { s -> Signer? in
            guard let email = s.emailAddresses.first?.rawString else { return nil }
            return Signer(email: email, keyID: s.label, fingerprint: s.label, trusted: true)
        }
        return SecurityDetailViewController(status: .signed(signers: signers))
    }

    func extensionViewController(messageContext context: Data) -> MEExtensionViewController? {
        guard let status = try? JSONDecoder().decode(SecurityStatus.self, from: context) else {
            return SecurityDetailViewController(status: .plain)
        }
        return SecurityDetailViewController(status: status)
    }

    func primaryActionClicked(forMessageContext context: Data, completionHandler: @escaping (MEExtensionViewController?) -> Void) {
        completionHandler(extensionViewController(messageContext: context))
    }
}
