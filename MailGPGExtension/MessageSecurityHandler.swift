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

        // Always report canEncrypt: true so the native encrypt button is available.
        // Recipients without keys are annotated as warnings but don't disable the button.
        // If the user sends with encryption on and keys are missing, encode() will
        // surface an error letting them choose to cancel or send without encryption.
        let allRecipients = message.toAddresses + message.ccAddresses + message.bccAddresses
        let failingAddresses: [MEEmailAddress] = allRecipients.filter { address in
            state?.recipientKeyStatus[address.rawString.lowercased()] == .notFound
        }

        completionHandler(MEOutgoingMessageEncodingStatus(
            canSign: true,
            canEncrypt: true,
            securityError: nil,
            addressesFailingEncryption: failingAddresses
        ))
    }

    func encode(_ message: MEMessage, composeContext: MEComposeContext, completionHandler: @escaping (MEMessageEncodingResult) -> Void) {
        let shouldSign    = composeContext.shouldSign
        let shouldEncrypt = composeContext.shouldEncrypt

        log.info("encode called — shouldSign=\(shouldSign) shouldEncrypt=\(shouldEncrypt)")

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
        let state = sessionState(for: message)
        let fingerprints = state?.recipientKeys.values.map(\.fingerprint) ?? []

        // Check if encryption is requested but some recipients are missing keys.
        if shouldEncrypt {
            let allRecipients = message.toAddresses + message.ccAddresses + message.bccAddresses
            let missingEmails = allRecipients
                .map { $0.rawString.lowercased() }
                .filter { state?.recipientKeyStatus[$0] != .found }

            if !missingEmails.isEmpty {
                let list = missingEmails.joined(separator: ", ")
                log.error("encode: encryption requested but missing keys for: \(list)")
                completionHandler(MEMessageEncodingResult(
                    encodedMessage: nil,
                    signingError: nil,
                    encryptionError: NSError(
                        domain: "com.mahaupt.mailgpg", code: 3,
                        userInfo: [NSLocalizedDescriptionKey:
                            "The following recipients don't have a public key:\n\(list)\n\n" +
                            "Turn off encryption to send without it, or add the missing keys."])))
                return
            }
        }

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
        // Scan the entire header block rather than a fixed byte prefix: routing
        // headers added by Gmail, Exchange, etc. (DKIM, ARC, Received, …) can
        // push Content-Type well past 4 KB.
        let eohRange = data.range(of: "\r\n\r\n".data(using: .utf8)!)
                    ?? data.range(of: "\n\n".data(using: .utf8)!)
        let headerData = eohRange.map { Data(data[..<$0.lowerBound]) } ?? data
        let preview = String(data: headerData, encoding: .utf8) ?? ""
        let isEncrypted = preview.contains("multipart/encrypted") ||
                          preview.contains("BEGIN PGP MESSAGE")
        let isSigned    = preview.contains("multipart/signed") ||
                          preview.contains("BEGIN PGP SIGNED MESSAGE")

        log.debug("decodedMessage: \(data.count) bytes — encrypted=\(isEncrypted) signed=\(isSigned)")

        guard isEncrypted || isSigned else {
            log.debug("decodedMessage: not encrypted or signed — returning nil")
            return nil
        }

        // MailKit requires this method to be synchronous, but our GPG calls are async.
        // We bridge with a DispatchSemaphore: a detached Task does the async work on its
        // own thread, signals when done, and the calling thread waits.
        // Using Task.detached avoids blocking a thread the cooperative executor might need.
        var result: MEDecodedMessage? = nil
        let semaphore = DispatchSemaphore(value: 0)

        if isSigned && !isEncrypted {
            // Signed-only: extract the signed data and detached signature,
            // then call gpg --verify to check the signature.
            Task.detached {
                do {
                    let (signedData, signatureData) = Self.extractSignedParts(from: data)
                    guard let signedData, let signatureData else {
                        log.error("decodedMessage: could not extract signed parts from multipart/signed")
                        semaphore.signal()
                        return
                    }
                    log.debug("decodedMessage: verifying signature (\(signedData.count) data bytes, \(signatureData.count) sig bytes)")
                    let status = try await GPGService.shared.verify(data: signedData, signature: signatureData)
                    log.debug("decodedMessage: verify result=\(String(describing: status))")
                    result = Self.makeDecodedMessage(data: data, status: status)
                } catch let error as NSError {
                    log.error("decodedMessage: verify error — \(error.localizedDescription)")
                    switch GPGXPCError(nsError: error) {
                    case .gpgFailed:
                        result = Self.makeDecodedMessage(
                            data: data,
                            status: .signatureInvalid(reason: error.localizedDescription))
                    default:
                        result = nil
                    }
                }
                semaphore.signal()
            }
        } else {
            // Encrypted (possibly also signed): decrypt.
            Task.detached {
                do {
                    let (plaintext, status) = try await GPGService.shared.decrypt(data: data)
                    log.debug("decodedMessage: decrypt succeeded, status=\(String(describing: status))")
                    result = Self.makeDecodedMessage(data: plaintext, status: status)
                } catch let error as NSError {
                    log.error("decodedMessage: decrypt error — \(error.localizedDescription)")
                    switch GPGXPCError(nsError: error) {
                    case .gpgFailed:
                        result = Self.makeDecodedMessage(
                            data: data,
                            status: .decryptionFailed(reason: error.localizedDescription))
                    default:
                        result = nil
                    }
                }
                semaphore.signal()
            }
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

    // MARK: - Multipart/signed parser

    /// Extract the signed data (first MIME part) and detached PGP signature
    /// (second MIME part) from a multipart/signed message.
    ///
    /// RFC 3156 §5: the first part is the signed content (must be passed to
    /// gpg --verify byte-for-byte), and the second part is the detached signature.
    private static func extractSignedParts(from data: Data) -> (signedData: Data?, signature: Data?) {
        guard let str = String(data: data, encoding: .utf8) else { return (nil, nil) }

        // Find the boundary from the Content-Type header.
        var boundary: String? = nil
        if let s = str.range(of: "boundary=\""),
           let e = str.range(of: "\"", range: s.upperBound..<str.endIndex) {
            boundary = String(str[s.upperBound..<e.lowerBound])
        } else if let s = str.range(of: "boundary=") {
            let rest = String(str[s.upperBound...])
            let end = rest.firstIndex(where: { ";,\r\n \t".contains($0) })
            boundary = end.map { String(rest[..<$0]) } ?? rest
        }

        guard let b = boundary else {
            log.error("extractSignedParts: no boundary found")
            return (nil, nil)
        }

        let delim = "--" + b
        let parts = str.components(separatedBy: delim)
        // parts: [preamble, signed-part, signature-part, epilogue (after --boundary--)]
        guard parts.count >= 3 else {
            log.error("extractSignedParts: expected ≥3 parts, got \(parts.count)")
            return (nil, nil)
        }

        // The signed data is the COMPLETE first MIME part including its headers,
        // but NOT including the boundary lines. gpg --verify needs the exact bytes
        // that were signed.
        let signedPart = parts[1]
        // Strip the leading line break after the boundary delimiter.
        let signedContent: String
        if signedPart.hasPrefix("\r\n") {
            signedContent = String(signedPart.dropFirst(2))
        } else if signedPart.hasPrefix("\n") {
            signedContent = String(signedPart.dropFirst(1))
        } else {
            signedContent = signedPart
        }
        // Strip the trailing line break before the next boundary delimiter.
        let trimmedSigned: String
        if signedContent.hasSuffix("\r\n") {
            trimmedSigned = String(signedContent.dropLast(2))
        } else if signedContent.hasSuffix("\n") {
            trimmedSigned = String(signedContent.dropLast(1))
        } else {
            trimmedSigned = signedContent
        }

        // The signature part: extract just the PGP signature block.
        let sigPart = parts[2]
        var sigBody: String? = nil
        // Skip part headers — find the blank line separating headers from body.
        for sep in ["\r\n\r\n", "\n\n"] {
            if let bodyStart = sigPart.range(of: sep) {
                sigBody = String(sigPart[bodyStart.upperBound...])
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                break
            }
        }

        guard let sigContent = sigBody, !sigContent.isEmpty else {
            log.error("extractSignedParts: could not extract signature body")
            return (nil, nil)
        }

        // Normalize to CRLF before verification. We sign the CRLF canonical form
        // (RFC 3156 §5), but locally stored messages often use LF. Normalizing
        // here ensures our own verify call uses the same bytes the signature
        // was computed over.
        let crlfSigned = trimmedSigned
            .replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\n", with: "\r\n")
        log.debug("extractSignedParts: signed=\(crlfSigned.count) chars (CRLF), sig=\(sigContent.count) chars")
        return (crlfSigned.data(using: .utf8), sigContent.data(using: .utf8))
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
