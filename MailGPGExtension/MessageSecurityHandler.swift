// MessageSecurityHandler.swift
// MailGPGExtension

import MailKit
import os

private let log = Logger(subsystem: "com.mahaupt.mailgpg", category: "encode")

class MessageSecurityHandler: NSObject, MEMessageSecurityHandler {

    static let shared = MessageSecurityHandler()

    /// Unified cache keyed by message UUID (`X-Universally-Unique-Identifier`).
    /// Mail calls encode() up to 3 times for the same logical message (send,
    /// auto-save, Sent copy) with slightly different rawData each time. It also
    /// calls decodedMessage() on the encrypted output for indexing. Both paths
    /// share this UUID-based cache so only the FIRST encode hits GPG — all
    /// subsequent encode and decode calls return instantly.
    var uuidCache: [String: UUIDCacheEntry] = [:]
    /// Serializes access to uuidCache. Mail calls decodedMessage() from multiple
    /// threads concurrently — without a lock they all miss the cache and start
    /// parallel GPG decrypts of the same 17 MB message.
    private let cacheLock = NSLock()

    struct UUIDCacheEntry {
        let encodeResult: MEMessageEncodingResult?
        let decodedMessage: MEDecodedMessage?
    }

    func clearUUIDCache() {
        cacheLock.lock()
        uuidCache.removeAll()
        cacheLock.unlock()
    }

    private static func logNSError(_ error: NSError, prefix: StaticString) {
        log.error("\(prefix, privacy: .public) domain=\(error.domain, privacy: .public) code=\(error.code)")
    }


    // MARK: - Encoding (outgoing)

    func getEncodingStatus(for message: MEMessage, composeContext: MEComposeContext, completionHandler: @escaping (MEOutgoingMessageEncodingStatus) -> Void) {
        // If we already know whether the host app is reachable, respond immediately.
        if let available = HostAppReachability.shared.isAvailable {
            completionHandler(Self.encodingStatus(hostAvailable: available))
            return
        }

        // Unknown state — only one caller should ping; the rest return optimistic
        // status for now (the banner in the compose panel covers the gap).
        guard HostAppReachability.shared.beginCheckIfNeeded() else {
            completionHandler(Self.encodingStatus(hostAvailable: true))
            return
        }

        // The fixed ping() fails fast when the host app is offline (sub-second).
        Task {
            let available: Bool
            do {
                _ = try await GPGService.shared.ping()
                available = true
            } catch {
                available = false
            }
            HostAppReachability.shared.isAvailable = available
            completionHandler(Self.encodingStatus(hostAvailable: available))
        }
    }

    private static func encodingStatus(hostAvailable: Bool) -> MEOutgoingMessageEncodingStatus {
        if hostAvailable {
            // Don't populate addressesFailingEncryption here — that causes Mail to
            // show a popup mid-composition when a recipient's key hasn't loaded yet.
            return MEOutgoingMessageEncodingStatus(
                canSign: true, canEncrypt: true, securityError: nil,
                addressesFailingEncryption: [])
        } else {
            return MEOutgoingMessageEncodingStatus(
                canSign: false, canEncrypt: false,
                securityError: GPGXPCError.make(.hostAppNotRunning,
                    message: "MailGPG host app is not running. Please open it to enable GPG operations."),
                addressesFailingEncryption: [])
        }
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

        log.info("encode: rawData size=\(body.count) bytes")

        // UUID-based cache: return a previous encode result for subsequent calls
        // with the same message UUID. This reduces 3 GPG calls to 1.
        // IMPORTANT: Skip caching for auto-saved drafts — they contain partial data
        // (X-Apple-Mail-Remote-Attachments: YES means attachments are server-side
        // references, not inlined). If we cache the draft result, the actual send
        // (which has full attachments inlined → much larger rawData) would get the
        // smaller draft result back, causing Mail to freeze.
        let messageUUID = header("x-universally-unique-identifier", in: message)
        // Auto-saved drafts have X-Apple-Mail-Remote-Attachments: YES — attachments
        // are server-side references, not inlined. Encrypting this partial message
        // wastes a large GPG call and the encrypted draft body is useless (attachment
        // refs become encrypted gibberish). Skip encoding entirely for auto-saves so
        // only the actual send (with all attachments inlined) goes through GPG.
        let isAutoSave = header("x-apple-auto-saved", in: message) != nil
                      || header("x-apple-mail-remote-attachments", in: message) != nil
        if isAutoSave {
            log.info("encode: auto-save draft detected — passing through unchanged")
            completionHandler(MEMessageEncodingResult(encodedMessage: nil, signingError: nil, encryptionError: nil))
            return
        }
        cacheLock.lock()
        let cachedEncode = messageUUID.flatMap { uuidCache[$0]?.encodeResult }
        cacheLock.unlock()
        if let cached = cachedEncode, let uuid = messageUUID {
            log.info("encode: UUID cache hit (\(body.count) bytes)")
            completionHandler(cached)
            return
        }

        let senderEmail  = message.fromAddress.rawString.lowercased()
        let state = sessionState(for: message)
        let fingerprints = state?.recipientKeys.values.map(\.fingerprint) ?? []

        // Check if encryption is requested but some recipients are missing keys.
        if shouldEncrypt {
            let allRecipients = message.toAddresses + message.ccAddresses + message.bccAddresses
            let missingEmails = allRecipients
                .map { $0.bareAddress }
                .filter { state?.recipientKeyStatus[$0] == .notFound }
            let loadingEmails = allRecipients
                .map { $0.bareAddress }
                .filter { state?.recipientKeyStatus[$0] == .loading }

            if !missingEmails.isEmpty {
                let list = missingEmails.joined(separator: ", ")
                log.error("encode: encryption requested but \(missingEmails.count) recipient key(s) are missing")
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

            if !loadingEmails.isEmpty {
                let list = loadingEmails.joined(separator: ", ")
                log.warning("encode: key lookup still in progress for \(loadingEmails.count) recipient(s)")
                completionHandler(MEMessageEncodingResult(
                    encodedMessage: nil,
                    signingError: nil,
                    encryptionError: NSError(
                        domain: "com.mahaupt.mailgpg", code: 4,
                        userInfo: [NSLocalizedDescriptionKey:
                            "Still looking up keys for:\n\(list)\n\nPlease try again in a moment."])))
                return
            }
        }

        Task {
            do {
                let encodedData: MEEncodedOutgoingMessage

                // Look up the sender's secret key for signing and/or encrypting
                // to the sender's own key (so the sent copy stays readable).
                log.info("encode: fetching secret keys via XPC…")
                let secretKeys = try await GPGService.shared.listSecretKeys()
                let usable = secretKeys.filter { !$0.isRevoked && $0.expiresAt.map { $0 > Date() } ?? true }
                log.info("encode: \(usable.count) usable key(s) of \(secretKeys.count) total")

                let signerKey = usable.first(where: { $0.email.lowercased() == senderEmail })
                                ?? usable.first

                // When encrypting, include the sender's key so the sent copy is
                // decryptable. Without this, Mail's indexer calls decodedMessage on
                // the sent message, decryption fails, and the error triggers a KVO
                // re-entrancy crash in Mail.app.
                var encryptFingerprints = fingerprints
                if shouldEncrypt, let sk = signerKey {
                    encryptFingerprints.append(sk.fingerprint)
                    log.info("encode: added sender key to encryption recipients")
                }

                if shouldSign {
                    guard let signerKey else {
                        log.error("encode: no usable secret key found for sender")
                        completionHandler(MEMessageEncodingResult(
                            encodedMessage: nil,
                            signingError: GPGXPCError.make(.keyNotFound, message: "No secret key found for \(senderEmail)"),
                            encryptionError: nil))
                        return
                    }
                    log.info("encode: signing with selected sender key")

                    if shouldEncrypt {
                        log.info("encode: sign+encrypt to \(encryptFingerprints.count) recipient(s)")
                        encodedData = MEEncodedOutgoingMessage(
                            rawData: try await GPGService.shared.signAndEncrypt(
                                data: body, signerKeyID: signerKey.keyID,
                                recipientFingerprints: encryptFingerprints),
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
                    log.info("encode: encrypt-only to \(encryptFingerprints.count) recipient(s)")
                    encodedData = MEEncodedOutgoingMessage(
                        rawData: try await GPGService.shared.encrypt(
                            data: body, recipientFingerprints: encryptFingerprints),
                        isSigned: false, isEncrypted: true)
                    log.info("encode: encrypt succeeded")
                }

                log.info("encode: encoded \(encodedData.rawData.count) bytes")

                let encodeResult = MEMessageEncodingResult(encodedMessage: encodedData, signingError: nil, encryptionError: nil)

                // Store in UUID cache: both the encode result (so subsequent
                // encode calls for the same message return instantly) and a
                // pre-built decoded message (so decodedMessage() on the encrypted
                // output also returns instantly without a GPG decrypt).
                if let uuid = messageUUID {
                    let signer = signerKey.map {
                        Signer(email: $0.email, keyID: $0.keyID,
                               fingerprint: $0.fingerprint, trustLevel: $0.trustLevel)
                    }
                    let signers = signer.map { [$0] } ?? []
                    let status: SecurityStatus = shouldEncrypt
                        ? .encrypted(signers: signers)
                        : .signed(signers: signers)
                    let decoded = Self.makeDecodedMessage(data: body, status: status,
                                                          wasEncrypted: shouldEncrypt)
                    self.cacheLock.lock()
                    self.uuidCache[uuid] = UUIDCacheEntry(
                        encodeResult: encodeResult, decodedMessage: decoded)
                    self.cacheLock.unlock()
                    log.info("encode: cached under UUID")
                }

                log.info("encode: calling completionHandler with \(encodedData.rawData.count) bytes")
                completionHandler(encodeResult)

            } catch {
                let nsError = error as NSError
                Self.logNSError(nsError, prefix: "encode: failed")
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

    /// Extract a header value from raw RFC 2822 message data (case-insensitive).
    private static func headerValue(_ name: String, in data: Data) -> String? {
        let eoh = data.range(of: Data("\r\n\r\n".utf8))
               ?? data.range(of: Data("\n\n".utf8))
        let headerData = eoh.map { Data(data[..<$0.lowerBound]) } ?? data.prefix(4096)
        guard let headerStr = String(data: headerData, encoding: .utf8) else { return nil }
        let target = name.lowercased() + ":"
        for line in headerStr.components(separatedBy: "\n") {
            let trimmed = line.hasSuffix("\r") ? String(line.dropLast()) : line
            if trimmed.lowercased().hasPrefix(target) {
                return trimmed.dropFirst(target.count).trimmingCharacters(in: .whitespaces)
            }
        }
        return nil
    }

    /// Decode RFC 2047 encoded words (e.g. `=?UTF-8?Q?verschl=C3=BCsselter?=`) in a header value.
    private static func decodeMIMEWords(_ value: String) -> String {
        let pattern = #"=\?([^?]+)\?([BbQq])\?([^?]*)\?="#
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return value }
        var result = value
        for match in regex.matches(in: value, range: NSRange(value.startIndex..., in: value)).reversed() {
            guard let fullRange    = Range(match.range,        in: value),
                  let charsetRange = Range(match.range(at: 1), in: value),
                  let encRange     = Range(match.range(at: 2), in: value),
                  let textRange    = Range(match.range(at: 3), in: value) else { continue }
            let charset  = String(value[charsetRange])
            let encoding = String(value[encRange]).uppercased()
            let text     = String(value[textRange])
            let strEnc   = String.Encoding(rawValue:
                CFStringConvertEncodingToNSStringEncoding(
                    CFStringConvertIANACharSetNameToEncoding(charset as CFString)))
            var data: Data?
            if encoding == "B" {
                data = Data(base64Encoded: text, options: .ignoreUnknownCharacters)
            } else { // Q-encoding: walk bytes, _ is space, =XX is hex byte
                var bytes = [UInt8](); var i = text.startIndex
                while i < text.endIndex {
                    if text[i] == "=", let j = text.index(i, offsetBy: 3, limitedBy: text.endIndex),
                       let byte = UInt8(String(text[text.index(after: i)..<j]), radix: 16) {
                        bytes.append(byte); i = j
                    } else {
                        bytes.append(text[i] == "_" ? 0x20 : text[i].asciiValue ?? 0x3F)
                        i = text.index(after: i)
                    }
                }
                data = Data(bytes)
            }
            if let data, let decoded = String(data: data, encoding: strEnc) {
                result.replaceSubrange(result.range(of: String(value[fullRange]))!, with: decoded)
            }
        }
        return result
    }

    func decodedMessage(forMessageData data: Data) -> MEDecodedMessage? {
        // Cache lookup: try UUID first (for messages we just encoded), then
        // Message-Id (for incoming messages from the server).
        let messageUUID = Self.headerValue("x-universally-unique-identifier", in: data)
        let messageId   = Self.headerValue("message-id", in: data)
        let cacheKey = messageUUID ?? messageId

        cacheLock.lock()
        if let key = cacheKey, let cached = uuidCache[key]?.decodedMessage {
            cacheLock.unlock()
            log.debug("decodedMessage: cache hit (\(data.count) bytes)")
            return cached
        }
        cacheLock.unlock()

        // Quick pre-check: only process messages that look like PGP content.
        // Returning nil for everything else tells Mail "not my message" and avoids:
        //   - unnecessary XPC round-trips for plaintext mail
        //   - calling gpg --decrypt on multipart/signed mails we just sent, which
        //     would produce a spurious "decryption failed" banner in Sent
        // Scan the entire header block rather than a fixed byte prefix: routing
        // headers added by Gmail, Exchange, etc. (DKIM, ARC, Received, ...) can
        // push Content-Type well past 4 KB.
        let eohRange = data.range(of: "\r\n\r\n".data(using: .utf8)!)
                    ?? data.range(of: "\n\n".data(using: .utf8)!)
        let headerData = eohRange.map { Data(data[..<$0.lowerBound]) } ?? data
        let preview = String(data: headerData, encoding: .utf8) ?? ""
        // For inline PGP (e.g. Mailvelope), the PGP block is in the body, not the headers.
        // Check the body as well.
        let bodyData = eohRange.map { Data(data[$0.upperBound...]) } ?? Data()
        let bodyStr  = String(data: bodyData, encoding: .utf8) ?? ""
        let isMIMEEncrypted = preview.contains("multipart/encrypted")
        let isMIMESigned    = preview.contains("multipart/signed")
        let isInlinePGP     = bodyStr.contains("-----BEGIN PGP MESSAGE-----")
        let isInlineSigned  = bodyStr.contains("-----BEGIN PGP SIGNED MESSAGE-----")
        let isEncrypted = isMIMEEncrypted || isInlinePGP
        let isSigned    = isMIMESigned    || isInlineSigned

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
                    log.debug("decodedMessage: verify completed")
                    result = Self.makeDecodedMessage(data: data, status: status)
                } catch let error as NSError {
                    Self.logNSError(error, prefix: "decodedMessage: verify error")
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
                    log.debug("decodedMessage: decrypt succeeded")
                    // Check for protected subject (RFC 3156 / Memory Hole):
                    // if the outer subject is a placeholder like "..." and the
                    // decrypted message has a real subject, show it via banner.
                    let outerSubject = Self.headerValue("subject", in: data)
                    let innerSubject = Self.headerValue("subject", in: plaintext)
                    let banner: MEDecodedMessageBanner?
                    if let inner = innerSubject,
                       let outer = outerSubject,
                       outer == "..." && inner != outer {
                        banner = MEDecodedMessageBanner(
                            title: "🔒 Subject: \(Self.decodeMIMEWords(inner))",
                            primaryActionTitle: "",
                            dismissable: false)
                    } else {
                        banner = nil
                    }
                    result = Self.makeDecodedMessage(data: plaintext, status: status, wasEncrypted: true, banner: banner)
                } catch let error as NSError {
                    Self.logNSError(error, prefix: "decodedMessage: decrypt error")
                    // Return nil so Mail shows the raw message instead of crashing.
                    // Returning a MEDecodedMessage with the original encrypted data
                    // causes Mail's indexer to loop and trigger a KVO re-entrancy crash.
                    result = nil
                }
                semaphore.signal()
            }
        }

        semaphore.wait()

        // Cache the decoded result so subsequent calls (Mail's indexer often
        // calls decodedMessage 10+ times for the same message) return instantly.
        if let key = cacheKey, let decoded = result {
            cacheLock.lock()
            if uuidCache[key] == nil {
                uuidCache[key] = UUIDCacheEntry(encodeResult: nil, decodedMessage: decoded)
            }
            cacheLock.unlock()
            log.debug("decodedMessage: cached result")
        }

        return result
    }

    /// - Parameter wasEncrypted: `true` when returning decrypted plaintext,
    ///   so `MEMessageSecurityInformation.isEncrypted` is set correctly even
    ///   when the status isn't `.encrypted` (e.g. `.signed` after decrypt).
    static nonisolated func makeDecodedMessage(data: Data, status: SecurityStatus, wasEncrypted: Bool = false, banner: MEDecodedMessageBanner? = nil) -> MEDecodedMessage? {
        let meSigners: [MEMessageSigner] = {
            switch status {
            case .signed(let signers), .encrypted(let signers):
                return signers.map {
                    MEMessageSigner(emailAddresses: [MEEmailAddress(rawString: $0.email)], signatureLabel: $0.keyID, context: nil)
                }
            default: return []
            }
        }()

        let isEncrypted: Bool = {
            if case .encrypted = status { return true }
            return wasEncrypted
        }()

        let securityInfo = MEMessageSecurityInformation(
            signers: meSigners,
            isEncrypted: isEncrypted,
            signingError: { if case .signatureInvalid(let r) = status { return NSError(domain: "MailGPG", code: 1, userInfo: [NSLocalizedDescriptionKey: r]) }; return nil }(),
            encryptionError: { if case .decryptionFailed(let r) = status { return NSError(domain: "MailGPG", code: 2, userInfo: [NSLocalizedDescriptionKey: r]) }; return nil }()
        )

        let context = try? JSONEncoder().encode(status)
        if let banner {
            return MEDecodedMessage(data: data, securityInformation: securityInfo, context: context, banner: banner)
        }
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
            return Signer(email: email, keyID: s.label, fingerprint: s.label, trustLevel: .unknown)
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
