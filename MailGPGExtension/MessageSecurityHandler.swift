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
    /// Cache keys in least-recently-stored-first order, so the cache can be bounded.
    /// Entries hold whole `MEDecodedMessage` payloads and have no TTL; the only
    /// eviction used to be `clearUUIDCache()` from `mailComposeSessionDidEnd`, so a
    /// Mail session that never opens a compose window grew this without limit.
    private var cacheOrder: [String] = []
    private static let cacheLimit = 128

    struct UUIDCacheEntry {
        let encodeResult: MEMessageEncodingResult?
        let decodedMessage: MEDecodedMessage?
        let isNotMailGPGContent: Bool
        /// Size of the message body the "not MailGPG content" verdict was reached on.
        /// A later call with MORE bytes is a different message as far as the sniff is
        /// concerned, so the verdict must be re-taken. See `isCachedNotMailGPGContent`.
        let notMailGPGSize: Int

        init(encodeResult: MEMessageEncodingResult?,
             decodedMessage: MEDecodedMessage?,
             isNotMailGPGContent: Bool,
             notMailGPGSize: Int = 0) {
            self.encodeResult = encodeResult
            self.decodedMessage = decodedMessage
            self.isNotMailGPGContent = isNotMailGPGContent
            self.notMailGPGSize = notMailGPGSize
        }
    }

    private func cachedEncodeResult(for key: String?) -> MEMessageEncodingResult? {
        guard let key else { return nil }
        cacheLock.lock()
        let cached = uuidCache[key]?.encodeResult
        cacheLock.unlock()
        return cached
    }

    private func cachedDecodedMessage(for key: String?) -> MEDecodedMessage? {
        guard let key else { return nil }
        cacheLock.lock()
        let cached = uuidCache[key]?.decodedMessage
        cacheLock.unlock()
        return cached
    }

    /// Whether we already decided this message is not PGP content.
    ///
    /// Honoured only for a body of the SAME size the verdict was reached on. Mail
    /// calls `decodedMessage` with partially downloaded bodies (large messages, or
    /// anything that needs "Download Remaining Content"), and a truncated body sniffs
    /// as non-PGP. Caching that verdict unconditionally made it permanent for the
    /// session: the complete body arrived later, hit the negative cache, and the
    /// message could never be decrypted again until a compose window opened and
    /// closed (the only thing that called `clearUUIDCache`). A larger body re-sniffs.
    private func isCachedNotMailGPGContent(for key: String?, size: Int) -> Bool {
        guard let key else { return false }
        cacheLock.lock()
        defer { cacheLock.unlock() }
        guard let entry = uuidCache[key], entry.isNotMailGPGContent else { return false }
        return entry.notMailGPGSize == size
    }

    /// Insert or replace an entry and evict the oldest once over `cacheLimit`.
    /// Caller must hold `cacheLock`.
    private func setLocked(_ entry: UUIDCacheEntry, for key: String) {
        if uuidCache[key] == nil { cacheOrder.append(key) }
        uuidCache[key] = entry
        while cacheOrder.count > Self.cacheLimit {
            uuidCache.removeValue(forKey: cacheOrder.removeFirst())
        }
    }

    private func storeCacheEntry(_ entry: UUIDCacheEntry, for key: String) {
        cacheLock.lock()
        setLocked(entry, for: key)
        cacheLock.unlock()
    }

    /// Store a successful decode.
    ///
    /// A successful decode is allowed to OVERWRITE a negative ("not MailGPG content")
    /// entry. Mail routinely calls `decodedMessage` with a partially downloaded body
    /// — large messages, or anything needing "Download Remaining Content" — and that
    /// partial body sniffs as non-PGP. Before, that verdict was permanent for the
    /// lifetime of the Mail session: the full body arrived later and hit the negative
    /// cache, so the message could never be decrypted again until a compose window
    /// happened to open and close. That is the "*some* mails do not decrypt" case.
    ///
    /// A real result is never overwritten, so the anti-re-entrancy guarantee that the
    /// repeat-call cache exists for is unaffected.
    private func storeDecodedMessageIfNeeded(_ decoded: MEDecodedMessage, for key: String) {
        cacheLock.lock()
        if uuidCache[key]?.decodedMessage == nil {
            setLocked(UUIDCacheEntry(
                encodeResult: uuidCache[key]?.encodeResult,
                decodedMessage: decoded,
                isNotMailGPGContent: false), for: key)
        }
        cacheLock.unlock()
    }

    private func storeNotMailGPGContent(for key: String?, size: Int) {
        guard let key else { return }
        cacheLock.lock()
        // Never downgrade a real result to "not ours"; do refresh the size a previous
        // negative verdict was reached on.
        if uuidCache[key]?.decodedMessage == nil && uuidCache[key]?.encodeResult == nil {
            setLocked(UUIDCacheEntry(
                encodeResult: nil,
                decodedMessage: nil,
                isNotMailGPGContent: true,
                notMailGPGSize: size), for: key)
        }
        cacheLock.unlock()
    }

    func clearUUIDCache() {
        cacheLock.lock()
        uuidCache.removeAll()
        cacheOrder.removeAll()
        cacheLock.unlock()
    }

    private nonisolated static func logNSError(_ error: NSError, prefix: StaticString) {
        log.error("\(prefix, privacy: .public) domain=\(error.domain, privacy: .public) code=\(error.code)")
    }


    // MARK: - Encoding (outgoing)

    func getEncodingStatus(for message: MEMessage, composeContext: MEComposeContext, completionHandler: @escaping (MEOutgoingMessageEncodingStatus) -> Void) {
        // If we already know whether the host app is reachable, respond immediately.
        if let available = HostAppReachability.shared.isAvailable {
            // A "not running" verdict must not be sticky: the host can come back
            // at any moment (relaunch, login item), and when we short-circuit here
            // nothing else on this path ever touches XPC again. Answer with the
            // cached verdict but clear it, so the NEXT status request re-pings.
            if !available { HostAppReachability.shared.isAvailable = nil }
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
        let cachedEncode = cachedEncodeResult(for: messageUUID)
        if let cached = cachedEncode {
            log.info("encode: UUID cache hit (\(body.count) bytes)")
            completionHandler(cached)
            return
        }

        // Must be the BARE address: `rawString` is the full RFC 2822 form
        // ("Jan Hesmert <jan@example.com>"), which can never equal a KeyInfo address,
        // so key selection silently fell through to "whatever gpg listed first".
        let senderEmail  = message.fromAddress.bareAddress
        let state = sessionState(for: message)
        // Every key of every recipient — a correspondent with two published keys gets
        // a PKESK packet for each, because we cannot know which one they can use.
        let fingerprints = state?.recipientKeys.values.flatMap { $0 }.map(\.fingerprint) ?? []

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
                log.info("encode: \(secretKeys.count) secret key(s) in the keyring")

                // Pick by identity: per-address pin → any-UID address match →
                // global default → first usable. selectSigningKey also applies the
                // revoked/expired filter, so "usable" is defined in exactly one place.
                let signerKey = selectSigningKey(
                    senderAddress: senderEmail,
                    from: secretKeys,
                    overrides: GPGService.shared.getSigningKeyOverrides(),
                    defaultFingerprint: await GPGService.shared.getDefaultSigningKey())
                if let signerKey {
                    log.info("encode: selected signing key \(signerKey.keyID, privacy: .public) for sender")
                }

                // When encrypting, include the sender's key so the sent copy is
                // decryptable. Without this, Mail's indexer calls decodedMessage on
                // the sent message, decryption fails, and the error triggers a KVO
                // re-entrancy crash in Mail.app.
                var encryptFingerprints = fingerprints
                if shouldEncrypt, let sk = signerKey {
                    encryptFingerprints.append(sk.fingerprint)
                    log.info("encode: added sender key to encryption recipients")
                }
                // De-duplicate: a recipient reachable under two of their addresses, or
                // a reply-all that includes ourselves, would otherwise pass the same
                // --recipient twice.
                var seenFingerprints = Set<String>()
                encryptFingerprints = encryptFingerprints.filter { seenFingerprints.insert($0).inserted }

                if shouldSign {
                    guard let signerKey else {
                        log.error("encode: no usable secret key found for sender")
                        completionHandler(MEMessageEncodingResult(
                            encodedMessage: nil,
                            signingError: GPGXPCError.make(.keyNotFound, message: "No secret key found for \(senderEmail)"),
                            encryptionError: nil))
                        return
                    }
                    // Pass the FINGERPRINT, not the 8-hex keyID: a short key ID is not
                    // unique, so with several secret keys `--local-user AABBCCDD` can
                    // resolve to a different key than the fingerprint we hand
                    // `--recipient` for encrypt-to-self — a message signed by one key
                    // and encrypted to another. (`signerKeyID:` keeps its label: it is
                    // part of the @objc XPC selector.)
                    log.info("encode: signing with selected sender key")

                    if shouldEncrypt {
                        log.info("encode: sign+encrypt to \(encryptFingerprints.count) recipient(s)")
                        encodedData = MEEncodedOutgoingMessage(
                            rawData: try await GPGService.shared.signAndEncrypt(
                                data: body, signerKeyID: signerKey.fingerprint,
                                recipientFingerprints: encryptFingerprints),
                            isSigned: true, isEncrypted: true)
                        log.info("encode: sign+encrypt succeeded")
                    } else {
                        encodedData = MEEncodedOutgoingMessage(
                            rawData: try await GPGService.shared.sign(
                                data: body, signerKeyID: signerKey.fingerprint),
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
                    self.storeCacheEntry(
                        UUIDCacheEntry(
                            encodeResult: encodeResult,
                            decodedMessage: decoded,
                            isNotMailGPGContent: false),
                        for: uuid)
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
    private nonisolated static func headerValue(_ name: String, in data: Data) -> String? {
        let headerData = Data(headerBlock(in: data))
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
    private nonisolated static func decodeMIMEWords(_ value: String) -> String {
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

    /// Range of the blank line that ends the RFC 2822 header block.
    ///
    /// Must pick whichever separator comes FIRST, not CRLFCRLF by preference: with
    /// LF headers and CRLF content in the body (routine for forwarded or re-encoded
    /// mail) the CRLF search matches inside the *body*, so the "header block" comes
    /// back as headers + body. One non-UTF-8 byte anywhere in that span then makes
    /// `String(data:encoding:.utf8)` return nil, `isMIMEEncrypted` false, and the
    /// message gets negative-cached as "not PGP" — and `headerValue` returns nil for
    /// message-id at the same time, nulling the cache key.
    ///
    /// `GPGServiceImpl.splitMessage` has carried this logic (and the explanation)
    /// for a while; these two helpers were simply never updated to match.
    /// Headers can grow past 4 KB (DKIM, ARC, Received, …) but never anywhere
    /// near this. Bounding the search matters for responsiveness: a pure-CRLF
    /// message contains no "\n\n" at all, so an unbounded search scanned the
    /// ENTIRE body on every call — and this runs several times per displayed
    /// message (cache-key lookup, subject extraction), for every message, PGP
    /// or not.
    private nonisolated static let headerSearchLimit = 256 * 1024

    private nonisolated static func endOfHeaders(in data: Data) -> Range<Data.Index>? {
        // Data slices share their parent's indices, so ranges found in the
        // bounded window are valid indices into `data`.
        let window = data.prefix(Self.headerSearchLimit)
        let crlf = window.range(of: Data("\r\n\r\n".utf8))
        let lf   = window.range(of: Data("\n\n".utf8))
        switch (crlf, lf) {
        case (let c?, let l?): return c.lowerBound <= l.lowerBound ? c : l
        case (let c?, nil):    return c
        case (nil, let l?):    return l
        case (nil, nil):       return nil
        }
    }

    /// Return only the RFC 2822 header block. This stays small for normal mail and
    /// avoids decoding large message bodies just to decide whether MailGPG applies.
    private nonisolated static func headerBlock(in data: Data) -> Data.SubSequence {
        endOfHeaders(in: data).map { data[..<$0.lowerBound] } ?? data.prefix(4096)
    }

    func decodedMessage(forMessageData data: Data) -> MEDecodedMessage? {
        let started = DispatchTime.now()
        func elapsedMs() -> Double {
            Double(DispatchTime.now().uptimeNanoseconds - started.uptimeNanoseconds) / 1_000_000
        }

        // Cache lookup: try UUID first (for messages we just encoded), then
        // Message-Id (for incoming messages from the server).
        let messageUUID = Self.headerValue("x-universally-unique-identifier", in: data)
        let messageId   = Self.headerValue("message-id", in: data)
        let cacheKey = messageUUID ?? messageId

        if let cached = cachedDecodedMessage(for: cacheKey) {
            log.debug("decodedMessage: cache hit after \(elapsedMs(), format: .fixed(precision: 1)) ms (\(data.count) bytes)")
            return cached
        }
        if isCachedNotMailGPGContent(for: cacheKey, size: data.count) {
            log.debug("decodedMessage: negative cache hit after \(elapsedMs(), format: .fixed(precision: 1)) ms (\(data.count) bytes)")
            return nil
        }

        // Quick pre-check: only process messages that look like PGP content.
        // Returning nil for everything else tells Mail "not my message" and avoids:
        //   - unnecessary XPC round-trips for plaintext mail
        //   - calling gpg --decrypt on multipart/signed mails we just sent, which
        //     would produce a spurious "decryption failed" banner in Sent
        // Scan the entire header block rather than a fixed byte prefix: routing
        // headers added by Gmail, Exchange, etc. (DKIM, ARC, Received, ...) can
        // push Content-Type well past 4 KB.
        let headerData = Data(Self.headerBlock(in: data))
        let preview = (String(data: headerData, encoding: .utf8) ?? "").lowercased()
        // Classification lives in Shared/SecurityStatus.swift (sniffPGPContent) so it
        // is unit-testable; it also covers base64-encoded armor (gpg4o / PGP Desktop
        // "partitioned" mail), which the old literal byte scan missed.
        let sniff = sniffPGPContent(lowercasedHeaderBlock: preview, rawMessage: data)
        let isMIMEEncrypted = sniff.isMIMEEncrypted
        let isEncrypted = sniff.isEncrypted
        let isSigned    = sniff.isSigned

        log.debug("decodedMessage: \(data.count) bytes — encrypted=\(isEncrypted) signed=\(isSigned)")

        guard isEncrypted || isSigned else {
            log.debug("decodedMessage: not encrypted or signed — returning nil after \(elapsedMs(), format: .fixed(precision: 1)) ms (\(data.count) bytes)")
            storeNotMailGPGContent(for: cacheKey, size: data.count)
            return nil
        }

        // MailKit requires this method to be synchronous, but our GPG calls are async.
        // We bridge with a DispatchSemaphore: a detached Task does the async work on its
        // own thread, signals when done, and the calling thread waits.
        // Using Task.detached avoids blocking a thread the cooperative executor might need.
        //
        // The result travels through a lock-protected box, not a captured var: the
        // wait below has a timeout, so the task may complete AFTER the caller has
        // already given up — writing a plain var then would race with the read.
        let box = DecodeResultBox()
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
                    box.set(Self.makeDecodedMessage(data: data, status: status))
                } catch let error as NSError {
                    Self.logNSError(error, prefix: "decodedMessage: verify error")
                    switch GPGXPCError(nsError: error) {
                    case .gpgFailed:
                        box.set(Self.makeDecodedMessage(
                            data: data,
                            status: .signatureInvalid(reason: error.localizedDescription)))
                    default:
                        box.set(nil)
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
                    if case .decryptionFailed(let reason, let details) = status {
                        // gpg NODATA on a message whose HEADERS promise
                        // multipart/encrypted means the encrypted body part was not
                        // in the bytes we got — Mail routinely calls decodedMessage
                        // with partially downloaded bodies. The failure is
                        // transient, and the error placeholder is a cached-forever
                        // "real result", so returning it here would shadow the
                        // successful decrypt once the full body arrives. Instead:
                        // negative-cache THIS size (a larger body re-evaluates,
                        // same mechanism as the non-PGP sniff) and tell Mail
                        // "not my message" for now.
                        // Two flavors of transient failure, same treatment:
                        //  • NODATA — the encrypted part wasn't in the bytes Mail
                        //    gave us (partially downloaded body)
                        //  • details.transient — the host classified the gpg error
                        //    as retryable (agent killed mid-op by GPG Suite's
                        //    shutdown-gpg-agent, pinentry dismissed)
                        if reason.contains("NODATA") || details.transient == true {
                            log.info("decodedMessage: transient decrypt failure (\(data.count) bytes) — will retry")
                            let note = reason.contains("NODATA")
                                ? "\n(Encrypted part missing — body probably not fully downloaded. Retries automatically once Mail has the complete message.)"
                                : "\n(Transient failure — GPG agent unavailable or prompt dismissed. Will be retried later, at the latest after Mail restarts.)"
                            DecryptionFailureLog.shared.record(
                                messageID: messageId ?? messageUUID,
                                subject: Self.headerValue("subject", in: data).map(Self.decodeMIMEWords),
                                reason: reason + note,
                                details: details)
                            box.negativeCacheSize = data.count
                        } else {
                            // The host app now reports *why* rather than throwing an
                            // opaque NSError, so there is something to show.
                            log.error("decodedMessage: decrypt failed — \(reason, privacy: .public)")
                            DecryptionFailureLog.shared.record(
                                messageID: messageId ?? messageUUID,
                                subject: Self.headerValue("subject", in: data).map(Self.decodeMIMEWords),
                                reason: reason,
                                details: details)
                            box.set(isMIMEEncrypted
                                ? Self.makeFailedDecodedMessage(reason: reason, status: status,
                                                                original: data)
                                : nil)
                        }
                    } else {
                        box.set(Self.makeDecodedMessage(data: plaintext, status: status, wasEncrypted: true, banner: banner))
                    }
                } catch let error as NSError {
                    Self.logNSError(error, prefix: "decodedMessage: decrypt error")
                    let reason = error.localizedDescription
                    DecryptionFailureLog.shared.record(
                        messageID: messageId ?? messageUUID,
                        subject: Self.headerValue("subject", in: data).map(Self.decodeMIMEWords),
                        reason: reason)
                    box.set(isMIMEEncrypted
                        ? Self.makeFailedDecodedMessage(
                            reason: reason,
                            status: .decryptionFailed(reason: reason),
                            original: data)
                        : nil)
                }
                semaphore.signal()
            }
        }

        // Bounded wait: an operation that never completes (a wedged XPC call, gpg
        // stuck on a pinentry that cannot be shown, …) must not block forever —
        // Mail serializes decode requests to the extension, so one permanently
        // blocked call here makes EVERY message spin, PGP or not. On timeout,
        // return nil (Mail shows the raw message) without negative-caching, so the
        // next look at the message simply tries again.
        if semaphore.wait(timeout: .now() + Self.decodeTimeout) == .timedOut {
            log.error("decodedMessage: timed out after \(Int(Self.decodeTimeout))s — returning nil uncached")
            DecryptionFailureLog.shared.record(
                messageID: messageId ?? messageUUID,
                subject: Self.headerValue("subject", in: data).map(Self.decodeMIMEWords),
                reason: "Timed out after \(Int(Self.decodeTimeout))s waiting for the host app / GPG")
            return nil
        }
        // Transient failure (encrypted part missing from a partially downloaded
        // body): negative-cache at this size so the indexer's repeat calls don't
        // re-run gpg, while a call with MORE bytes re-evaluates and decrypts.
        if let size = box.negativeCacheSize {
            storeNotMailGPGContent(for: cacheKey, size: size)
            return nil
        }
        let result = box.value

        // Cache the decoded result so subsequent calls (Mail's indexer often
        // calls decodedMessage 10+ times for the same message) return instantly.
        if let key = cacheKey, let decoded = result {
            storeDecodedMessageIfNeeded(decoded, for: key)
            log.debug("decodedMessage: cached result")
        }

        return result
    }

    /// How long `decodedMessage` waits for the async GPG work before giving up.
    /// Generous on purpose: a legitimate pinentry passphrase prompt happens inside
    /// this window. It exists only so a truly stuck operation cannot wedge Mail's
    /// decode pipeline permanently.
    private static let decodeTimeout: TimeInterval = 60

    /// Lock-protected one-shot handoff from the detached decode task to the
    /// synchronous `decodedMessage` caller. A plain captured var would race once
    /// the wait can time out: the task may write after the caller has moved on.
    private final class DecodeResultBox: @unchecked Sendable {
        private let lock = NSLock()
        private var stored: MEDecodedMessage?
        private var _negativeCacheSize: Int?
        func set(_ value: MEDecodedMessage?) { lock.lock(); stored = value; lock.unlock() }
        var value: MEDecodedMessage? { lock.lock(); defer { lock.unlock() }; return stored }
        /// When set, the caller should negative-cache the message at this size and
        /// return nil — used for transient failures (partially downloaded body)
        /// that must be retried once Mail supplies more bytes.
        var negativeCacheSize: Int? {
            get { lock.lock(); defer { lock.unlock() }; return _negativeCacheSize }
            set { lock.lock(); _negativeCacheSize = newValue; lock.unlock() }
        }
    }

    /// Build the `MEDecodedMessage` returned for a message we could not decrypt.
    ///
    /// Only used when the message is *certainly* encrypted — a `multipart/encrypted`
    /// part with `application/pgp-encrypted`. The inline-PGP sniff is a byte scan for
    /// the armor marker anywhere in the message, so a plaintext mail that merely
    /// QUOTES an armor block matches it; replacing such a message with an error
    /// placeholder would be worse than the silence this replaces. Those failures are
    /// still recorded in `DecryptionFailureLog`, and the caller returns nil for them.
    ///
    /// The hazard this has to work around: returning an `MEDecodedMessage` whose data
    /// is the ORIGINAL encrypted message makes Mail's indexer re-enter
    /// `decodedMessage` for the same content, loop, and eventually hit a KVO
    /// re-entrancy crash. That is why this path used to return `nil` — at the cost of
    /// telling Mail "not my message" and making every failure invisible.
    ///
    /// Two things keep it safe here:
    ///  • the body is explanatory text, NOT the armor echoed back, so re-decoding it
    ///    sniffs as plain and terminates immediately;
    ///  • the caller caches the result under `cacheKey`, so Mail's repeat calls get
    ///    the identical object back rather than starting another decrypt.
    private nonisolated static func makeFailedDecodedMessage(reason: String,
                                                             status: SecurityStatus,
                                                             original: Data) -> MEDecodedMessage? {
        let subject = headerValue("subject", in: original).map(decodeMIMEWords) ?? ""
        // Keep the envelope headers so Mail still shows From/To/Date/Subject, but
        // replace the content type: the body below is plain text, not PGP.
        var headerLines: [String] = []
        for name in ["from", "to", "cc", "date", "message-id", "subject"] {
            if let value = headerValue(name, in: original) {
                headerLines.append("\(name.capitalized): \(value)")
            }
        }
        headerLines.append("Content-Type: text/plain; charset=utf-8")
        headerLines.append("Content-Transfer-Encoding: 8bit")

        let body = """
            🔒 This message is encrypted, and MailGPG could not decrypt it.

            \(reason)

            The original encrypted message is unchanged on the server. See             MailGPG → Diagnostics → Recent decryption failures for the full list.
            """
        let message = headerLines.joined(separator: "\n") + "\n\n" + body + "\n"
        log.info("decodedMessage: returning decryptionFailed placeholder for \(subject, privacy: .private)")
        // The reason can be raw gpg stderr, which is multi-line — keep the banner to
        // one readable line and leave the full text to the body and the Details panel.
        let headline = reason.components(separatedBy: .newlines)
            .first(where: { !$0.trimmingCharacters(in: .whitespaces).isEmpty }) ?? reason
        let title = headline.count > 120 ? String(headline.prefix(117)) + "…" : headline
        return makeDecodedMessage(data: Data(message.utf8), status: status, wasEncrypted: true,
                                  banner: MEDecodedMessageBanner(
                                    title: "🔒 Could not decrypt: \(title)",
                                    primaryActionTitle: "Details",
                                    dismissable: false))
    }

    /// - Parameter wasEncrypted: `true` when returning decrypted plaintext,
    ///   so `MEMessageSecurityInformation.isEncrypted` is set correctly even
    ///   when the status isn't `.encrypted` (e.g. `.signed` after decrypt).
    static nonisolated func makeDecodedMessage(data: Data, status: SecurityStatus, wasEncrypted: Bool = false, banner: MEDecodedMessageBanner? = nil) -> MEDecodedMessage? {
        let meSigners: [MEMessageSigner] = {
            switch status {
            case .signed(let signers), .encrypted(let signers, _):
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
            encryptionError: { if case .decryptionFailed(let r, _) = status { return NSError(domain: "MailGPG", code: 2, userInfo: [NSLocalizedDescriptionKey: r]) }; return nil }()
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
    private nonisolated static func extractSignedParts(from data: Data) -> (signedData: Data?, signature: Data?) {
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
