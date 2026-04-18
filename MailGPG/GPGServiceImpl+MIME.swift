// GPGServiceImpl+MIME.swift
// MailGPG (host app only)

import Foundation
import os

extension GPGServiceImpl {

    // MARK: - RFC 2822 / MIME helpers

    /// Decode a quoted-printable encoded body (RFC 2045) into raw bytes.
    /// Decoding to Data first preserves multi-byte UTF-8 sequences (e.g. =C3=A9 → é)
    /// instead of mapping each =XX byte to a separate UnicodeScalar.
    private func decodeQuotedPrintableData(_ s: String) -> Data {
        let bytes = Array(s.utf8)
        var result: [UInt8] = []
        result.reserveCapacity(bytes.count)

        func isHex(_ b: UInt8) -> Bool {
            (48...57).contains(b) || (65...70).contains(b) || (97...102).contains(b)
        }
        func hexVal(_ b: UInt8) -> UInt8 {
            switch b {
            case 48...57:  return b - 48
            case 65...70:  return b - 55
            default:       return b - 87
            }
        }

        var i = 0
        while i < bytes.count {
            if bytes[i] == 61 { // '='
                // soft line break =\r\n
                if i + 2 < bytes.count, bytes[i+1] == 13, bytes[i+2] == 10 { i += 3; continue }
                // soft line break =\n
                if i + 1 < bytes.count, bytes[i+1] == 10 { i += 2; continue }
                // =XX hex pair
                if i + 2 < bytes.count, isHex(bytes[i+1]), isHex(bytes[i+2]) {
                    result.append((hexVal(bytes[i+1]) << 4) | hexVal(bytes[i+2]))
                    i += 3; continue
                }
            }
            result.append(bytes[i])
            i += 1
        }
        return Data(result)
    }

    /// Decode a quoted-printable encoded string (RFC 2045) into Unicode text.
    func decodeQuotedPrintable(_ s: String) -> String {
        let data = decodeQuotedPrintableData(s)
        return String(data: data, encoding: .utf8) ?? String(decoding: data, as: UTF8.self)
    }

    /// Split a raw RFC 2822 message into its header block (as String) and body (as Data).
    /// The separator between headers and body is either CRLFCRLF or LFLF.
    func splitMessage(_ data: Data) -> (headers: String, body: Data) {
        // Find whichever blank-line sequence comes FIRST in the message.
        // Trying "\r\n\r\n" before "\n\n" is wrong: if the headers use LF but the
        // body contains CRLF content (e.g. quoted text from a decrypted Mailvelope
        // message), we'd split at a CRLF blank line *inside the body* instead of
        // the real "\n\n" header/body separator — corrupting the header/body split
        // and causing lineEnding() to detect CRLF, which makes Mail.app crash.
        let crlfSep = "\r\n\r\n".data(using: .utf8)!
        let lfSep   = "\n\n".data(using: .utf8)!
        let crlfRange = data.range(of: crlfSep)
        let lfRange   = data.range(of: lfSep)

        let splitRange: Range<Data.Index>?
        switch (crlfRange, lfRange) {
        case (let c?, let l?) where c.lowerBound <= l.lowerBound:
            splitRange = c   // \r\n\r\n comes first (or ties — prefer the longer match)
        case (_, let l?):
            splitRange = l   // \n\n comes first
        case (let c?, nil):
            splitRange = c
        case (nil, nil):
            splitRange = nil
        }

        if let r = splitRange {
            return (String(data: data[..<r.lowerBound], encoding: .utf8) ?? "",
                    Data(data[r.upperBound...]))
        }
        return (String(data: data, encoding: .utf8) ?? "", Data())
    }

    /// Detect whether a string uses CRLF or LF line endings.
    func lineEnding(in text: String) -> String {
        text.contains("\r\n") ? "\r\n" : "\n"
    }

    /// Split a header block into lines, stripping any trailing CR from each line.
    private func headerLines(from headers: String) -> [String] {
        headers.components(separatedBy: "\n").map {
            $0.hasSuffix("\r") ? String($0.dropLast()) : $0
        }
    }

    /// Remove a named header (and any folded continuation lines) from a header block.
    /// Preserves the original line ending style.
    func removeHeader(_ name: String, from headers: String) -> String {
        let eol = lineEnding(in: headers)
        let lines = headerLines(from: headers)
        let prefix = name.lowercased() + ":"
        var out: [String] = []
        var skipping = false
        for line in lines {
            if line.lowercased().hasPrefix(prefix) {
                skipping = true
            } else if skipping && (line.hasPrefix(" ") || line.hasPrefix("\t")) {
                // continuation of the removed header — skip
            } else {
                skipping = false
                out.append(line)
            }
        }
        return out.joined(separator: eol)
    }

    /// Replace (or append) a named header in a block of RFC 2822 headers.
    /// Handles folded (multi-line) header values by skipping continuation lines.
    /// Preserves the original line ending style.
    func setHeader(_ name: String, to value: String, in headers: String) -> String {
        let eol = lineEnding(in: headers)
        let lines = headerLines(from: headers)
        let prefix = name.lowercased() + ":"
        var out: [String] = []
        var replaced = false
        var skipContinuation = false

        for line in lines {
            if line.lowercased().hasPrefix(prefix) {
                if !replaced {
                    out.append("\(name): \(value)")
                    replaced = true
                }
                skipContinuation = true
            } else if skipContinuation && (line.hasPrefix(" ") || line.hasPrefix("\t")) {
                // fold continuation of the header we just replaced — drop it
            } else {
                skipContinuation = false
                out.append(line)
            }
        }
        if !replaced { out.append("\(name): \(value)") }
        return out.joined(separator: eol)
    }

    // MARK: - PGP/MIME builders (RFC 3156)

    /// Build a self-contained inner MIME entity from the original message's
    /// Content-Type (+ Content-Transfer-Encoding) and body. This is what gets
    /// encrypted — so when the recipient decrypts, the output starts with MIME
    /// headers and can be parsed correctly. Without this, multipart/alternative
    /// bodies (text + html) lose their Content-Type wrapper and recipients see
    /// raw MIME boundary text.
    func buildInnerMIMEEntity(rawHeaders: String, body: Data) -> Data {
        let origCT  = foldedHeaderValue("content-type", in: rawHeaders)
                   ?? "text/plain; charset=utf-8"
        let origCTE = foldedHeaderValue("content-transfer-encoding", in: rawHeaders)
        let bodyStr = String(data: body, encoding: .utf8) ?? ""

        var entity = "Content-Type: \(origCT)\r\n"
        if let cte = origCTE {
            entity += "Content-Transfer-Encoding: \(cte)\r\n"
        }
        entity += "\r\n" + bodyStr
        return entity.data(using: .utf8) ?? body
    }

    /// Build the first MIME body part for a multipart/signed message — the content
    /// that gets signed with `gpg --detach-sign`. RFC 3156 §5: the signature covers
    /// the complete first MIME part (headers + blank line + body), not just the body.
    func buildSignedPart(rawHeaders: String, body: Data) -> String {
        let eol = lineEnding(in: rawHeaders)
        let origCT  = foldedHeaderValue("content-type", in: rawHeaders)
                   ?? "text/plain; charset=utf-8"
        let origCTE = foldedHeaderValue("content-transfer-encoding", in: rawHeaders)
        let bodyStr = String(data: body, encoding: .utf8) ?? ""

        var part = "Content-Type: \(origCT)" + eol
        if let cte = origCTE {
            part += "Content-Transfer-Encoding: \(cte)" + eol
        }
        part += eol + bodyStr
        return part
    }

    func buildSignedMessage(original: Data, signedPart: String, signature: Data) -> Data {
        let boundary = "MailGPGSig_\(UUID().uuidString.replacingOccurrences(of: "-", with: ""))"
        let (rawHeaders, _) = splitMessage(original)

        // Detect line ending style from the original message — Mail.app uses LF (\n),
        // not CRLF (\r\n). Returning mismatched line endings crashes Mail's MIME parser.
        let eol = lineEnding(in: rawHeaders)
        let origCTE = foldedHeaderValue("content-transfer-encoding", in: rawHeaders)
        let sigStr  = String(data: signature, encoding: .utf8) ?? ""

        // MEEncodedOutgoingMessage.rawData must be a complete RFC 2822 message.
        // Strategy: start with the original envelope headers and:
        //   1. Replace Content-Type with our multipart/signed type (and new boundary).
        //   2. Remove Content-Transfer-Encoding from the top level (it now lives inside
        //      the first signed sub-part).
        //   3. Strip our internal X-Mailgpg-* headers so they don't appear in the wire msg.
        //   4. Ensure MIME-Version: 1.0 is present.
        var headers = setHeader(
            "Content-Type",
            to: "multipart/signed; micalg=\"pgp-sha256\";" +
                " protocol=\"application/pgp-signature\"; boundary=\"\(boundary)\"",
            in: rawHeaders)
        if origCTE != nil {
            headers = removeHeader("content-transfer-encoding", from: headers)
        }
        headers = removeHeader("x-mailgpg-sign",      from: headers)
        headers = removeHeader("x-mailgpg-encrypt",   from: headers)
        headers = removeHeader("x-mailgpg-sessionid", from: headers)
        if foldedHeaderValue("mime-version", in: headers) == nil {
            headers += eol + "MIME-Version: 1.0"
        }

        // Assemble the full RFC 2822 message: updated headers + blank line + MIME body.
        // The signedPart is placed byte-for-byte as the first MIME part — this is the
        // exact content the detached signature was computed over.
        let mime = headers + eol +
            eol +
            "--\(boundary)" + eol +
            signedPart + eol +
            "--\(boundary)" + eol +
            "Content-Type: application/pgp-signature; name=\"signature.asc\"" + eol +
            "Content-Disposition: attachment; filename=\"signature.asc\"" + eol +
            eol +
            sigStr + eol +
            "--\(boundary)--" + eol

        log.info("buildSignedMessage: eol=\(eol == "\r\n" ? "CRLF" : "LF") signedPartLen=\(signedPart.count) sigLen=\(signature.count) totalLen=\(mime.count)")
        return mime.data(using: .utf8) ?? Data()
    }

    /// Wrap original message in a PGP/MIME multipart/encrypted envelope.
    ///
    /// Structure (RFC 3156 §4):
    ///   Content-Type: multipart/encrypted;
    ///                 protocol="application/pgp-encrypted"
    ///   --BOUNDARY
    ///   Content-Type: application/pgp-encrypted
    ///   Version: 1
    ///   --BOUNDARY
    ///   Content-Type: application/octet-stream
    ///   <encrypted payload>
    ///   --BOUNDARY--
    func buildEncryptedMessage(original: Data, encrypted: Data) -> Data {
        let boundary = "MailGPGEnc_\(UUID().uuidString.replacingOccurrences(of: "-", with: ""))"
        let (rawHeaders, _) = splitMessage(original)
        let eol = lineEnding(in: rawHeaders)
        let origCTE = foldedHeaderValue("content-transfer-encoding", in: rawHeaders)

        // Build full RFC 2822 message with updated envelope headers.
        var headers = setHeader(
            "Content-Type",
            to: "multipart/encrypted;" +
                " protocol=\"application/pgp-encrypted\"; boundary=\"\(boundary)\"",
            in: rawHeaders)
        if origCTE != nil {
            headers = removeHeader("content-transfer-encoding", from: headers)
        }
        headers = removeHeader("x-mailgpg-sign",      from: headers)
        headers = removeHeader("x-mailgpg-encrypt",   from: headers)
        headers = removeHeader("x-mailgpg-sessionid", from: headers)
        if foldedHeaderValue("mime-version", in: headers) == nil {
            headers += eol + "MIME-Version: 1.0"
        }

        // Build MIME using Data concatenation to avoid creating multi-MB
        // intermediate String copies (String + on large strings is O(n) per op).
        var result = Data()
        let eolBytes = Data(eol.utf8)
        result.append(Data(headers.utf8))
        result.append(eolBytes)
        result.append(eolBytes)
        result.append(Data("--\(boundary)".utf8)); result.append(eolBytes)
        result.append(Data("Content-Type: application/pgp-encrypted".utf8)); result.append(eolBytes)
        result.append(Data("Content-Disposition: attachment".utf8)); result.append(eolBytes)
        result.append(eolBytes)
        result.append(Data("Version: 1".utf8)); result.append(eolBytes)
        result.append(eolBytes)
        result.append(Data("--\(boundary)".utf8)); result.append(eolBytes)
        result.append(Data("Content-Type: application/octet-stream; name=\"encrypted.asc\"".utf8)); result.append(eolBytes)
        result.append(Data("Content-Disposition: inline; filename=\"encrypted.asc\"".utf8)); result.append(eolBytes)
        result.append(eolBytes)
        result.append(encrypted)
        result.append(eolBytes)
        result.append(Data("--\(boundary)--".utf8)); result.append(eolBytes)
        return result
    }

    /// Extract a header value from a block of RFC 2822 headers, collecting
    /// folded (multi-line) continuation lines.
    func foldedHeaderValue(_ name: String, in headers: String) -> String? {
        let lines = headerLines(from: headers)
        let prefix = name.lowercased() + ":"
        var result: String? = nil
        for (i, line) in lines.enumerated() {
            if result != nil {
                if line.hasPrefix(" ") || line.hasPrefix("\t") {
                    result! += " " + line.trimmingCharacters(in: .whitespaces)
                } else {
                    break
                }
            } else if line.lowercased().hasPrefix(prefix) {
                result = String(line.dropFirst(prefix.count)).trimmingCharacters(in: .whitespaces)
                // peek at the next line for continuations
                if i + 1 < lines.count,
                   lines[i + 1].hasPrefix(" ") || lines[i + 1].hasPrefix("\t") {
                    continue  // will be picked up in the next iteration
                }
                break
            }
        }
        return result
    }

    // MARK: - Inline PGP helpers

    /// Extract a named parameter value from a MIME header value string.
    /// e.g. headerParameter("boundary", in: "multipart/alternative; boundary=\"ABC\"") → "ABC"
    private func headerParameter(_ name: String, in headerValue: String) -> String? {
        let lower = headerValue.lowercased()
        let needle = name.lowercased() + "="
        guard let range = lower.range(of: needle) else { return nil }
        let start = headerValue[range.upperBound...]
        if start.hasPrefix("\"") {
            let afterQuote = start.index(after: start.startIndex)
            guard let endQuote = start[afterQuote...].firstIndex(of: "\"") else { return nil }
            return String(start[afterQuote..<endQuote])
        }
        let end = start.firstIndex(where: { ";,\r\n \t".contains($0) }) ?? start.endIndex
        return String(start[..<end])
    }

    /// Decode a MIME part body according to its Content-Transfer-Encoding.
    private func decodedTransferBody(_ body: String, encoding: String?) -> String {
        switch encoding?.lowercased().trimmingCharacters(in: .whitespacesAndNewlines) {
        case "quoted-printable":
            return decodeQuotedPrintable(body)
        case "base64":
            if let data = Data(base64Encoded: body, options: .ignoreUnknownCharacters),
               let str = String(data: data, encoding: .utf8) {
                return str
            }
            return body
        default:
            return body
        }
    }

    /// Normalize all line endings in text to the given style.
    private func normalizeLineEndings(in text: String, to eol: String) -> String {
        let lf = text.replacingOccurrences(of: "\r\n", with: "\n")
        return eol == "\r\n" ? lf.replacingOccurrences(of: "\n", with: "\r\n") : lf
    }

    /// Find the range of the first inline PGP block in a decoded body string.
    private func inlinePGPRange(in body: String) -> Range<String.Index>? {
        guard let start = body.range(of: "-----BEGIN PGP MESSAGE-----"),
              let end = body.range(of: "-----END PGP MESSAGE-----",
                                   range: start.lowerBound..<body.endIndex)
        else { return nil }
        return start.lowerBound..<end.upperBound
    }

    /// Find the text/plain part in a message, decode its content-transfer-encoding,
    /// and return the envelope headers, part content-type, and decoded body text.
    /// Handles top-level text/plain and one level of multipart (alternative/mixed).
    private func findTextPlainBody(in message: String) -> (envelopeHeaders: String, contentType: String, decodedBody: String)? {
        let (headers, bodyData) = splitMessage(message.data(using: .utf8) ?? Data())
        let body = String(data: bodyData, encoding: .utf8) ?? ""
        let ct = foldedHeaderValue("content-type", in: headers) ?? "text/plain; charset=utf-8"

        if ct.lowercased().contains("multipart/"),
           let boundary = headerParameter("boundary", in: ct) {
            let delim = "--" + boundary
            let parts = body.components(separatedBy: delim)
            guard parts.count >= 3 else { return nil }
            for idx in 1..<(parts.count - 1) {
                var piece = parts[idx]
                // Strip the leading newline(s) after the boundary delimiter
                while piece.first == "\r" || piece.first == "\n" { piece.removeFirst() }
                let (partHeaders, partBodyData) = splitMessage(piece.data(using: .utf8) ?? Data())
                let partCT = foldedHeaderValue("content-type", in: partHeaders) ?? "text/plain; charset=utf-8"
                guard partCT.lowercased().hasPrefix("text/plain") else { continue }
                let cte = foldedHeaderValue("content-transfer-encoding", in: partHeaders)
                let partBody = String(data: partBodyData, encoding: .utf8) ?? ""
                return (headers, partCT, decodedTransferBody(partBody, encoding: cte))
            }
            return nil
        }

        guard ct.lowercased().hasPrefix("text/plain") else { return nil }
        let cte = foldedHeaderValue("content-transfer-encoding", in: headers)
        return (headers, ct, decodedTransferBody(body, encoding: cte))
    }

    /// Extract the raw PGP ciphertext from an incoming message so GPG can decrypt it.
    /// Handles both multipart/encrypted (RFC 3156) and inline PGP.
    func extractPGPPayload(from data: Data) -> Data {
        guard let str = String(data: data, encoding: .utf8) else { return data }

        // ── multipart/encrypted (RFC 3156) ───────────────────────────────────
        let (headers, _) = splitMessage(data)
        if let ct = foldedHeaderValue("content-type", in: headers),
           ct.lowercased().contains("multipart/encrypted"),
           let boundary = headerParameter("boundary", in: ct) {
            let delim = "--" + boundary
            let parts = str.components(separatedBy: delim)
            // parts: [preamble, version-part, encrypted-part, epilogue]
            if parts.count >= 3 {
                let encPart = parts[2]
                for sep in ["\r\n\r\n", "\n\n"] {
                    if let bodyStart = encPart.range(of: sep) {
                        let pgp = String(encPart[bodyStart.upperBound...])
                            .trimmingCharacters(in: .whitespacesAndNewlines)
                        return pgp.data(using: .utf8) ?? data
                    }
                }
            }
        }

        // ── inline PGP ──────────────────────────────────────────────────────
        // Try MIME-aware extraction first (decodes CTE, finds text/plain part)
        if let (_, _, decodedBody) = findTextPlainBody(in: str),
           let range = inlinePGPRange(in: decodedBody) {
            return String(decodedBody[range]).data(using: .utf8) ?? data
        }

        // Fallback: raw search on the whole message
        if let range = inlinePGPRange(in: str) {
            return String(str[range]).data(using: .utf8) ?? data
        }

        return data
    }

    /// Reconstruct a complete RFC 2822 message from the outer encrypted envelope
    /// and the decrypted payload. `MEDecodedMessage` requires a full RFC 2822
    /// message, not just the raw decrypted bytes.
    ///
    /// We handle three cases:
    ///  • Inline PGP: the original message contains a PGP block embedded in a
    ///    text/plain body (possibly inside multipart/alternative). The encrypted
    ///    block is replaced with the decrypted text; surrounding prose is kept.
    ///  • Full inner MIME entity (RFC 3156-compliant, used by Thunderbird etc.):
    ///    the decrypted bytes start with MIME headers (e.g. Content-Type:) followed
    ///    by a blank line and the body. We extract those headers and use them.
    ///  • Body-only (used by our own outgoing messages):
    ///    the decrypted bytes are the raw body with no headers. We default to
    ///    text/plain and use the raw bytes as the body.
    func reconstructDecryptedMessage(original: Data, plaintext: Data) -> Data {
        let plaintextStr = String(data: plaintext, encoding: .utf8) ?? ""

        // ── inline PGP: replace just the encrypted block, keep surrounding text ──
        if let originalStr = String(data: original, encoding: .utf8),
           let (envHeaders, partCT, decodedBody) = findTextPlainBody(in: originalStr),
           let pgpRange = inlinePGPRange(in: decodedBody) {
            log.info("decrypt: rebuilt inline PGP message as text/plain")
            let eol = lineEnding(in: envHeaders)
            let rewrittenBody = decodedBody.replacingCharacters(in: pgpRange, with: plaintextStr)

            var headers = removeHeader("content-type", from: envHeaders)
            headers = removeHeader("content-transfer-encoding", from: headers)
            headers = removeHeader("x-mailgpg-sessionid", from: headers)
            headers = setHeader("Content-Type", to: partCT, in: headers)
            headers = setHeader("Content-Transfer-Encoding", to: "8bit", in: headers)
            if foldedHeaderValue("mime-version", in: headers) == nil {
                headers += eol + "MIME-Version: 1.0"
            }
            let normalizedBody = normalizeLineEndings(in: rewrittenBody, to: eol)
            return (headers + eol + eol + normalizedBody).data(using: .utf8) ?? Data(plaintextStr.utf8)
        }

        // ── multipart/encrypted (RFC 3156) ───────────────────────────────────
        let (outerHeaders, _) = splitMessage(original)
        let eol = lineEnding(in: outerHeaders)

        var contentType = "text/plain; charset=utf-8"
        var contentTransferEncoding: String? = nil
        var subject: String? = nil
        var body = plaintextStr

        // Check whether the decrypted content is itself a complete MIME entity.
        for sep in ["\r\n\r\n", "\n\n"] {
            if let range = plaintextStr.range(of: sep) {
                let innerHeaders = String(plaintextStr[..<range.lowerBound])
                if innerHeaders.lowercased().contains("content-type:") {
                    if let ct = foldedHeaderValue("content-type", in: innerHeaders) {
                        contentType = ct
                    }
                    contentTransferEncoding = foldedHeaderValue("content-transfer-encoding", in: innerHeaders)
                    subject = foldedHeaderValue("subject", in: innerHeaders)
                    body = String(plaintextStr[range.upperBound...])
        log.info("decrypt: inner MIME entity detected")
                }
                break
            }
        }

        // Build the reconstructed RFC 2822 message using the outer envelope headers,
        // replacing the multipart/encrypted wrapper with the decrypted content type.
        var headers = removeHeader("content-type", from: outerHeaders)
        headers = removeHeader("content-transfer-encoding", from: headers)
        headers = removeHeader("x-mailgpg-sessionid", from: headers)
        headers = setHeader("Content-Type", to: contentType, in: headers)
        if let cte = contentTransferEncoding {
            headers = setHeader("Content-Transfer-Encoding", to: cte, in: headers)
        }
        if let subject {
            headers = removeHeader("subject", from: headers)
            headers = setHeader("Subject", to: subject, in: headers)
        }
        if foldedHeaderValue("mime-version", in: headers) == nil {
            headers += eol + "MIME-Version: 1.0"
        }

        // Normalize the body to the same line-ending style as the outer headers so
        // the reconstructed message has consistent endings. A mismatch (e.g. LF outer
        // headers + CRLF body from GPG output) lets splitMessage() find a \r\n\r\n
        // inside the quoted body when a reply is composed, corrupting the header split.
        let normalizedBody = normalizeLineEndings(in: body, to: eol)

        let fullMessage = headers + eol + eol + normalizedBody
        log.info("decrypt: reconstructed \(fullMessage.count) bytes (plaintext was \(plaintext.count) bytes)")
        return fullMessage.data(using: .utf8) ?? plaintext
    }
}
