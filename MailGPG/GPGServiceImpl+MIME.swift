// GPGServiceImpl+MIME.swift
// MailGPG (host app only)

import Foundation
import os

extension GPGServiceImpl {

    // MARK: - RFC 2822 / MIME helpers

    /// Decode a quoted-printable encoded string (RFC 2045).
    /// Removes soft line breaks (=\r\n, =\n) and replaces =XX with the corresponding byte.
    func decodeQuotedPrintable(_ s: String) -> String {
        var out = s.replacingOccurrences(of: "=\r\n", with: "")
                   .replacingOccurrences(of: "=\n", with: "")
        var result = ""; var i = out.startIndex
        while i < out.endIndex {
            if out[i] == "=", let j = out.index(i, offsetBy: 3, limitedBy: out.endIndex),
               let byte = UInt8(String(out[out.index(after: i)..<j]), radix: 16) {
                result += String(UnicodeScalar(byte)); i = j
            } else { result.append(out[i]); i = out.index(after: i) }
        }
        return result
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

    /// Remove a named header (and any folded continuation lines) from a header block.
    /// Preserves the original line ending style.
    func removeHeader(_ name: String, from headers: String) -> String {
        let eol = lineEnding(in: headers)
        let lines = headers.components(separatedBy: "\n").map {
            $0.hasSuffix("\r") ? String($0.dropLast()) : $0
        }
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
        let lines = headers.components(separatedBy: "\n").map {
            $0.hasSuffix("\r") ? String($0.dropLast()) : $0
        }
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

    /// Wrap original message in a PGP/MIME multipart/signed envelope.
    ///
    /// Structure (RFC 3156 §5):
    ///   Content-Type: multipart/signed; micalg="pgp-sha256";
    ///                 protocol="application/pgp-signature"
    ///   --BOUNDARY
    ///   <original body>
    ///   --BOUNDARY
    ///   Content-Type: application/pgp-signature
    ///   <detached signature>
    ///   --BOUNDARY--
    /// Build the first MIME body part for a multipart/signed message.
    /// This is the content that gets signed with `gpg --detach-sign`.
    /// RFC 3156 §5: the signature covers the complete first MIME part
    /// (part headers + blank line + body), NOT just the message body text.
    /// Build a self-contained inner MIME entity from the original message's
    /// Content-Type (+ Content-Transfer-Encoding) and body.  This is what gets
    /// encrypted — so when the recipient (or our own extension) decrypts, the
    /// output starts with MIME headers and can be parsed correctly.
    /// Without this, multipart/alternative bodies (text + html) lose their
    /// Content-Type wrapper and recipients see raw MIME boundary text.
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
        let lines = headers.components(separatedBy: "\n").map {
            $0.hasSuffix("\r") ? String($0.dropLast()) : $0
        }
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

    /// Extract the raw PGP ciphertext from an incoming message so GPG can decrypt it.
    /// Handles both multipart/encrypted (RFC 3156) and inline PGP.
    func extractPGPPayload(from data: Data) -> Data {
        guard let str = String(data: data, encoding: .utf8) else { return data }

        // ── multipart/encrypted ──────────────────────────────────────────────
        if str.contains("multipart/encrypted") {
            // Find the boundary value — may be quoted or unquoted.
            var boundary: String? = nil
            if let s = str.range(of: "boundary=\""),
               let e = str.range(of: "\"", range: s.upperBound..<str.endIndex) {
                boundary = String(str[s.upperBound..<e.lowerBound])
            } else if let s = str.range(of: "boundary=") {
                let rest = String(str[s.upperBound...])
                let end  = rest.firstIndex(where: { ";,\r\n \t".contains($0) })
                boundary = end.map { String(rest[..<$0]) } ?? rest
            }

            if let b = boundary {
                let delim = "--" + b
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
        }

        // ── inline PGP ───────────────────────────────────────────────────────
        if let start = str.range(of: "-----BEGIN PGP MESSAGE-----"),
           let end   = str.range(of: "-----END PGP MESSAGE-----") {
            let endIdx = str.index(end.upperBound, offsetBy: 0)
            return String(str[start.lowerBound..<endIdx]).data(using: .utf8) ?? data
        }

        return data
    }

    /// Reconstruct a complete RFC 2822 message from the outer encrypted envelope
    /// and the decrypted payload. `MEDecodedMessage` requires a full RFC 2822
    /// message, not just the raw decrypted bytes.
    ///
    /// We handle two formats:
    ///  • Full inner MIME entity (RFC 3156-compliant, used by Thunderbird etc.):
    ///    the decrypted bytes start with MIME headers (e.g. Content-Type:) followed
    ///    by a blank line and the body. We extract those headers and use them.
    ///  • Body-only (used by our own outgoing messages):
    ///    the decrypted bytes are the raw body with no headers. We default to
    ///    text/plain and use the raw bytes as the body.
    func reconstructDecryptedMessage(original: Data, plaintext: Data) -> Data {
        let (outerHeaders, _) = splitMessage(original)
        let eol = lineEnding(in: outerHeaders)
        let plaintextStr = String(data: plaintext, encoding: .utf8) ?? ""

        var contentType = "text/plain; charset=utf-8"
        var contentTransferEncoding: String? = nil
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
                    body = String(plaintextStr[range.upperBound...])
                    log.info("decrypt: inner MIME entity detected, content-type=\(contentType)")
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
        if foldedHeaderValue("mime-version", in: headers) == nil {
            headers += eol + "MIME-Version: 1.0"
        }

        // Normalize the body to the same line-ending style as the outer headers so
        // the reconstructed message has consistent endings. A mismatch (e.g. LF outer
        // headers + CRLF body from GPG output) lets splitMessage() find a \r\n\r\n
        // inside the quoted body when a reply is composed, corrupting the header split.
        let normalizedBody = eol == "\r\n"
            ? body.replacingOccurrences(of: "\r\n", with: "\n").replacingOccurrences(of: "\n", with: "\r\n")
            : body.replacingOccurrences(of: "\r\n", with: "\n")

        let fullMessage = headers + eol + eol + normalizedBody
        log.info("decrypt: reconstructed \(fullMessage.count) bytes (plaintext was \(plaintext.count) bytes)")
        return fullMessage.data(using: .utf8) ?? plaintext
    }
}
