// MIMEHelpersTests.swift
// MailGPGTests

import XCTest
@testable import MailGPG

final class MIMEHelpersTests: XCTestCase {

    let svc = GPGServiceImpl()

    // MARK: - lineEnding

    func testLineEnding_LF() {
        XCTAssertEqual(svc.lineEnding(in: "From: a\nTo: b\n"), "\n")
    }

    func testLineEnding_CRLF() {
        XCTAssertEqual(svc.lineEnding(in: "From: a\r\nTo: b\r\n"), "\r\n")
    }

    func testLineEnding_emptyString() {
        // No line endings → defaults to LF
        XCTAssertEqual(svc.lineEnding(in: ""), "\n")
    }

    // MARK: - splitMessage

    func testSplitMessage_LFSeparator() {
        let msg = "From: a\nTo: b\n\nHello body"
        let (headers, body) = svc.splitMessage(msg.data(using: .utf8)!)
        XCTAssertEqual(headers, "From: a\nTo: b")
        XCTAssertEqual(String(data: body, encoding: .utf8), "Hello body")
    }

    func testSplitMessage_CRLFSeparator() {
        let msg = "From: a\r\nTo: b\r\n\r\nHello body"
        let (headers, body) = svc.splitMessage(msg.data(using: .utf8)!)
        XCTAssertEqual(headers, "From: a\r\nTo: b")
        XCTAssertEqual(String(data: body, encoding: .utf8), "Hello body")
    }

    /// Critical regression: LF headers must split at \n\n even when the body
    /// contains \r\n\r\n (e.g. quoted text inside a decrypted Mailvelope message).
    /// If we searched for \r\n\r\n first we'd split inside the body, causing
    /// lineEnding() to detect CRLF and ultimately crash Mail.app.
    func testSplitMessage_LFHeadersBodyContainsCRLF() {
        let headers = "From: alice@example.com\nContent-Type: text/plain\n"
        let body    = "Hello\r\n\r\nQuoted content\r\n"
        // The real header/body separator is \n\n; the body has \r\n\r\n inside it.
        let data = (headers + "\n" + body).data(using: .utf8)!
        let (parsedHeaders, parsedBody) = svc.splitMessage(data)
        XCTAssertEqual(parsedHeaders, "From: alice@example.com\nContent-Type: text/plain")
        let bodyStr = String(data: parsedBody, encoding: .utf8) ?? ""
        XCTAssert(bodyStr.hasPrefix("Hello"), "Expected body to start with 'Hello', got: \(bodyStr.debugDescription)")
    }

    func testSplitMessage_noSeparator() {
        let msg = "Just a single line with no blank line"
        let data = msg.data(using: .utf8)!
        let (headers, body) = svc.splitMessage(data)
        XCTAssertEqual(headers, msg)
        XCTAssertTrue(body.isEmpty)
    }

    func testSplitMessage_emptyBody() {
        let msg = "From: a\n\n"
        let (headers, body) = svc.splitMessage(msg.data(using: .utf8)!)
        XCTAssertEqual(headers, "From: a")
        XCTAssertTrue(body.isEmpty)
    }

    // MARK: - decodeQuotedPrintable

    func testDecodeQP_softLineBreakCRLF() {
        XCTAssertEqual(svc.decodeQuotedPrintable("Hello=\r\nWorld"), "HelloWorld")
    }

    func testDecodeQP_softLineBreakLF() {
        XCTAssertEqual(svc.decodeQuotedPrintable("Hello=\nWorld"), "HelloWorld")
    }

    func testDecodeQP_hexEncodedASCII() {
        // =41 → 'A', =61 → 'a'
        XCTAssertEqual(svc.decodeQuotedPrintable("=41=61"), "Aa")
    }

    func testDecodeQP_hexEncodedHighByte() {
        // =C3=A9 is UTF-8 for é — must decode the byte pair together, not as separate scalars
        let result = svc.decodeQuotedPrintable("=C3=A9")
        XCTAssertEqual(result, "é")
    }

    func testDecodeQP_passthrough_plainText() {
        let input = "Hello, World! No encoded content here."
        XCTAssertEqual(svc.decodeQuotedPrintable(input), input)
    }

    func testDecodeQP_invalidHexLeftAsIs() {
        // =ZZ is not valid hex → '=' is emitted as-is, 'Z' and 'Z' follow
        let result = svc.decodeQuotedPrintable("A=ZZB")
        XCTAssertEqual(result, "A=ZZB")
    }

    // MARK: - foldedHeaderValue

    func testFoldedHeader_simple() {
        let headers = "From: alice@example.com\nTo: bob@example.com\n"
        XCTAssertEqual(svc.foldedHeaderValue("From", in: headers), "alice@example.com")
        XCTAssertEqual(svc.foldedHeaderValue("To",   in: headers), "bob@example.com")
    }

    func testFoldedHeader_caseInsensitive() {
        let headers = "Content-Type: text/plain; charset=utf-8\n"
        XCTAssertEqual(svc.foldedHeaderValue("content-type",  in: headers), "text/plain; charset=utf-8")
        XCTAssertEqual(svc.foldedHeaderValue("CONTENT-TYPE",  in: headers), "text/plain; charset=utf-8")
    }

    func testFoldedHeader_foldedValue() {
        // Folded (multi-line) header value per RFC 2822 §2.2.3
        let headers = "Content-Type: multipart/signed;\n\tprotocol=\"application/pgp-signature\";\n\tboundary=\"abc123\"\n"
        let val = svc.foldedHeaderValue("Content-Type", in: headers)
        XCTAssertNotNil(val)
        XCTAssert(val!.contains("multipart/signed"),         "val=\(val!)")
        XCTAssert(val!.contains("pgp-signature"),            "val=\(val!)")
        XCTAssert(val!.contains("abc123"),                   "val=\(val!)")
    }

    func testFoldedHeader_missingReturnsNil() {
        let headers = "From: alice@example.com\n"
        XCTAssertNil(svc.foldedHeaderValue("Subject", in: headers))
    }

    func testFoldedHeader_CRLF() {
        let headers = "From: alice@example.com\r\nTo: bob@example.com\r\n"
        XCTAssertEqual(svc.foldedHeaderValue("From", in: headers), "alice@example.com")
    }

    // MARK: - removeHeader

    func testRemoveHeader_simple() {
        let headers = "From: a\nContent-Transfer-Encoding: quoted-printable\nTo: b\n"
        let result  = svc.removeHeader("Content-Transfer-Encoding", from: headers)
        XCTAssertFalse(result.lowercased().contains("content-transfer-encoding"))
        XCTAssert(result.contains("From: a"))
        XCTAssert(result.contains("To: b"))
    }

    func testRemoveHeader_withContinuationLines() {
        let headers = "From: a\nContent-Type: multipart/signed;\n\tprotocol=\"pgp\";\n\tboundary=\"abc\"\nTo: b\n"
        let result  = svc.removeHeader("Content-Type", from: headers)
        XCTAssertFalse(result.lowercased().contains("content-type"))
        XCTAssertFalse(result.contains("protocol"))
        XCTAssertFalse(result.contains("boundary"))
        XCTAssert(result.contains("From: a"))
        XCTAssert(result.contains("To: b"))
    }

    func testRemoveHeader_notPresent_unchanged() {
        let headers = "From: a\nTo: b\n"
        let result  = svc.removeHeader("Subject", from: headers)
        XCTAssert(result.contains("From: a"))
        XCTAssert(result.contains("To: b"))
    }

    func testRemoveHeader_preservesCRLF() {
        let headers = "From: a\r\nContent-Transfer-Encoding: 7bit\r\nTo: b\r\n"
        let result  = svc.removeHeader("Content-Transfer-Encoding", from: headers)
        XCTAssert(result.contains("\r\n"),                                          "should keep CRLF")
        XCTAssertFalse(result.lowercased().contains("content-transfer-encoding"))
    }

    // MARK: - setHeader

    func testSetHeader_replace() {
        let headers = "From: a\nContent-Type: text/plain\nTo: b\n"
        let result  = svc.setHeader("Content-Type", to: "text/html; charset=utf-8", in: headers)
        XCTAssert(result.contains("Content-Type: text/html; charset=utf-8"))
        XCTAssertFalse(result.contains("text/plain"))
    }

    func testSetHeader_append() {
        let headers = "From: a\nTo: b\n"
        let result  = svc.setHeader("Subject", to: "Hello", in: headers)
        XCTAssert(result.contains("Subject: Hello"))
        XCTAssert(result.contains("From: a"))
    }

    func testSetHeader_replaceDropsContinuationLines() {
        let headers = "From: a\nContent-Type: multipart/signed;\n\tprotocol=\"pgp\"\nTo: b\n"
        let result  = svc.setHeader("Content-Type", to: "text/plain", in: headers)
        XCTAssert(result.contains("Content-Type: text/plain"))
        XCTAssertFalse(result.contains("protocol"))
    }

    func testSetHeader_preservesLFStyle() {
        let result = svc.setHeader("Subject", to: "Hi", in: "From: a\nTo: b\n")
        XCTAssertFalse(result.contains("\r\n"))
    }

    func testSetHeader_preservesCRLFStyle() {
        let result = svc.setHeader("Subject", to: "Hi", in: "From: a\r\nTo: b\r\n")
        XCTAssert(result.contains("\r\n"))
    }

    // MARK: - extractPGPPayload

    func testExtractPGPPayload_multipartEncrypted() {
        let ciphertext = "-----BEGIN PGP MESSAGE-----\nhEwDAAAAAAAAAAA\n-----END PGP MESSAGE-----"
        let msg = """
            From: alice@example.com
            Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary="BOUND"

            --BOUND
            Content-Type: application/pgp-encrypted
            Content-Disposition: attachment

            Version: 1

            --BOUND
            Content-Type: application/octet-stream; name="encrypted.asc"
            Content-Disposition: inline; filename="encrypted.asc"

            \(ciphertext)
            --BOUND--
            """
        let result = svc.extractPGPPayload(from: msg.data(using: .utf8)!)
        let str = String(data: result, encoding: .utf8) ?? ""
        XCTAssert(str.contains("-----BEGIN PGP MESSAGE-----"), "str=\(str)")
        XCTAssert(str.contains("-----END PGP MESSAGE-----"),   "str=\(str)")
    }

    func testExtractPGPPayload_unquotedBoundary() {
        // boundary= without quotes
        let ciphertext = "-----BEGIN PGP MESSAGE-----\nhEwD\n-----END PGP MESSAGE-----"
        let msg = """
            Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary=BOUND2

            --BOUND2
            Content-Type: application/pgp-encrypted

            Version: 1

            --BOUND2
            Content-Type: application/octet-stream

            \(ciphertext)
            --BOUND2--
            """
        let result = svc.extractPGPPayload(from: msg.data(using: .utf8)!)
        let str = String(data: result, encoding: .utf8) ?? ""
        XCTAssert(str.contains("-----BEGIN PGP MESSAGE-----"), "str=\(str)")
    }

    func testExtractPGPPayload_inlinePGP() {
        let msg = "From: alice@example.com\n\n-----BEGIN PGP MESSAGE-----\nhEwD\n-----END PGP MESSAGE-----\n"
        let result = svc.extractPGPPayload(from: msg.data(using: .utf8)!)
        let str = String(data: result, encoding: .utf8) ?? ""
        XCTAssert(str.hasPrefix("-----BEGIN PGP MESSAGE-----"), "str=\(str)")
        XCTAssert(str.contains("-----END PGP MESSAGE-----"),   "str=\(str)")
    }

    func testExtractPGPPayload_multipartAlternativeQuotedPrintable() {
        let msg = """
            From: sender@example.invalid
            To: recipient@example.invalid
            Subject: Inline QP test
            Content-Type: multipart/alternative; boundary="BOUND"

            --BOUND
            Content-Transfer-Encoding: quoted-printable
            Content-Type: text/plain; charset=utf-8

            Intro text

            -----BEGIN PGP MESSAGE-----

            =
            wV4DTESTPAYLOADONE=
            123
            FINALPAYLOAD=3D=3D
            =3DABCD
            -----END PGP MESSAGE-----

            Outro text
            --BOUND
            Content-Type: text/html; charset=utf-8

            <p>HTML copy</p>
            --BOUND--
            """
        let result = svc.extractPGPPayload(from: msg.data(using: .utf8)!)
        let str = String(data: result, encoding: .utf8) ?? ""
        XCTAssert(str.hasPrefix("-----BEGIN PGP MESSAGE-----"), "str=\(str.prefix(80))")
        XCTAssert(str.contains("-----END PGP MESSAGE-----"), "str=\(str.suffix(80))")
        XCTAssertFalse(str.contains("=3D"), "QP escapes should be decoded; str=\(str)")
        XCTAssertFalse(str.contains("Intro text"), "surrounding prose must not be in payload; str=\(str)")
        XCTAssertFalse(str.contains("Outro text"), "surrounding prose must not be in payload; str=\(str)")
    }

    func testExtractPGPPayload_base64TextPlainPart() {
        let armor = "-----BEGIN PGP MESSAGE-----\nhEwD\n-----END PGP MESSAGE-----\n"
        let encoded = Data(armor.utf8).base64EncodedString()
        let msg = """
            Content-Type: multipart/alternative; boundary="BOUND"

            --BOUND
            Content-Type: text/plain; charset=utf-8
            Content-Transfer-Encoding: base64

            \(encoded)
            --BOUND--
            """
        let result = svc.extractPGPPayload(from: msg.data(using: .utf8)!)
        let str = String(data: result, encoding: .utf8) ?? ""
        XCTAssertTrue(str.contains("-----BEGIN PGP MESSAGE-----"), "str=\(str)")
        XCTAssertTrue(str.contains("-----END PGP MESSAGE-----"), "str=\(str)")
    }

    func testExtractPGPPayload_plainMessage_returnsOriginal() {
        let msg  = "From: alice@example.com\n\nHello, no PGP here."
        let data = msg.data(using: .utf8)!
        XCTAssertEqual(svc.extractPGPPayload(from: data), data)
    }

    // MARK: - buildInnerMIMEEntity

    func testBuildInnerMIMEEntity_basic() {
        let headers = "From: a\nContent-Type: text/plain; charset=utf-8\n"
        let body    = "Hello, World!".data(using: .utf8)!
        let str     = String(data: svc.buildInnerMIMEEntity(rawHeaders: headers, body: body), encoding: .utf8) ?? ""
        XCTAssert(str.hasPrefix("Content-Type: text/plain; charset=utf-8"), "str=\(str)")
        XCTAssert(str.contains("\r\n\r\n"), "inner entity must use CRLF blank line; str=\(str)")
        XCTAssert(str.hasSuffix("Hello, World!"))
    }

    func testBuildInnerMIMEEntity_includesCTE() {
        let headers = "Content-Type: text/plain\nContent-Transfer-Encoding: quoted-printable\n"
        let str     = String(data: svc.buildInnerMIMEEntity(rawHeaders: headers, body: "Hi".data(using: .utf8)!), encoding: .utf8) ?? ""
        XCTAssert(str.contains("Content-Transfer-Encoding: quoted-printable"))
    }

    func testBuildInnerMIMEEntity_defaultsToTextPlain() {
        // No Content-Type in outer headers
        let headers = "From: a\n"
        let str     = String(data: svc.buildInnerMIMEEntity(rawHeaders: headers, body: "Hi".data(using: .utf8)!), encoding: .utf8) ?? ""
        XCTAssert(str.contains("Content-Type: text/plain; charset=utf-8"))
    }

    // MARK: - buildSignedPart

    func testBuildSignedPart_inheritsLFLineEnding() {
        let headers = "From: a\nContent-Type: text/plain\n"
        let result  = svc.buildSignedPart(rawHeaders: headers, body: "Hi".data(using: .utf8)!)
        XCTAssertFalse(result.contains("\r\n"), "LF message must produce LF signed part; result=\(result.debugDescription)")
    }

    func testBuildSignedPart_inheritsCRLFLineEnding() {
        let headers = "From: a\r\nContent-Type: text/plain\r\n"
        let result  = svc.buildSignedPart(rawHeaders: headers, body: "Hi".data(using: .utf8)!)
        XCTAssert(result.contains("\r\n"))
    }

    func testBuildSignedPart_startsWithContentType() {
        // RFC 3156 §5: signed content starts with Content-Type header, not envelope headers
        let headers = "From: a\nContent-Type: text/plain; charset=utf-8\n"
        let result  = svc.buildSignedPart(rawHeaders: headers, body: "Body".data(using: .utf8)!)
        XCTAssert(result.hasPrefix("Content-Type:"), "result=\(result.debugDescription)")
    }

    func testBuildSignedPart_hasBlankLineBeforeBody() {
        let headers = "From: a\nContent-Type: text/plain\n"
        let result  = svc.buildSignedPart(rawHeaders: headers, body: "TheBody".data(using: .utf8)!)
        XCTAssert(result.contains("\n\nTheBody"), "result=\(result.debugDescription)")
    }

    // MARK: - reconstructDecryptedMessage

    func testReconstructDecryptedMessage_bodyOnly() {
        let original  = "From: alice@example.com\nContent-Type: multipart/encrypted; boundary=\"X\"\n\n--X"
        let plaintext = "Plain decrypted body."
        let result    = String(data: svc.reconstructDecryptedMessage(
            original:  original.data(using: .utf8)!,
            plaintext: plaintext.data(using: .utf8)!
        ), encoding: .utf8) ?? ""
        XCTAssert(result.contains("From: alice@example.com"))
        XCTAssert(result.lowercased().contains("content-type: text/plain"), "result=\(result)")
        XCTAssert(result.contains("Plain decrypted body."))
    }

    func testReconstructDecryptedMessage_innerMIMEEntity() {
        // Thunderbird-style: decrypted payload is itself a MIME entity
        let original  = "From: alice@example.com\nContent-Type: multipart/encrypted; boundary=\"X\"\n\n--X"
        let plaintext = "Content-Type: text/html; charset=utf-8\n\n<p>Hello</p>"
        let result    = String(data: svc.reconstructDecryptedMessage(
            original:  original.data(using: .utf8)!,
            plaintext: plaintext.data(using: .utf8)!
        ), encoding: .utf8) ?? ""
        XCTAssert(result.contains("From: alice@example.com"))
        XCTAssert(result.lowercased().contains("content-type: text/html"), "result=\(result)")
        XCTAssert(result.contains("<p>Hello</p>"))
    }

    func testReconstructDecryptedMessage_innerSubjectOverridesOuter() {
        let original  = "From: alice@example.com\nSubject: Outer Subject\nContent-Type: multipart/encrypted; boundary=\"X\"\n\n--X"
        let plaintext = "Content-Type: text/plain\nSubject: Inner Secret Subject\n\nSecret"
        let result    = String(data: svc.reconstructDecryptedMessage(
            original:  original.data(using: .utf8)!,
            plaintext: plaintext.data(using: .utf8)!
        ), encoding: .utf8) ?? ""
        XCTAssert(result.contains("Subject: Inner Secret Subject"),   "result=\(result)")
        XCTAssertFalse(result.contains("Subject: Outer Subject"),     "outer subject must be replaced; result=\(result)")
    }

    func testReconstructDecryptedMessage_normalizesCRLFBodyToLF() {
        // If outer headers use LF but GPG outputs CRLF plaintext, the body should
        // be normalised to LF so splitMessage() doesn't false-split on \r\n\r\n later.
        let original  = "From: a\nContent-Type: multipart/encrypted; boundary=\"X\"\n\n--X"
        let plaintext = "Hello\r\nWorld"
        let result    = String(data: svc.reconstructDecryptedMessage(
            original:  original.data(using: .utf8)!,
            plaintext: plaintext.data(using: .utf8)!
        ), encoding: .utf8) ?? ""
        // Body portion should not contain \r\n since outer headers are LF
        let bodyStart = result.range(of: "\n\n").map { result[$0.upperBound...] }.map(String.init) ?? result
        XCTAssertFalse(bodyStart.contains("\r\n"), "CRLF body not normalised; body=\(bodyStart.debugDescription)")
    }

    // MARK: - reconstructDecryptedMessage (inline PGP)

    func testReconstructDecryptedMessage_inlinePGPPreservesSurroundingText() throws {
        let msg = """
            From: notifications@example.invalid
            To: assigned@example.invalid
            Subject: Re: Inline reply
            Mime-Version: 1.0
            Content-Type: multipart/alternative;
             boundary="--==_mimepart_test"
            Content-Transfer-Encoding: 7bit

            ----==_mimepart_test
            Content-Type: text/plain;
             charset=UTF-8
            Content-Transfer-Encoding: 7bit

            Someone left a comment

            -----BEGIN PGP MESSAGE-----

            wV4DTESTPAYLOADLINEONE123
            FINALPAYLOAD==
            =ABCD
            -----END PGP MESSAGE-----

            Reply to this message
            ----==_mimepart_test
            Content-Type: text/html;
             charset=UTF-8

            <p>HTML part</p>
            ----==_mimepart_test--
            """
        let result = String(data: svc.reconstructDecryptedMessage(
            original: Data(msg.utf8),
            plaintext: Data("Secret replacement".utf8)
        ), encoding: .utf8) ?? ""
        XCTAssert(result.lowercased().contains("content-type: text/plain"), "result=\(result)")
        XCTAssertFalse(result.lowercased().contains("multipart/alternative"), "result=\(result)")
        let (_, bodyData) = svc.splitMessage(result.data(using: .utf8)!)
        let body = String(data: bodyData, encoding: .utf8) ?? ""
        XCTAssert(body.contains("Someone left a comment"), "body=\(body)")
        XCTAssert(body.contains("Secret replacement"), "body=\(body)")
        XCTAssert(body.contains("Reply to this message"), "body=\(body)")
        XCTAssertFalse(body.contains("-----BEGIN PGP MESSAGE-----"), "PGP block should be replaced; body=\(body)")
    }

    func testReconstructDecryptedMessage_inlinePGPWithQuotedPrintableUnicode() throws {
        let msg = """
            From: sender@example.invalid
            To: recipient@example.invalid
            Subject: Unicode inline
            Content-Type: multipart/alternative; boundary="UB"

            --UB
            Content-Type: text/plain; charset=utf-8
            Content-Transfer-Encoding: quoted-printable

            Gr=C3=BC=C3=9Fe vor dem Block

            -----BEGIN PGP MESSAGE-----

            TESTPAYLOAD=3D=3D
            =3DCRC
            -----END PGP MESSAGE-----

            Tsch=C3=BC=C3=9F nach dem Block
            --UB--
            """
        let result = String(data: svc.reconstructDecryptedMessage(
            original: Data(msg.utf8),
            plaintext: Data("Entschlüsselter Inhalt".utf8)
        ), encoding: .utf8) ?? ""
        let (_, bodyData) = svc.splitMessage(result.data(using: .utf8)!)
        let body = String(data: bodyData, encoding: .utf8) ?? ""
        XCTAssert(body.contains("Grüße vor dem Block"), "body=\(body)")
        XCTAssert(body.contains("Entschlüsselter Inhalt"), "body=\(body)")
        XCTAssert(body.contains("Tschüß nach dem Block"), "body=\(body)")
        XCTAssertFalse(body.contains("=C3=BC"), "QP escapes should be decoded; body=\(body)")
        XCTAssertFalse(body.contains("-----BEGIN PGP MESSAGE-----"), "body=\(body)")
    }
}
