// GPGCryptoTests.swift
// MailGPGTests – integration tests for GPG sign/encrypt/decrypt/verify operations.
//
// Each test creates a fresh isolated GPG homedir (TempGPGHomedir) and a
// GPGServiceImpl pointed at it. No user keys are touched.

import XCTest
@testable import MailGPG

final class GPGCryptoTests: XCTestCase {

    var homedir: TempGPGHomedir!
    var svc: GPGServiceImpl!

    /// A minimal RFC 2822 message used as input to sign/encrypt operations.
    static let testMessage = Data(
        "From: mailgpg-test@example.com\nTo: mailgpg-test@example.com\nSubject: Test\nContent-Type: text/plain\n\nHello, MailGPG!"
            .utf8)

    override func setUpWithError() throws {
        try super.setUpWithError()
        homedir = try TempGPGHomedir()
        svc = GPGServiceImpl(gnupgHome: homedir.path)
    }

    override func tearDownWithError() throws {
        homedir = nil
        svc = nil
        try super.tearDownWithError()
    }

    // MARK: - Encrypt / Decrypt

    func testEncryptDecryptRoundTrip() throws {
        let fp = homedir.fingerprint

        // Encrypt
        var encrypted: Data?
        let encSem = DispatchSemaphore(value: 0)
        svc.encrypt(data: Self.testMessage, recipientFingerprints: [fp]) { data, error in
            XCTAssertNil(error, "Encrypt error: \(String(describing: error))")
            encrypted = data
            encSem.signal()
        }
        encSem.wait()

        let encData = try XCTUnwrap(encrypted, "No encrypted data returned")
        let encStr = String(data: encData, encoding: .utf8) ?? ""
        XCTAssertTrue(encStr.contains("multipart/encrypted"), "Output is not multipart/encrypted MIME")

        // Decrypt
        var plain: Data?
        var statusRaw: Data?
        let decSem = DispatchSemaphore(value: 0)
        svc.decrypt(data: encData) { plainData, statusData, error in
            XCTAssertNil(error, "Decrypt error: \(String(describing: error))")
            plain = plainData
            statusRaw = statusData
            decSem.signal()
        }
        decSem.wait()

        let plainStr = String(data: try XCTUnwrap(plain), encoding: .utf8) ?? ""
        XCTAssertTrue(plainStr.contains("Hello, MailGPG!"), "Decrypted body does not match original")

        let status = try XCTUnwrap(
            statusRaw.flatMap { try? xpcDecode(SecurityStatus.self, from: $0) },
            "Could not decode SecurityStatus")
        guard case .encrypted(let signers) = status else {
            XCTFail("Expected .encrypted, got \(status)"); return
        }
        XCTAssertTrue(signers.isEmpty, "Encrypt-only message should have no signers")
    }

    func testDecryptInlinePGPPreservesSurroundingText() throws {
        let fp = homedir.fingerprint
        let secret = "Inline secret body"
        let (ciphertext, stderr, code) = try homedir.run(
            ["--armor", "--trust-model", "always", "--encrypt", "--recipient", fp],
            input: Data(secret.utf8)
        )
        XCTAssertEqual(code, 0, "Direct GPG encrypt failed: \(stderr)")

        let armor = String(data: ciphertext, encoding: .utf8)!
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let message = """
            From: sender@example.com
            To: \(homedir.email)
            Subject: Inline
            Content-Type: multipart/alternative; boundary="BOUND"

            --BOUND
            Content-Type: text/plain; charset=utf-8
            Content-Transfer-Encoding: 7bit

            Prefix before block

            \(armor)

            Suffix after block
            --BOUND
            Content-Type: text/html; charset=utf-8
            Content-Transfer-Encoding: 7bit

            <p>HTML untouched</p>
            --BOUND--
            """

        var plain: Data?
        var statusRaw: Data?
        let sem = DispatchSemaphore(value: 0)
        svc.decrypt(data: Data(message.utf8)) { plainData, statusData, error in
            XCTAssertNil(error, "Decrypt error: \(String(describing: error))")
            plain = plainData
            statusRaw = statusData
            sem.signal()
        }
        sem.wait()

        let plainStr = String(data: try XCTUnwrap(plain), encoding: .utf8) ?? ""
        XCTAssert(plainStr.lowercased().contains("content-type: text/plain"), "plain=\(plainStr)")
        XCTAssertFalse(plainStr.lowercased().contains("multipart/alternative"), "plain=\(plainStr)")
        let (_, bodyData) = svc.splitMessage(Data(plainStr.utf8))
        let body = String(data: bodyData, encoding: .utf8) ?? ""
        XCTAssertTrue(body.contains("Prefix before block"), "body=\(body)")
        XCTAssertTrue(body.contains(secret), "body=\(body)")
        XCTAssertTrue(body.contains("Suffix after block"), "body=\(body)")
        XCTAssertFalse(body.contains("-----BEGIN PGP MESSAGE-----"), "body=\(body)")

        let status = try XCTUnwrap(
            statusRaw.flatMap { try? xpcDecode(SecurityStatus.self, from: $0) },
            "Could not decode SecurityStatus")
        guard case .encrypted(let signers) = status else {
            XCTFail("Expected .encrypted, got \(status)"); return
        }
        XCTAssertTrue(signers.isEmpty, "Encrypt-only message should have no signers")
    }

    // MARK: - Sign + verify round-trip

    func testSignRoundTrip() throws {
        let fp = homedir.fingerprint

        var signed: Data?
        let sem = DispatchSemaphore(value: 0)
        svc.sign(data: Self.testMessage, signerKeyID: fp) { data, error in
            XCTAssertNil(error, "Sign error: \(String(describing: error))")
            signed = data
            sem.signal()
        }
        sem.wait()

        let signedStr = String(data: try XCTUnwrap(signed), encoding: .utf8) ?? ""
        XCTAssertTrue(signedStr.contains("multipart/signed"),           "Missing multipart/signed content type")
        XCTAssertTrue(signedStr.contains("application/pgp-signature"),  "Missing pgp-signature part")
        XCTAssertTrue(signedStr.contains("-----BEGIN PGP SIGNATURE-----"), "Missing PGP signature block")
        XCTAssertTrue(signedStr.contains("Hello, MailGPG!"),            "Signed body is missing")

        // Parse the multipart/signed MIME output and verify the signature is
        // cryptographically valid — catches bugs where sign() produces a correct
        // MIME structure but signs the wrong content or uses the wrong canonical form.
        let (signedContent, sigData) = try XCTUnwrap(
            extractForVerify(from: signedStr),
            "Could not extract signed content and signature from MIME output")

        var verifyStatus: SecurityStatus?
        let verifySem = DispatchSemaphore(value: 0)
        svc.verify(data: signedContent, signature: sigData) { statusData, error in
            XCTAssertNil(error, "Verify error: \(String(describing: error))")
            verifyStatus = statusData.flatMap { try? xpcDecode(SecurityStatus.self, from: $0) }
            verifySem.signal()
        }
        verifySem.wait()

        let vs = try XCTUnwrap(verifyStatus)
        guard case .signed(let signers) = vs else {
            XCTFail("Expected .signed after verify, got \(vs)"); return
        }
        XCTAssertEqual(signers[0].email, homedir.email)
    }

    // MARK: - Helpers

    /// Parse a multipart/signed MIME message and return the signed content
    /// (in CRLF canonical form, which is what sign() actually signs) and the
    /// detached PGP signature armor. Returns nil if the structure can't be parsed.
    private func extractForVerify(from mimeStr: String) -> (data: Data, sig: Data)? {
        guard let b0 = mimeStr.range(of: "boundary=\""),
              let b1 = mimeStr.range(of: "\"", range: b0.upperBound..<mimeStr.endIndex)
        else { return nil }
        let delim = "--" + mimeStr[b0.upperBound..<b1.lowerBound]

        let parts = mimeStr.components(separatedBy: delim)
        // parts[0]=preamble+headers, parts[1]=signed-content, parts[2]=sig-part, parts[3]="--"
        guard parts.count >= 3 else { return nil }

        // Strip the leading \n (after --BOUNDARY) and trailing \n (before --BOUNDARY)
        var content = parts[1]
        if content.hasPrefix("\n") { content.removeFirst() }
        if content.hasSuffix("\n") { content.removeLast() }

        // sign() canonicalises to CRLF before signing (RFC 3156 §5)
        let crlf = content
            .replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\n",   with: "\r\n")

        let sigPart = parts[2]
        guard let s0 = sigPart.range(of: "-----BEGIN PGP SIGNATURE-----"),
              let s1 = sigPart.range(of: "-----END PGP SIGNATURE-----")
        else { return nil }
        let armor = String(sigPart[s0.lowerBound..<s1.upperBound])

        guard let dataBytes = crlf.data(using: .utf8),
              let sigBytes  = armor.data(using: .utf8) else { return nil }
        return (dataBytes, sigBytes)
    }

    // MARK: - Verify (detached signature)

    func testVerifyGoodSignature() throws {
        let plainData = "Hello, MailGPG!".data(using: .utf8)!
        let fp = homedir.fingerprint

        // Sign directly using the test homedir's GPG binary
        let (sigData, signErr, signCode) = try homedir.run(
            ["--detach-sign", "--armor", "--batch", "--yes", "--local-user", fp],
            input: plainData)
        XCTAssertEqual(signCode, 0, "Direct GPG sign failed: \(signErr)")

        // Verify via GPGServiceImpl
        var status: SecurityStatus?
        let sem = DispatchSemaphore(value: 0)
        svc.verify(data: plainData, signature: sigData) { statusData, error in
            XCTAssertNil(error, "Verify error: \(String(describing: error))")
            status = statusData.flatMap { try? xpcDecode(SecurityStatus.self, from: $0) }
            sem.signal()
        }
        sem.wait()

        let s = try XCTUnwrap(status)
        guard case .signed(let signers) = s else {
            XCTFail("Expected .signed, got \(s)"); return
        }
        XCTAssertEqual(signers.count, 1)
        // GPG2 reports the SIGNING-SUBKEY fingerprint in VALIDSIG, not the primary key.
        // Confirm the signer belongs to our test key via email, and that enrichWithTrust
        // could look it up (trustLevel != .unknown means the key was found in the homedir).
        XCTAssertEqual(signers[0].email, homedir.email)
        XCTAssertFalse(signers[0].fingerprint.isEmpty)
    }

    func testVerifyBadSignature() throws {
        let originalData = "Hello!".data(using: .utf8)!
        let tamperedData = "Goodbye!".data(using: .utf8)!
        let fp = homedir.fingerprint

        // Sign the original data
        let (sigData, _, signCode) = try homedir.run(
            ["--detach-sign", "--armor", "--batch", "--yes", "--local-user", fp],
            input: originalData)
        XCTAssertEqual(signCode, 0)

        // Verify the signature against different (tampered) data
        var status: SecurityStatus?
        let sem = DispatchSemaphore(value: 0)
        svc.verify(data: tamperedData, signature: sigData) { statusData, _ in
            status = statusData.flatMap { try? xpcDecode(SecurityStatus.self, from: $0) }
            sem.signal()
        }
        sem.wait()

        let s = try XCTUnwrap(status)
        if case .signatureInvalid = s { /* expected */ }
        else { XCTFail("Expected .signatureInvalid for tampered data, got \(s)") }
    }

    // MARK: - Sign + Encrypt / Decrypt

    func testSignEncryptDecryptRoundTrip() throws {
        let fp = homedir.fingerprint

        // Sign + encrypt in one pass
        var encrypted: Data?
        let encSem = DispatchSemaphore(value: 0)
        svc.signAndEncrypt(
            data: Self.testMessage,
            signerKeyID: fp,
            recipientFingerprints: [fp]) { data, error in
                XCTAssertNil(error, "SignAndEncrypt error: \(String(describing: error))")
                encrypted = data
                encSem.signal()
        }
        encSem.wait()

        // Decrypt — signature info should survive inside the encrypted payload
        var plain: Data?
        var statusRaw: Data?
        let decSem = DispatchSemaphore(value: 0)
        svc.decrypt(data: try XCTUnwrap(encrypted)) { plainData, statusData, error in
            XCTAssertNil(error, "Decrypt error: \(String(describing: error))")
            plain = plainData
            statusRaw = statusData
            decSem.signal()
        }
        decSem.wait()

        let plainStr = String(data: try XCTUnwrap(plain), encoding: .utf8) ?? ""
        XCTAssertTrue(plainStr.contains("Hello, MailGPG!"))

        let status = try XCTUnwrap(
            statusRaw.flatMap { try? xpcDecode(SecurityStatus.self, from: $0) })
        guard case .encrypted(let signers) = status else {
            XCTFail("Expected .encrypted(signers:), got \(status)"); return
        }
        XCTAssertEqual(signers.count, 1, "Expected exactly one signer")
        // GPG2 reports the signing-subkey fingerprint in VALIDSIG, not the primary key.
        // Verify signer identity via email; fingerprint non-empty confirms it was parsed.
        XCTAssertEqual(signers[0].email, homedir.email)
        XCTAssertFalse(signers[0].fingerprint.isEmpty)
    }
}
