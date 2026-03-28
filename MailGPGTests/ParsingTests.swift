// ParsingTests.swift
// MailGPGTests

import XCTest
@testable import MailGPG

final class ParsingTests: XCTestCase {

    let svc = GPGServiceImpl()

    // MARK: - parseUID

    func testParseUID_fullFormat() {
        let (name, email) = svc.parseUID("Alice Wonderland (work key) <alice@example.com>")
        XCTAssertEqual(name,  "Alice Wonderland")
        XCTAssertEqual(email, "alice@example.com")
    }

    func testParseUID_noComment() {
        let (name, email) = svc.parseUID("Bob Builder <bob@example.com>")
        XCTAssertEqual(name,  "Bob Builder")
        XCTAssertEqual(email, "bob@example.com")
    }

    func testParseUID_noEmail() {
        let (name, email) = svc.parseUID("Carol Without Email")
        XCTAssertEqual(name,  "Carol Without Email")
        XCTAssertEqual(email, "")
    }

    func testParseUID_emailOnly() {
        let (_, email) = svc.parseUID("<dave@example.com>")
        XCTAssertEqual(email, "dave@example.com")
    }

    func testParseUID_empty() {
        let (name, email) = svc.parseUID("")
        XCTAssertEqual(name,  "")
        XCTAssertEqual(email, "")
    }

    func testParseUID_usesLastAngleBrackets() {
        // Multiple angle bracket pairs → last pair wins
        let (_, email) = svc.parseUID("Name <old@example.com> <real@example.com>")
        XCTAssertEqual(email, "real@example.com")
    }

    // MARK: - parseColonOutput: public keys

    // GPG colon format: type:validity:keylen:algo:keyid:created:expires:hash:ownertrust:uid_or_fpr...
    //                    [0]    [1]      [2]   [3]   [4]    [5]     [6]   [7]    [8]       [9]

    func testParseColonOutput_publicKey() {
        // validity(f=full), ownertrust(u=ultimate), no expiry
        let output = """
            pub:f:4096:1:AABBCCDD11223344:1600000000:::u:
            fpr:::::::::AABBCCDD112233441122334411223344AABBCCDD:
            uid:f::::1600000001::UID_HASH::Alice Wonderland <alice@example.com>:::::::::0:
            sub:f:4096:1:DEADBEEFDEADBEEF:1600000000::::::e:
            """
        let keys = svc.parseColonOutput(output, wantSecretKeys: false)
        XCTAssertEqual(keys.count, 1)
        let k = keys[0]
        XCTAssertEqual(k.fingerprint,  "AABBCCDD112233441122334411223344AABBCCDD")
        XCTAssertEqual(k.keyID,        "AABBCCDD")    // last 8 chars of fingerprint
        XCTAssertEqual(k.name,         "Alice Wonderland")
        XCTAssertEqual(k.email,        "alice@example.com")
        XCTAssertEqual(k.trustLevel,   .ultimate)     // ownertrust field = 'u'
        XCTAssertEqual(k.validity,     .full)          // validity field   = 'f'
        XCTAssertFalse(k.hasSecretKey)
        XCTAssertFalse(k.isRevoked)
        XCTAssertNil(k.expiresAt)
    }

    func testParseColonOutput_secretKey() {
        let output = """
            sec:u:4096:1:AABBCCDD11223344:1600000000:::u:
            fpr:::::::::AABBCCDD112233441122334411223344AABBCCDD:
            uid:u::::1600000001::UID_HASH::Bob Builder <bob@example.com>:::::::::0:
            ssb:u:4096:1:DEADBEEFDEADBEEF:1600000000::::::e:
            """
        let keys = svc.parseColonOutput(output, wantSecretKeys: true)
        XCTAssertEqual(keys.count, 1)
        XCTAssertEqual(keys[0].name,  "Bob Builder")
        XCTAssertEqual(keys[0].email, "bob@example.com")
        XCTAssertTrue(keys[0].hasSecretKey)
    }

    func testParseColonOutput_secretKeyStub() {
        // sec# = stub: key lives on smartcard/YubiKey, no local private key bytes
        let output = """
            sec#:u:4096:1:AABBCCDD11223344:1600000000:::u:
            fpr:::::::::AABBCCDD112233441122334411223344AABBCCDD:
            uid:u::::1600000001::UID_HASH::Carol Yubikey <carol@example.com>:::::::::0:
            """
        let keys = svc.parseColonOutput(output, wantSecretKeys: true)
        XCTAssertEqual(keys.count, 1)
        XCTAssertEqual(keys[0].email, "carol@example.com")
    }

    func testParseColonOutput_revokedKey() {
        let output = """
            pub:r:4096:1:AABBCCDD11223344:1600000000:::u:
            fpr:::::::::AABBCCDD112233441122334411223344AABBCCDD:
            uid:r::::1600000001::UID_HASH::Dave Revoked <dave@example.com>:::::::::0:
            """
        let keys = svc.parseColonOutput(output, wantSecretKeys: false)
        XCTAssertEqual(keys.count, 1)
        XCTAssertTrue(keys[0].isRevoked)
    }

    func testParseColonOutput_withExpiry() {
        let expiry: Double = 1893456000
        let output = """
            pub:f:4096:1:AABBCCDD11223344:1600000000:\(Int(expiry))::u:
            fpr:::::::::AABBCCDD112233441122334411223344AABBCCDD:
            uid:f::::1600000001::UID_HASH::Eve Expires <eve@example.com>:::::::::0:
            """
        let keys = svc.parseColonOutput(output, wantSecretKeys: false)
        XCTAssertEqual(keys.count, 1)
        XCTAssertNotNil(keys[0].expiresAt)
        XCTAssertEqual(keys[0].expiresAt!.timeIntervalSince1970, expiry, accuracy: 1.0)
    }

    func testParseColonOutput_ownertrust_n_mapsToNone() {
        // GPG uses 'n' for "not trusted" in the ownertrust field, but 'n' is not a
        // TrustLevel raw value — it must be explicitly mapped to .none.
        let output = """
            pub:f:4096:1:AABBCCDD11223344:1600000000:::n:
            fpr:::::::::AABBCCDD112233441122334411223344AABBCCDD:
            uid:f::::1600000001::UID_HASH::Frank <frank@example.com>:::::::::0:
            """
        let keys = svc.parseColonOutput(output, wantSecretKeys: false)
        XCTAssertEqual(keys.count, 1)
        XCTAssertEqual(keys[0].trustLevel, .none)
    }

    func testParseColonOutput_validity_n_mapsToNone() {
        // Same mapping but for the validity field
        let output = """
            pub:n:4096:1:AABBCCDD11223344:1600000000:::u:
            fpr:::::::::AABBCCDD112233441122334411223344AABBCCDD:
            uid:n::::1600000001::UID_HASH::Grace <grace@example.com>:::::::::0:
            """
        let keys = svc.parseColonOutput(output, wantSecretKeys: false)
        XCTAssertEqual(keys.count, 1)
        XCTAssertEqual(keys[0].validity, .none)
    }

    func testParseColonOutput_firstUIDOnly() {
        // Multiple UIDs per key — only the first should be returned
        let output = """
            pub:f:4096:1:AABBCCDD11223344:1600000000:::u:
            fpr:::::::::AABBCCDD112233441122334411223344AABBCCDD:
            uid:f::::1600000001::UID_HASH::Primary Name <primary@example.com>:::::::::0:
            uid:f::::1600000002::UID_HASH::Secondary Name <secondary@example.com>:::::::::0:
            """
        let keys = svc.parseColonOutput(output, wantSecretKeys: false)
        XCTAssertEqual(keys.count, 1)
        XCTAssertEqual(keys[0].email, "primary@example.com")
    }

    func testParseColonOutput_ignoresSecKeyRecords_whenWantingPublic() {
        let output = """
            sec:u:4096:1:AABBCCDD11223344:1600000000:::u:
            fpr:::::::::AABBCCDD112233441122334411223344AABBCCDD:
            uid:u::::1600000001::UID_HASH::Alice <alice@example.com>:::::::::0:
            """
        let keys = svc.parseColonOutput(output, wantSecretKeys: false)
        XCTAssertTrue(keys.isEmpty, "sec record must be ignored when wantSecretKeys=false")
    }

    func testParseColonOutput_multipleTrustLevels() {
        // Smoke-test all TrustLevel raw values round-trip through the parser
        let levels: [(String, TrustLevel)] = [("?", .unknown), ("-", .none), ("m", .marginal), ("f", .full), ("u", .ultimate)]
        for (raw, expected) in levels {
            let output = """
                pub:f:4096:1:AABBCCDD11223344:1600000000:::\(raw):
                fpr:::::::::AABBCCDD112233441122334411223344AABBCCDD:
                uid:f::::1600000001::H::Test <test@example.com>:::::::::0:
                """
            let keys = svc.parseColonOutput(output, wantSecretKeys: false)
            XCTAssertEqual(keys.first?.trustLevel, expected, "raw='\(raw)' should map to \(expected)")
        }
    }

    // MARK: - parseDecryptStatus

    func testParseDecryptStatus_encryptedOnly() {
        let stderr = """
            gpg: encrypted with rsa4096 key
            [GNUPG:] ENC_TO AABBCCDD11223344 1 0
            [GNUPG:] DECRYPTION_OKAY
            """
        let status = svc.parseDecryptStatus(stderr: stderr)
        if case .encrypted(let signers) = status {
            XCTAssertTrue(signers.isEmpty)
        } else {
            XCTFail("Expected .encrypted, got \(status)")
        }
    }

    func testParseDecryptStatus_encryptedAndSigned() {
        // GOODSIG followed by VALIDSIG (which provides the full fingerprint)
        let stderr = """
            [GNUPG:] ENC_TO AABBCCDD11223344 1 0
            [GNUPG:] DECRYPTION_OKAY
            [GNUPG:] GOODSIG AABBCCDD11223344 Alice Wonderland <alice@example.com>
            [GNUPG:] VALIDSIG AABBCCDD112233441122334411223344AABBCCDD 2021-01-01 1609459200 0 4 0 1 8 00 AABBCCDD112233441122334411223344AABBCCDD
            """
        let status = svc.parseDecryptStatus(stderr: stderr)
        if case .encrypted(let signers) = status {
            XCTAssertEqual(signers.count, 1)
            XCTAssertEqual(signers[0].email,       "alice@example.com")
            XCTAssertEqual(signers[0].keyID,       "AABBCCDD11223344")
            XCTAssertEqual(signers[0].fingerprint, "AABBCCDD112233441122334411223344AABBCCDD")
        } else {
            XCTFail("Expected .encrypted(signers:), got \(status)")
        }
    }

    func testParseDecryptStatus_signedOnly() {
        // GOODSIG without DECRYPTION_OKAY → signed but not encrypted
        let stderr = """
            [GNUPG:] GOODSIG AABBCCDD11223344 Bob <bob@example.com>
            [GNUPG:] VALIDSIG AABBCCDD112233441122334411223344AABBCCDD 2021-01-01 1609459200
            """
        let status = svc.parseDecryptStatus(stderr: stderr)
        if case .signed(let signers) = status {
            XCTAssertEqual(signers.count, 1)
            XCTAssertEqual(signers[0].email, "bob@example.com")
        } else {
            XCTFail("Expected .signed, got \(status)")
        }
    }

    func testParseDecryptStatus_badSig() {
        let stderr = """
            [GNUPG:] DECRYPTION_OKAY
            [GNUPG:] BADSIG AABBCCDD11223344 Eve Attacker
            """
        let status = svc.parseDecryptStatus(stderr: stderr)
        if case .signatureInvalid(let reason) = status {
            XCTAssert(reason.contains("AABBCCDD11223344"), "reason=\(reason)")
        } else {
            XCTFail("Expected .signatureInvalid, got \(status)")
        }
    }

    func testParseDecryptStatus_noPubKey() {
        let stderr = "[GNUPG:] NO_PUBKEY DEADBEEFDEADBEEF"
        let status = svc.parseDecryptStatus(stderr: stderr)
        if case .keyNotFound(let keyID) = status {
            XCTAssertEqual(keyID, "DEADBEEFDEADBEEF")
        } else {
            XCTFail("Expected .keyNotFound, got \(status)")
        }
    }

    func testParseDecryptStatus_plain() {
        let status = svc.parseDecryptStatus(stderr: "gpg: no encrypted data found")
        XCTAssertEqual(status, .plain)
    }

    // MARK: - parseVerifyStatus

    func testParseVerifyStatus_goodSig() {
        let stdout = """
            [GNUPG:] GOODSIG AABBCCDD11223344 Alice Wonderland <alice@example.com>
            [GNUPG:] VALIDSIG AABBCCDD112233441122334411223344AABBCCDD 2021-01-01 1609459200
            """
        let status = svc.parseVerifyStatus(stdout: stdout, stderr: "")
        if case .signed(let signers) = status {
            XCTAssertEqual(signers.count, 1)
            XCTAssertEqual(signers[0].email,       "alice@example.com")
            XCTAssertEqual(signers[0].keyID,       "AABBCCDD11223344")
            XCTAssertEqual(signers[0].fingerprint, "AABBCCDD112233441122334411223344AABBCCDD")
        } else {
            XCTFail("Expected .signed, got \(status)")
        }
    }

    func testParseVerifyStatus_goodSig_noEmail_fallsBackToName() {
        // GOODSIG with a plain name (no <email>) → name is used as email field
        let stdout = "[GNUPG:] GOODSIG AABBCCDD11223344 Just A Name"
        let status = svc.parseVerifyStatus(stdout: stdout, stderr: "")
        if case .signed(let signers) = status {
            XCTAssertFalse(signers[0].email.isEmpty)
        } else {
            XCTFail("Expected .signed, got \(status)")
        }
    }

    func testParseVerifyStatus_badSig() {
        let stdout = "[GNUPG:] BADSIG AABBCCDD11223344 Eve Attacker"
        let status = svc.parseVerifyStatus(stdout: stdout, stderr: "")
        if case .signatureInvalid(_) = status { /* pass */ }
        else { XCTFail("Expected .signatureInvalid, got \(status)") }
    }

    func testParseVerifyStatus_noPubKey() {
        let stdout = "[GNUPG:] NO_PUBKEY DEADBEEFDEADBEEF"
        let status = svc.parseVerifyStatus(stdout: stdout, stderr: "")
        if case .keyNotFound(let keyID) = status {
            XCTAssertEqual(keyID, "DEADBEEFDEADBEEF")
        } else {
            XCTFail("Expected .keyNotFound, got \(status)")
        }
    }

    func testParseVerifyStatus_humanReadableFallback() {
        // No [GNUPG:] status lines → falls back to checking human-readable stderr
        let status = svc.parseVerifyStatus(stdout: "", stderr: "gpg: Good signature from \"Alice\"")
        if case .signed(_) = status { /* pass */ }
        else { XCTFail("Expected .signed from stderr fallback, got \(status)") }
    }

    func testParseVerifyStatus_unknownFailure() {
        let status = svc.parseVerifyStatus(stdout: "", stderr: "gpg: something went wrong")
        if case .signatureInvalid(_) = status { /* pass */ }
        else { XCTFail("Expected .signatureInvalid for unrecognised stderr, got \(status)") }
    }

    // MARK: - extractFromEmail

    func testExtractFromEmail_angleFormat() {
        let msg = "From: Alice Wonderland <alice@example.com>\nTo: bob@example.com\n\nHello"
        XCTAssertEqual(svc.extractFromEmail(from: msg.data(using: .utf8)!), "alice@example.com")
    }

    func testExtractFromEmail_plainEmail() {
        let msg = "From: alice@example.com\nTo: bob@example.com\n\nHello"
        XCTAssertEqual(svc.extractFromEmail(from: msg.data(using: .utf8)!), "alice@example.com")
    }

    func testExtractFromEmail_noFromHeader() {
        let msg = "To: bob@example.com\n\nHello"
        XCTAssertNil(svc.extractFromEmail(from: msg.data(using: .utf8)!))
    }

    func testExtractFromEmail_caseInsensitive() {
        let msg = "FROM: alice@example.com\n\nHello"
        XCTAssertEqual(svc.extractFromEmail(from: msg.data(using: .utf8)!), "alice@example.com")
    }

    // MARK: - parseImportedFingerprint

    func testParseImportedFingerprint_valid() {
        let output = """
            [GNUPG:] IMPORT_OK 1 AABBCCDD112233441122334411223344AABBCCDD
            [GNUPG:] IMPORT_RES 1 0 1 0 0 0 0 0 0 0 0
            """
        XCTAssertEqual(
            svc.parseImportedFingerprint(from: output),
            "AABBCCDD112233441122334411223344AABBCCDD"
        )
    }

    func testParseImportedFingerprint_notFound() {
        let output = "[GNUPG:] IMPORT_RES 0 0 0 0 0 0 0 0 0 0 0"
        XCTAssertNil(svc.parseImportedFingerprint(from: output))
    }

    func testParseImportedFingerprint_multipleImports_returnsFirst() {
        let output = """
            [GNUPG:] IMPORT_OK 1 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
            [GNUPG:] IMPORT_OK 1 BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
            """
        XCTAssertEqual(
            svc.parseImportedFingerprint(from: output),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )
    }
}
