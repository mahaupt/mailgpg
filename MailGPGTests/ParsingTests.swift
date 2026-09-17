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

    func testParseColonOutput_multipleUIDs_oneKeyAllAddresses() {
        // Multiple UIDs per key must produce ONE KeyInfo (id == fingerprint, so
        // duplicates would break the SwiftUI lists and double the --recipient args)
        // carrying every address. `email` stays the primary UID's address.
        let output = """
            pub:f:4096:1:AABBCCDD11223344:1600000000:::u:
            fpr:::::::::AABBCCDD112233441122334411223344AABBCCDD:
            uid:f::::1600000001::UID_HASH::Primary Name <primary@example.com>:::::::::0:
            uid:f::::1600000002::UID_HASH::Secondary Name <secondary@example.com>:::::::::0:
            """
        let keys = svc.parseColonOutput(output, wantSecretKeys: false)
        XCTAssertEqual(keys.count, 1)
        XCTAssertEqual(keys[0].email, "primary@example.com")
        XCTAssertEqual(keys[0].emails, ["primary@example.com", "secondary@example.com"])
        XCTAssertEqual(keys[0].normalizedEmails, ["primary@example.com", "secondary@example.com"])
    }

    func testParseColonOutput_uidAddressesAreLowercased() {
        let output = """
            pub:f:4096:1:AABBCCDD11223344:1600000000:::u:
            fpr:::::::::AABBCCDD112233441122334411223344AABBCCDD:
            uid:f::::1600000001::UID_HASH::Jan Hesmert <Jan.Hesmert@Example.DE>:::::::::0:
            """
        let keys = svc.parseColonOutput(output, wantSecretKeys: false)
        XCTAssertEqual(keys[0].emails, ["jan.hesmert@example.de"])
        // `email` keeps its original casing — only the match list is normalised.
        XCTAssertEqual(keys[0].email, "Jan.Hesmert@Example.DE")
    }

    func testParseColonOutput_revokedUIDExcludedFromMatching() {
        // A retired address must not win a From-header match, but the still-valid
        // UID on the same key must.
        let output = """
            pub:f:4096:1:AABBCCDD11223344:1600000000:::u:
            fpr:::::::::AABBCCDD112233441122334411223344AABBCCDD:
            uid:r::::1600000001::UID_HASH::Old Job <old@former-employer.com>:::::::::0:
            uid:f::::1600000002::UID_HASH::Current <current@example.com>:::::::::0:
            """
        let keys = svc.parseColonOutput(output, wantSecretKeys: false)
        XCTAssertEqual(keys.count, 1)
        XCTAssertEqual(keys[0].emails, ["current@example.com"])
        // The primary display address skips the revoked UID too.
        XCTAssertEqual(keys[0].email, "current@example.com")
    }

    func testParseColonOutput_expiredUIDExcluded() {
        let output = """
            pub:f:4096:1:AABBCCDD11223344:1600000000:::u:
            fpr:::::::::AABBCCDD112233441122334411223344AABBCCDD:
            uid:f::::1600000001::UID_HASH::Valid <valid@example.com>:::::::::0:
            uid:e::::1600000002::UID_HASH::Expired <expired@example.com>:::::::::0:
            """
        let keys = svc.parseColonOutput(output, wantSecretKeys: false)
        XCTAssertEqual(keys[0].emails, ["valid@example.com"])
    }

    func testParseColonOutput_duplicateUIDAddressesDeduped() {
        let output = """
            pub:f:4096:1:AABBCCDD11223344:1600000000:::u:
            fpr:::::::::AABBCCDD112233441122334411223344AABBCCDD:
            uid:f::::1600000001::UID_HASH::Work <a@example.com>:::::::::0:
            uid:f::::1600000002::UID_HASH::Home <A@Example.com>:::::::::0:
            """
        let keys = svc.parseColonOutput(output, wantSecretKeys: false)
        XCTAssertEqual(keys[0].emails, ["a@example.com"])
    }

    func testParseColonOutput_twoKeysSameAddress() {
        // The reporting user's setup: one RSA and one ECC key on the same address.
        // The block boundary is the *next* pub record, not the first uid.
        let output = """
            pub:f:4096:1:AAAA000000000000:1600000000:::u:
            fpr:::::::::AAAA0000000000000000000000000000AAAA0000:
            uid:f::::1600000001::UID_HASH::Jan RSA <jan@example.com>:::::::::0:
            sub:f:4096:1:1111111111111111:1600000000::::::e:
            pub:f:255:22:BBBB000000000000:1600000000:::u:
            fpr:::::::::BBBB0000000000000000000000000000BBBB0000:
            uid:f::::1600000001::UID_HASH::Jan ECC <jan@example.com>:::::::::0:
            sub:f:255:18:2222222222222222:1600000000::::::e:
            """
        let keys = svc.parseColonOutput(output, wantSecretKeys: false)
        XCTAssertEqual(keys.count, 2)
        XCTAssertEqual(keys[0].fingerprint, "AAAA0000000000000000000000000000AAAA0000")
        XCTAssertEqual(keys[1].fingerprint, "BBBB0000000000000000000000000000BBBB0000")
        XCTAssertEqual(keys.map(\.emails), [["jan@example.com"], ["jan@example.com"]])
    }

    func testParseColonOutput_subkeyRegionDoesNotLeakUIDs() {
        // Nothing after a sub/ssb record may be attributed to the primary key.
        let output = """
            sec:u:4096:1:AABBCCDD11223344:1600000000:::u:
            fpr:::::::::AABBCCDD112233441122334411223344AABBCCDD:
            uid:u::::1600000001::UID_HASH::Real <real@example.com>:::::::::0:
            ssb:u:4096:1:DEADBEEFDEADBEEF:1600000000::::::e:
            uid:u::::1600000002::UID_HASH::Bogus <bogus@example.com>:::::::::0:
            """
        let keys = svc.parseColonOutput(output, wantSecretKeys: true)
        XCTAssertEqual(keys.count, 1)
        XCTAssertEqual(keys[0].emails, ["real@example.com"])
    }

    func testParseColonOutput_fullyRevokedKeyStillReported() {
        // Regression guard: skipping revoked UIDs must not make a revoked key vanish
        // — the UI needs it in order to show the REVOKED badge.
        let output = """
            pub:r:4096:1:AABBCCDD11223344:1600000000:::u:
            fpr:::::::::AABBCCDD112233441122334411223344AABBCCDD:
            uid:r::::1600000001::UID_HASH::Dave Revoked <dave@example.com>:::::::::0:
            """
        let keys = svc.parseColonOutput(output, wantSecretKeys: false)
        XCTAssertEqual(keys.count, 1)
        XCTAssertTrue(keys[0].isRevoked)
        XCTAssertEqual(keys[0].email, "dave@example.com")
        XCTAssertTrue(keys[0].emails.isEmpty, "A revoked UID is not a matchable address")
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
        if case .encrypted(let signers, _) = status {
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
        if case .encrypted(let signers, _) = status {
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

    // MARK: - parseDecryptStatus: decryption diagnostics

    func testParseDecryptStatus_carriesEncToAndDecryptionKey() {
        // ENC_TO names every key the message was encrypted to, DECRYPTION_KEY the one
        // of ours that opened it — together they answer "why did THIS one work".
        let stderr = """
            [GNUPG:] ENC_TO AAAA111111111111 1 0
            [GNUPG:] ENC_TO BBBB222222222222 18 0
            [GNUPG:] DECRYPTION_KEY BBBB2222222222222222222222222222BBBB2222 BBBB2222222222222222222222222222BBBB2222 u
            [GNUPG:] DECRYPTION_OKAY
            """
        guard case .encrypted(_, let details) = svc.parseDecryptStatus(stderr: stderr) else {
            return XCTFail("Expected .encrypted")
        }
        XCTAssertEqual(details.encryptedToKeyIDs, ["AAAA111111111111", "BBBB222222222222"])
        XCTAssertEqual(details.decryptionKeyFingerprint,
                       "BBBB2222222222222222222222222222BBBB2222")
        XCTAssertTrue(details.missingSecretKeyIDs.isEmpty)
    }

    func testParseDecryptStatus_noSecKeyIsADecryptionFailure() {
        // The RSA+ECC case: encrypted to the one key we don't hold.
        let stderr = """
            [GNUPG:] ENC_TO DEADBEEFDEADBEEF 1 0
            [GNUPG:] NO_SECKEY DEADBEEFDEADBEEF
            gpg: decryption failed: No secret key
            """
        guard case .decryptionFailed(let reason, let details) = svc.parseDecryptStatus(stderr: stderr) else {
            return XCTFail("Expected .decryptionFailed, got \(svc.parseDecryptStatus(stderr: stderr))")
        }
        XCTAssertEqual(details.missingSecretKeyIDs, ["DEADBEEFDEADBEEF"])
        XCTAssertEqual(details.encryptedToKeyIDs, ["DEADBEEFDEADBEEF"])
        XCTAssertTrue(reason.contains("DEADBEEFDEADBEEF"),
                      "The reason must name the key ID: \(reason)")
    }

    func testParseDecryptStatus_noSecKeyForOneOfTwoKeysStillDecrypts() {
        // Encrypted to both our keys but only one secret key is present: gpg reports
        // NO_SECKEY for the other and still succeeds. That is NOT a failure.
        let stderr = """
            [GNUPG:] ENC_TO AAAA111111111111 1 0
            [GNUPG:] ENC_TO BBBB222222222222 18 0
            [GNUPG:] NO_SECKEY AAAA111111111111
            [GNUPG:] DECRYPTION_KEY BBBB2222222222222222222222222222BBBB2222 BBBB2222222222222222222222222222BBBB2222 u
            [GNUPG:] DECRYPTION_OKAY
            """
        guard case .encrypted(_, let details) = svc.parseDecryptStatus(stderr: stderr) else {
            return XCTFail("Expected .encrypted")
        }
        XCTAssertEqual(details.missingSecretKeyIDs, ["AAAA111111111111"])
        XCTAssertEqual(details.decryptionKeyFingerprint,
                       "BBBB2222222222222222222222222222BBBB2222")
    }

    func testParseDecryptStatus_decryptionFailedAlongsideOkayIsAFailure() {
        // MDC / integrity failure: gpg emits BOTH and still writes plaintext to
        // stdout. Treating OKAY as authoritative returned tampered plaintext as a
        // good decrypt.
        let stderr = """
            [GNUPG:] ENC_TO AAAA111111111111 1 0
            [GNUPG:] DECRYPTION_OKAY
            gpg: WARNING: message was not integrity protected
            [GNUPG:] DECRYPTION_FAILED
            """
        guard case .decryptionFailed(_, let details) = svc.parseDecryptStatus(stderr: stderr) else {
            return XCTFail("Expected .decryptionFailed")
        }
        XCTAssertEqual(details.encryptedToKeyIDs, ["AAAA111111111111"])
    }

    func testParseDecryptStatus_decryptionFailureOutranksSignatureVerdict() {
        // Without plaintext there is nothing for a signature verdict to be about.
        let stderr = """
            [GNUPG:] ENC_TO DEADBEEFDEADBEEF 1 0
            [GNUPG:] NO_SECKEY DEADBEEFDEADBEEF
            [GNUPG:] NO_PUBKEY CAFEBABECAFEBABE
            """
        guard case .decryptionFailed = svc.parseDecryptStatus(stderr: stderr) else {
            return XCTFail("Expected .decryptionFailed to win over .keyNotFound")
        }
    }

    // MARK: - SecurityStatus wire compatibility

    func testSecurityStatusRoundTripsWithDetails() {
        let details = DecryptionDetails(encryptedToKeyIDs: ["AAAA1111", "BBBB2222"],
                                        decryptionKeyFingerprint: "CCCC3333",
                                        missingSecretKeyIDs: ["AAAA1111"])
        for status: SecurityStatus in [
            .encrypted(signers: [], details: details),
            .signed(signers: [Signer(email: "a@b.c", keyID: "K", fingerprint: "F", trustLevel: .full)]),
            .signatureInvalid(reason: "bad"),
            .decryptionFailed(reason: "nope", details: details),
            .keyNotFound(keyID: "DEAD"),
            .plain,
        ] {
            let data = try! JSONEncoder().encode(status)
            XCTAssertEqual(try! JSONDecoder().decode(SecurityStatus.self, from: data), status)
        }
    }

    func testSecurityStatusDecodesPayloadWithoutDetails() {
        // JSON from a host app built before DecryptionDetails existed. The synthesized
        // decoder would reject this, which is why SecurityStatus hand-rolls Codable.
        let json = Data(#"{"encrypted":{"signers":[]}}"#.utf8)
        XCTAssertEqual(try? JSONDecoder().decode(SecurityStatus.self, from: json),
                       .encrypted(signers: [], details: DecryptionDetails()))
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

    // MARK: - sniffPGPContent / PGP "partitioned" mail (gpg4o, PGP Desktop)

    private static let fakeArmor = """
        -----BEGIN PGP MESSAGE-----
        Comment: Using gpg4o v6.0.124.9651

        hF4D6SBd26gA4IgSAQdALaMhy+ZjYJ4dGKhVnBCNlLnktjxHoplXEt4PAnlDVicw
        wcDMA1x2yr2CjS4cAQwAiKgtcMdMCUBVyDCcYYb2AbBUnLPGZXY0AJq0R59nZBkr
        =NhIh
        -----END PGP MESSAGE-----
        """

    /// A redacted copy of the structure gpg4o (Outlook) produces: NOT RFC 3156 —
    /// a plain multipart/mixed whose text part is the ASCII armor hidden under
    /// Content-Transfer-Encoding: base64, plus an encrypted-HTML attachment.
    private static func partitionedMessage(armor: String = fakeArmor) -> Data {
        let armorB64 = Data(armor.utf8)
            .base64EncodedString(options: [.lineLength76Characters, .endLineWithCarriageReturn])
        let message = """
            From: sender@example.com\r
            To: recipient@example.com\r
            Subject: Abstimmung Termine\r
            Message-ID: <redacted@example.com>\r
            Content-Type: multipart/mixed; boundary="_002_boundary_"\r
            MIME-Version: 1.0\r
            \r
            --_002_boundary_\r
            Content-Type: text/plain; charset=UTF-8\r
            Content-Transfer-Encoding: base64\r
            \r
            \(armorB64)\r
            \r
            --_002_boundary_\r
            Content-Type: application/octet-stream; name="PGPexch.htm.pgp"\r
            Content-Disposition: attachment; filename="PGPexch.htm.pgp"\r
            Content-Transfer-Encoding: base64\r
            \r
            \(armorB64)\r
            \r
            --_002_boundary_--\r
            """
        return Data(message.utf8)
    }

    private func lowercasedHeaderBlock(of data: Data) -> String {
        let (headers, _) = svc.splitMessage(data)
        return headers.lowercased()
    }

    func testSniff_partitionedBase64Armor_detectedAsEncrypted() {
        let data = Self.partitionedMessage()
        let sniff = sniffPGPContent(lowercasedHeaderBlock: lowercasedHeaderBlock(of: data),
                                    rawMessage: data)
        XCTAssertTrue(sniff.isInlinePGP, "base64-encoded armor must sniff as inline PGP")
        XCTAssertTrue(sniff.isEncrypted)
        XCTAssertFalse(sniff.isMIMEEncrypted, "partitioned mail is multipart/mixed, not RFC 3156")
        XCTAssertFalse(sniff.isSigned)
    }

    func testSniff_literalInlineArmor_detectedAsEncrypted() {
        let data = Data("""
            From: sender@example.com\r
            Content-Type: text/plain\r
            \r
            \(Self.fakeArmor)\r
            """.utf8)
        let sniff = sniffPGPContent(lowercasedHeaderBlock: lowercasedHeaderBlock(of: data),
                                    rawMessage: data)
        XCTAssertTrue(sniff.isInlinePGP)
        XCTAssertTrue(sniff.isEncrypted)
    }

    func testSniff_rfc3156_detectedAsMIMEEncrypted() {
        let armored = Data(Self.fakeArmor.utf8)
        let data = svc.buildEncryptedMessage(
            original: Data("From: a@b.c\nSubject: x\nContent-Type: text/plain\n\nhello".utf8),
            encrypted: armored)
        let sniff = sniffPGPContent(lowercasedHeaderBlock: lowercasedHeaderBlock(of: data),
                                    rawMessage: data)
        XCTAssertTrue(sniff.isMIMEEncrypted)
        XCTAssertTrue(sniff.isEncrypted)
    }

    func testSniff_plainMail_notDetected() {
        let data = Data("""
            From: sender@example.com\r
            Content-Type: text/plain\r
            \r
            Just a normal message. Nothing to see here.\r
            """.utf8)
        let sniff = sniffPGPContent(lowercasedHeaderBlock: lowercasedHeaderBlock(of: data),
                                    rawMessage: data)
        XCTAssertFalse(sniff.isEncrypted)
        XCTAssertFalse(sniff.isSigned)
    }

    // MARK: - Transient decryption failures (agent died / pinentry dismissed)

    func testParseDecryptStatus_pinentryCancelledIsTransient() {
        // 0x05000063 = source gpg-agent, code 99 (GPG_ERR_CANCELED)
        let stderr = """
            [GNUPG:] ENC_TO AABBCCDD11223344 1 0
            [GNUPG:] ERROR pkdecrypt_failed 83886179
            [GNUPG:] DECRYPTION_FAILED
            [GNUPG:] FAILURE decrypt 83886179
            """
        guard case .decryptionFailed(_, let details) = svc.parseDecryptStatus(stderr: stderr) else {
            return XCTFail("expected .decryptionFailed")
        }
        XCTAssertEqual(details.transient, true)
    }

    func testParseDecryptStatus_agentEOFIsTransient() {
        // 0x0500_3FFF = source gpg-agent, code 16383 (GPG_ERR_EOF): agent killed mid-op
        let stderr = """
            [GNUPG:] ENC_TO AABBCCDD11223344 1 0
            [GNUPG:] DECRYPTION_FAILED
            [GNUPG:] FAILURE decrypt \(UInt32(5 << 24 | 16383))
            """
        guard case .decryptionFailed(_, let details) = svc.parseDecryptStatus(stderr: stderr) else {
            return XCTFail("expected .decryptionFailed")
        }
        XCTAssertEqual(details.transient, true)
    }

    func testParseDecryptStatus_missingSecretKeyIsNotTransient() {
        let stderr = """
            [GNUPG:] ENC_TO AABBCCDD11223344 1 0
            [GNUPG:] NO_SECKEY AABBCCDD11223344
            [GNUPG:] DECRYPTION_FAILED
            [GNUPG:] FAILURE decrypt \(UInt32(5 << 24 | 17))
            """
        guard case .decryptionFailed(_, let details) = svc.parseDecryptStatus(stderr: stderr) else {
            return XCTFail("expected .decryptionFailed")
        }
        XCTAssertNotEqual(details.transient, true)
        XCTAssertEqual(details.missingSecretKeyIDs, ["AABBCCDD11223344"])
    }

    func testParseDecryptStatus_failureWithoutCodeIsNotTransient() {
        let stderr = "[GNUPG:] DECRYPTION_FAILED"
        guard case .decryptionFailed(_, let details) = svc.parseDecryptStatus(stderr: stderr) else {
            return XCTFail("expected .decryptionFailed")
        }
        XCTAssertNotEqual(details.transient, true)
    }

    func testDecryptionDetails_transientRoundTripsAndDefaultsNil() throws {
        // Wire compatibility: payloads from a host app without the field decode
        // to nil; payloads with it round-trip.
        let old = try JSONDecoder().decode(DecryptionDetails.self,
            from: Data(#"{"encryptedToKeyIDs":["AA"]}"#.utf8))
        XCTAssertNil(old.transient)

        let details = DecryptionDetails(encryptedToKeyIDs: ["AA"], transient: true)
        let decoded = try JSONDecoder().decode(DecryptionDetails.self,
            from: JSONEncoder().encode(details))
        XCTAssertEqual(decoded.transient, true)
    }

    func testExtractPGPPayload_partitionedBase64Armor_returnsArmor() {
        let payload = svc.extractPGPPayload(from: Self.partitionedMessage())
        let str = String(data: payload, encoding: .utf8) ?? ""
        XCTAssertTrue(str.hasPrefix("-----BEGIN PGP MESSAGE-----"),
                      "extraction must decode the base64 CTE and return the armor")
        XCTAssertTrue(str.hasSuffix("-----END PGP MESSAGE-----"))
    }
}
