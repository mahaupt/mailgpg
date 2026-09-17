// SignerSelectionTests.swift
// MailGPGTests — pins down `selectSigningKey`, the identity-aware signing key
// choice behind issue #11.

import XCTest
@testable import MailGPG

final class SignerSelectionTests: XCTestCase {

    // MARK: - Fixtures

    /// A fixed "now" so expiry assertions never depend on wall-clock time.
    let now = Date(timeIntervalSince1970: 1_700_000_000)
    var past: Date { now.addingTimeInterval(-86_400) }
    var future: Date { now.addingTimeInterval(86_400) }

    /// Builds a 40-char fingerprint out of a repeated hex nibble, so the tests read
    /// as "the A key" / "the B key" rather than as walls of hex.
    func fpr(_ nibble: String) -> String { String(repeating: nibble, count: 40) }

    func key(_ nibble: String,
             _ addresses: [String],
             expiresAt: Date? = nil,
             isRevoked: Bool = false) -> KeyInfo {
        let fp = fpr(nibble)
        return KeyInfo(fingerprint: fp,
                       keyID: String(fp.suffix(8)),
                       email: addresses.first ?? "",
                       emails: addresses.map { $0.lowercased() },
                       name: "Key \(nibble)",
                       trustLevel: .ultimate,
                       validity: .ultimate,
                       hasSecretKey: true,
                       expiresAt: expiresAt,
                       isRevoked: isRevoked)
    }

    func select(_ sender: String,
                _ keys: [KeyInfo],
                overrides: [String: String] = [:],
                defaultFingerprint: String? = nil) -> KeyInfo? {
        selectSigningKey(senderAddress: sender, from: keys,
                         overrides: overrides, defaultFingerprint: defaultFingerprint,
                         now: now)
    }

    // MARK: - Override tier

    func testOverrideWinsOverAddressMatch() {
        let rsa = key("A", ["jan@example.com"])
        let ecc = key("B", ["jan@example.com"])
        // Both match the address; the pin decides which.
        let picked = select("jan@example.com", [rsa, ecc],
                            overrides: ["jan@example.com": fpr("B")])
        XCTAssertEqual(picked?.fingerprint, fpr("B"))
    }

    func testOverrideWinsOverGlobalDefault() {
        let a = key("A", ["jan@example.com"])
        let b = key("B", ["jan@example.com"])
        let picked = select("jan@example.com", [a, b],
                            overrides: ["jan@example.com": fpr("B")],
                            defaultFingerprint: fpr("A"))
        XCTAssertEqual(picked?.fingerprint, fpr("B"))
    }

    func testOverridePointingAtExpiredKeyFallsThrough() {
        // A pin must not be able to break sending once the pinned key expires.
        let expired = key("A", ["jan@example.com"], expiresAt: past)
        let live    = key("B", ["jan@example.com"])
        let picked  = select("jan@example.com", [expired, live],
                             overrides: ["jan@example.com": fpr("A")])
        XCTAssertEqual(picked?.fingerprint, fpr("B"))
    }

    func testOverridePointingAtRevokedKeyFallsThrough() {
        let revoked = key("A", ["jan@example.com"], isRevoked: true)
        let live    = key("B", ["jan@example.com"])
        let picked  = select("jan@example.com", [revoked, live],
                             overrides: ["jan@example.com": fpr("A")])
        XCTAssertEqual(picked?.fingerprint, fpr("B"))
    }

    func testOverrideForADifferentAddressIsIgnored() {
        let a = key("A", ["jan@example.com"])
        let b = key("B", ["other@example.com"])
        let picked = select("jan@example.com", [a, b],
                            overrides: ["other@example.com": fpr("B")])
        XCTAssertEqual(picked?.fingerprint, fpr("A"))
    }

    // MARK: - Address-match tier

    func testAddressMatchBeatsKeyringOrder() {
        // The regression in issue #11: before this, whatever gpg listed first won.
        let first  = key("A", ["someone-else@example.com"])
        let mine   = key("B", ["jan@example.com"])
        XCTAssertEqual(select("jan@example.com", [first, mine])?.fingerprint, fpr("B"))
    }

    func testSecondUIDMatches() {
        // A key shared across two accounts: the From address is on its *second* UID.
        let shared = key("A", ["work@example.com", "private@example.com"])
        let other  = key("B", ["nobody@example.com"])
        XCTAssertEqual(select("private@example.com", [other, shared])?.fingerprint, fpr("A"))
    }

    func testMixedCaseSenderAndMixedCaseUIDBothMatch() {
        // `KeyInfo.emails` is lowercased by the parser; the sender address comes
        // straight from the From header and may not be.
        let k = key("A", ["Jan.Hesmert@Example.DE"])
        XCTAssertEqual(select("JAN.HESMERT@example.de", [k])?.fingerprint, fpr("A"))
    }

    func testTwoAddressMatchesDefaultBreaksTie() {
        // The reporting user's setup: RSA + ECC, both currently valid, both on the
        // same address. The global default decides.
        let rsa = key("A", ["jan@example.com"])
        let ecc = key("B", ["jan@example.com"])
        let picked = select("jan@example.com", [rsa, ecc], defaultFingerprint: fpr("B"))
        XCTAssertEqual(picked?.fingerprint, fpr("B"))
    }

    func testTwoAddressMatchesNoDefaultUsesKeyringOrder() {
        let rsa = key("A", ["jan@example.com"])
        let ecc = key("B", ["jan@example.com"])
        XCTAssertEqual(select("jan@example.com", [rsa, ecc])?.fingerprint, fpr("A"))
        XCTAssertEqual(select("jan@example.com", [ecc, rsa])?.fingerprint, fpr("B"))
    }

    func testDefaultPointingOutsideTheMatchesDoesNotHijackTheMatch() {
        // The default key belongs to a different identity — an address match on the
        // actual From address must still win over it.
        let unrelated = key("A", ["other@example.com"])
        let mine      = key("B", ["jan@example.com"])
        let picked = select("jan@example.com", [unrelated, mine],
                            defaultFingerprint: fpr("A"))
        XCTAssertEqual(picked?.fingerprint, fpr("B"))
    }

    func testExpiredMatchIsSkippedInFavourOfUsableNonMatch() {
        let expiredMatch = key("A", ["jan@example.com"], expiresAt: past)
        let usableOther  = key("B", ["other@example.com"])
        XCTAssertEqual(select("jan@example.com", [expiredMatch, usableOther])?.fingerprint,
                       fpr("B"))
    }

    func testKeyExpiringInTheFutureStillMatches() {
        let k = key("A", ["jan@example.com"], expiresAt: future)
        XCTAssertEqual(select("jan@example.com", [k])?.fingerprint, fpr("A"))
    }

    // MARK: - Fallback tiers

    func testNoAddressMatchFallsBackToGlobalDefault() {
        let a = key("A", ["a@example.com"])
        let b = key("B", ["b@example.com"])
        let picked = select("unknown@example.com", [a, b], defaultFingerprint: fpr("B"))
        XCTAssertEqual(picked?.fingerprint, fpr("B"))
    }

    func testNoMatchNoDefaultFallsBackToFirstUsableKey() {
        let expired = key("A", ["a@example.com"], expiresAt: past)
        let usable  = key("B", ["b@example.com"])
        XCTAssertEqual(select("unknown@example.com", [expired, usable])?.fingerprint,
                       fpr("B"))
    }

    func testDefaultPointingAtAnExpiredKeyIsIgnored() {
        let expiredDefault = key("A", ["a@example.com"], expiresAt: past)
        let usable         = key("B", ["b@example.com"])
        let picked = select("unknown@example.com", [expiredDefault, usable],
                            defaultFingerprint: fpr("A"))
        XCTAssertEqual(picked?.fingerprint, fpr("B"))
    }

    func testAllKeysExpiredReturnsNil() {
        let keys = [key("A", ["a@example.com"], expiresAt: past),
                    key("B", ["b@example.com"], expiresAt: past)]
        XCTAssertNil(select("a@example.com", keys))
    }

    func testAllKeysRevokedReturnsNil() {
        let keys = [key("A", ["a@example.com"], isRevoked: true)]
        XCTAssertNil(select("a@example.com", keys))
    }

    func testEmptyKeyringReturnsNil() {
        XCTAssertNil(select("a@example.com", []))
    }

    // MARK: - Wire-compat fallback

    func testKeyWithoutEmailsArrayStillMatchesOnEmail() {
        // A host app that predates multi-UID parsing sends no `emails` field.
        // `normalizedEmails` must fall back to `email` so matching still works.
        let legacy = KeyInfo(fingerprint: fpr("A"), keyID: "AAAAAAAA",
                             email: "Jan@Example.com", name: "Legacy",
                             trustLevel: .ultimate, validity: .ultimate,
                             hasSecretKey: true, expiresAt: nil, isRevoked: false)
        XCTAssertEqual(legacy.normalizedEmails, ["jan@example.com"])
        XCTAssertEqual(select("jan@example.com", [legacy])?.fingerprint, fpr("A"))
    }

    func testDecodingJSONWithoutEmailsFieldSucceeds() {
        // The actual XPC skew case: JSON produced by an older host app binary.
        let json = Data("""
            {"fingerprint":"\(fpr("A"))","keyID":"AAAAAAAA","email":"jan@example.com",
             "name":"Legacy","trustLevel":"u","validity":"u",
             "hasSecretKey":true,"isRevoked":false}
            """.utf8)
        let key = try? JSONDecoder().decode(KeyInfo.self, from: json)
        XCTAssertEqual(key?.emails, [])
        XCTAssertEqual(key?.normalizedEmails, ["jan@example.com"])
    }

    func testEmailsRoundTripsThroughJSON() {
        let original = key("A", ["work@example.com", "private@example.com"])
        let data = try! JSONEncoder().encode(original)
        let decoded = try! JSONDecoder().decode(KeyInfo.self, from: data)
        XCTAssertEqual(decoded, original)
        XCTAssertEqual(decoded.emails, ["work@example.com", "private@example.com"])
    }
}
