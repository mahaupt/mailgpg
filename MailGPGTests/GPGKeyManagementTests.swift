// GPGKeyManagementTests.swift
// MailGPGTests – integration tests for key management operations.

import XCTest
@testable import MailGPG

final class GPGKeyManagementTests: XCTestCase {

    var homedir: TempGPGHomedir!
    var svc: GPGServiceImpl!

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

    // MARK: - Semaphore helper

    /// Synchronously call a callback-based method and return its result.
    /// `block` receives a completion handler; call it to unblock and return the value.
    func wait<T>(_ block: (@escaping (T) -> Void) -> Void) -> T {
        var result: T!
        let sem = DispatchSemaphore(value: 0)
        block { value in result = value; sem.signal() }
        sem.wait()
        return result
    }

    private func assertEncodingFailed(
        _ error: Error?,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        guard let error else {
            XCTFail("Expected encodingFailed error", file: file, line: line)
            return
        }
        let nsError = error as NSError
        XCTAssertEqual(nsError.domain, GPGXPCErrorDomain, file: file, line: line)
        XCTAssertEqual(nsError.code, GPGXPCError.encodingFailed.rawValue, file: file, line: line)
    }

    // MARK: - List keys

    func testListSecretKeys() throws {
        let sem = DispatchSemaphore(value: 0)
        var keys: [KeyInfo]?
        svc.listSecretKeys { data, error in
            XCTAssertNil(error)
            keys = data.flatMap { try? xpcDecode([KeyInfo].self, from: $0) }
            sem.signal()
        }
        sem.wait()

        // The fixture holds two secret keys on one address (RSA + ECC).
        let k = try XCTUnwrap(keys)
        XCTAssertEqual(Set(k.map(\.fingerprint)),
                       [homedir.fingerprint, homedir.secondFingerprint])
        XCTAssertTrue(k.allSatisfy { $0.normalizedEmails == [homedir.email] })
        XCTAssertTrue(k.allSatisfy(\.hasSecretKey))
    }

    func testListPublicKeys() throws {
        let sem = DispatchSemaphore(value: 0)
        var keys: [KeyInfo]?
        svc.listPublicKeys { data, error in
            XCTAssertNil(error)
            keys = data.flatMap { try? xpcDecode([KeyInfo].self, from: $0) }
            sem.signal()
        }
        sem.wait()

        let k = try XCTUnwrap(keys)
        XCTAssertEqual(Set(k.map(\.fingerprint)),
                       [homedir.fingerprint, homedir.secondFingerprint])
        XCTAssertFalse(k.contains(where: \.isRevoked))
        // listPublicKeys passes wantSecretKeys:false — hasSecretKey must be false
        XCTAssertFalse(k.contains(where: \.hasSecretKey))
    }

    // MARK: - Multi-key lookup

    func testResolveKeysReturnsEveryKeyForTheAddress() throws {
        // Both fixture keys share one address — a recipient with an RSA and an ECC key.
        let keys = try svc.resolveKeys(email: homedir.email)
        XCTAssertEqual(Set(keys.map(\.fingerprint)),
                       [homedir.fingerprint, homedir.secondFingerprint],
                       "Encrypting to only one of a recipient's keys can leave them unable to read it")
    }

    func testResolveKeysFiltersSubstringMatches() throws {
        // gpg's key search matches a substring anywhere in the UID, so a search term
        // that is not a complete address still comes back with keys. Without the
        // re-filter on normalizedEmails those keys become --recipient arguments —
        // i.e. strangers silently added as recipients of an encrypted message.
        let (raw, _, code) = try homedir.run(
            ["--list-keys", "--with-colons", "--fixed-list-mode", "example.com"])
        XCTAssertEqual(code, 0)
        let matched = svc.parseColonOutput(String(data: raw, encoding: .utf8) ?? "",
                                           wantSecretKeys: false)
        XCTAssertFalse(matched.isEmpty, "Expected gpg to substring-match both fixture keys")

        XCTAssertTrue(try svc.resolveKeys(email: "example.com").isEmpty,
                      "A substring match is not an address match")
    }

    func testResolveKeysReturnsEmptyForUnknownAddress() throws {
        // No keyservers configured in the test environment, so this stays local.
        XCTAssertTrue(try svc.resolveKeys(email: "nobody@nowhere.invalid").isEmpty)
    }

    // MARK: - Import / Export

    func testImportExportedPublicKey() throws {
        let fp = homedir.fingerprint

        // Export the public key armor
        let (armorData, exportErr, exportCode) = try homedir.run(["--export", "--armor", fp])
        XCTAssertEqual(exportCode, 0, "Export failed: \(exportErr)")
        let armor = try XCTUnwrap(String(data: armorData, encoding: .utf8))
        XCTAssertTrue(armor.contains("BEGIN PGP PUBLIC KEY BLOCK"))

        // Delete the secret key first (required before deleting the public key)
        let (_, _, delSecCode) = try homedir.run(["--batch", "--yes", "--delete-secret-key", fp])
        XCTAssertEqual(delSecCode, 0, "delete-secret-key failed")
        let (_, _, delPubCode) = try homedir.run(["--batch", "--yes", "--delete-key", fp])
        XCTAssertEqual(delPubCode, 0, "delete-key failed")

        // Re-import via GPGServiceImpl
        let sem = DispatchSemaphore(value: 0)
        var imported: KeyInfo?
        svc.importKey(armoredKey: armor) { data, error in
            XCTAssertNil(error, "Import error: \(String(describing: error))")
            imported = data.flatMap { try? xpcDecode(KeyInfo.self, from: $0) }
            sem.signal()
        }
        sem.wait()

        let key = try XCTUnwrap(imported)
        XCTAssertEqual(key.fingerprint, fp)
        XCTAssertEqual(key.email, homedir.email)
        XCTAssertFalse(key.hasSecretKey, "Re-imported public-only key must not have secret key")
    }

    // MARK: - Delete

    func testDeletePublicKey() throws {
        let fp = homedir.fingerprint

        // Must delete secret key before the public key
        let (_, _, _) = try homedir.run(["--batch", "--yes", "--delete-secret-key", fp])

        let sem = DispatchSemaphore(value: 0)
        var deleteError: Error?
        svc.deleteKey(fingerprint: fp) { error in
            deleteError = error
            sem.signal()
        }
        sem.wait()
        XCTAssertNil(deleteError, "deleteKey returned error: \(String(describing: deleteError))")

        // Confirm the key is gone
        let listSem = DispatchSemaphore(value: 0)
        var keys: [KeyInfo]?
        svc.listPublicKeys { data, _ in
            keys = data.flatMap { try? xpcDecode([KeyInfo].self, from: $0) }
            listSem.signal()
        }
        listSem.wait()
        // The fixture's second key on the same address is untouched.
        XCTAssertEqual(keys?.map(\.fingerprint) ?? [], [homedir.secondFingerprint],
                       "Only the requested key should have been deleted")
    }

    func testDeleteKeyRejectsInvalidFingerprint() {
        let error = wait { done in
            svc.deleteKey(fingerprint: "DEADBEEF\nAABBCCDD112233441122334411223344AABBCCDD") { done($0) }
        }
        assertEncodingFailed(error)
    }

    // MARK: - Trust

    func testSetTrustLevel() throws {
        let fp = homedir.fingerprint

        let sem = DispatchSemaphore(value: 0)
        var setError: Error?
        svc.setTrust(fingerprint: fp, level: TrustLevel.full.rawValue) { error in
            setError = error
            sem.signal()
        }
        sem.wait()
        XCTAssertNil(setError, "setTrust returned error: \(String(describing: setError))")

        // Verify the trust level is reflected in the key listing
        let listSem = DispatchSemaphore(value: 0)
        var keys: [KeyInfo]?
        svc.listPublicKeys { data, _ in
            keys = data.flatMap { try? xpcDecode([KeyInfo].self, from: $0) }
            listSem.signal()
        }
        listSem.wait()

        let key = try XCTUnwrap(keys?.first)
        XCTAssertEqual(key.trustLevel, .full, "Trust level should be .full after setTrust")
    }

    func testSetTrustRejectsInvalidFingerprint() {
        let error = wait { done in
            svc.setTrust(fingerprint: "DEADBEEF\nAABBCCDD112233441122334411223344AABBCCDD",
                         level: TrustLevel.full.rawValue) { done($0) }
        }
        assertEncodingFailed(error)
    }

    // MARK: - Local sign (lsign)

    func testLsignKey() throws {
        let fp = homedir.fingerprint

        // lsignKey creates a local (non-exportable) signature on the key —
        // it's the mechanism users use to mark a key as "trusted for this machine".
        let (error) = wait { done in svc.lsignKey(fingerprint: fp) { done($0) } }
        XCTAssertNil(error, "lsignKey returned error: \(String(describing: error))")

        // After lsigning our own key the validity should advance to at least .full
        // (GPG considers a key valid when it has enough trusted signatures).
        let keys = wait { done in
            svc.listPublicKeys { data, _ in
                done(data.flatMap { try? xpcDecode([KeyInfo].self, from: $0) } ?? [])
            }
        }
        let key = try XCTUnwrap(keys.first)
        // A local signature by an ultimately-trusted key (our own) makes validity full.
        XCTAssertTrue(
            key.validity == .full || key.validity == .ultimate,
            "Expected validity .full or .ultimate after lsign, got \(key.validity)")
    }

    func testLsignKeyRejectsInvalidFingerprint() {
        let error = wait { done in
            svc.lsignKey(fingerprint: "--batch") { done($0) }
        }
        assertEncodingFailed(error)
    }
}
