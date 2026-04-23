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

        let k = try XCTUnwrap(keys)
        XCTAssertEqual(k.count, 1)
        XCTAssertEqual(k[0].fingerprint, homedir.fingerprint)
        XCTAssertEqual(k[0].email, homedir.email)
        XCTAssertTrue(k[0].hasSecretKey)
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
        XCTAssertEqual(k.count, 1)
        XCTAssertEqual(k[0].fingerprint, homedir.fingerprint)
        XCTAssertFalse(k[0].isRevoked)
        // listPublicKeys passes wantSecretKeys:false — hasSecretKey must be false
        XCTAssertFalse(k[0].hasSecretKey)
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
        XCTAssertEqual(keys?.count ?? -1, 0, "Key should have been deleted")
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
