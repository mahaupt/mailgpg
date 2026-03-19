// ComposeSessionHandler.swift
// MailGPGExtension

import MailKit
import os

private let log = Logger(subsystem: "com.mahaupt.mailgpg", category: "compose")

class ComposeSessionHandler: NSObject, MEComposeSessionHandler {

    // MARK: - Session lifecycle

    func mailComposeSessionDidBegin(_ session: MEComposeSession) {
        log.info("session began: \(session.sessionID)")
        ComposeStateStore.shared.register(session)
    }

    func mailComposeSessionDidEnd(_ session: MEComposeSession) {
        log.info("session ended: \(session.sessionID)")
        ComposeStateStore.shared.remove(session.sessionID)
    }

    // MARK: - Recipient annotations

    func annotateAddressesForSession(_ session: MEComposeSession) async -> [MEEmailAddress: MEAddressAnnotation] {
        guard let state = ComposeStateStore.shared.state(for: session.sessionID) else { return [:] }

        let addresses = session.mailMessage.allRecipientAddresses
        var annotations: [MEEmailAddress: MEAddressAnnotation] = [:]
        var keyStatus: [String: RecipientKeyStatus] = [:]
        var recipientKeys: [String: KeyInfo] = [:]

        // Mark all as loading immediately so the UI shows spinners right away.
        for address in addresses {
            keyStatus[address.rawString.lowercased()] = .loading
            annotations[address] = .success(withLocalizedDescription: "Checking key…")
        }
        await MainActor.run { state.recipientKeyStatus = keyStatus }

        // Look up each recipient's public key via XPC → GPG.
        // lookupKey first checks the local keyring; Step 6 will add keyserver fallback.
        for address in addresses {
            let email = address.rawString.lowercased()
            do {
                if let key = try await GPGService.shared.lookupKey(email: email) {
                    keyStatus[email] = .found
                    recipientKeys[email] = key
                    annotations[address] = .success(withLocalizedDescription: "Key: \(key.keyID)")
                } else {
                    keyStatus[email] = .notFound
                    annotations[address] = .warning(withLocalizedDescription: "No public key")
                }
            } catch {
                keyStatus[email] = .notFound
                annotations[address] = .warning(withLocalizedDescription: "Key lookup failed")
            }
        }

        await MainActor.run {
            state.recipientKeyStatus = keyStatus
            state.recipientKeys = recipientKeys
        }
        return annotations
    }

    // MARK: - View controller

    func viewController(for session: MEComposeSession) -> MEExtensionViewController {
        let state = ComposeStateStore.shared.state(for: session.sessionID) ?? ComposeStateStore.shared.register(session)
        return ComposeSessionViewController(state: state)
    }

    // MARK: - Headers

    func additionalHeaders(for session: MEComposeSession) -> [String: [String]] {
        guard let state = ComposeStateStore.shared.state(for: session.sessionID) else { return [:] }

        // X-MailGPG-SessionID lets MessageSecurityHandler.encode() look up the
        // correct ComposeSessionState even when multiple compose windows are open.
        // MEMessageSecurityHandler only receives MEMessage + MEComposeContext, with
        // no direct reference to the originating MEComposeSession — the header is
        // the only clean bridge between the two handler types.
        var headers: [String: [String]] = [
            "X-MailGPG-SessionID": [session.sessionID.uuidString]
        ]
        if state.signEnabled    { headers["X-MailGPG-Sign"]    = ["1"] }
        if state.encryptEnabled { headers["X-MailGPG-Encrypt"] = ["1"] }
        return headers
    }

    // MARK: - Send gate

    func allowMessageSendForSession(_ session: MEComposeSession, completion: @escaping (Error?) -> Void) {
        guard let state = ComposeStateStore.shared.state(for: session.sessionID) else {
            completion(nil)
            return
        }

        // Block if encryption is requested but keys are missing for some recipients.
        if state.encryptEnabled && !state.canEncrypt {
            completion(NSError(
                domain: "com.mahaupt.mailgpg", code: 1,
                userInfo: [NSLocalizedDescriptionKey:
                    "Encryption is enabled but one or more recipients are missing a public key. " +
                    "Turn off encryption or add the missing keys before sending."]))
            return
        }

        // When signing is enabled, verify that at least one secret key is available.
        // This catches "no key" early and surfaces the error before encode is called,
        // preventing Mail from silently sending an unsigned message on failure.
        guard state.signEnabled else {
            log.debug("allowMessageSend: sign disabled, allowing send")
            completion(nil)
            return
        }

        log.debug("allowMessageSend: sign enabled, checking secret keys via XPC…")
        Task {
            do {
                let keys = try await GPGService.shared.listSecretKeys()
                log.info("allowMessageSend: found \(keys.count) secret key(s)")
                if keys.isEmpty {
                    log.error("allowMessageSend: blocking send — no secret keys found")
                    completion(NSError(
                        domain: "com.mahaupt.mailgpg", code: 2,
                        userInfo: [NSLocalizedDescriptionKey:
                            "Signing is enabled but no GPG secret key was found. " +
                            "Import or create a key, or turn off signing."]))
                } else {
                    log.debug("allowMessageSend: keys OK, allowing send")
                    completion(nil)
                }
            } catch {
                // Can't reach host app or GPG — let encode report the error.
                log.error("allowMessageSend: XPC error checking keys — \(error.localizedDescription) — allowing send anyway")
                completion(nil)
            }
        }
    }
}
