// ComposeSessionHandler.swift
// MailGPGExtension

import MailKit
import os

private let log = Logger(subsystem: "com.mahaupt.mailgpg", category: "compose")

extension MEEmailAddress {
    /// Bare email address, stripped of any RFC 2822 display name and angle brackets.
    /// e.g. "Marcel Haupt <marcel.haupt@proton.me>" → "marcel.haupt@proton.me"
    var bareAddress: String {
        let raw = rawString.trimmingCharacters(in: .whitespaces)
        if let lt = raw.firstIndex(of: "<"),
           let gt = raw.lastIndex(of: ">"), lt < gt {
            return String(raw[raw.index(after: lt)..<gt]).lowercased()
        }
        return raw.lowercased()
    }
}

class ComposeSessionHandler: NSObject, MEComposeSessionHandler {

    // MARK: - Session lifecycle

    func mailComposeSessionDidBegin(_ session: MEComposeSession) {
        log.info("compose session began")
        ComposeStateStore.shared.register(session)
    }

    func mailComposeSessionDidEnd(_ session: MEComposeSession) {
        log.info("compose session ended")
        ComposeStateStore.shared.remove(session.sessionID)
        MessageSecurityHandler.shared.uuidCache.removeAll()
    }

    // MARK: - Recipient annotations

    func annotateAddressesForSession(_ session: MEComposeSession) async -> [MEEmailAddress: MEAddressAnnotation] {
        guard let state = ComposeStateStore.shared.state(for: session.sessionID) else { return [:] }

        let addresses = session.mailMessage.allRecipientAddresses
        let shouldEncrypt = session.composeContext.shouldEncrypt
        var annotations: [MEEmailAddress: MEAddressAnnotation] = [:]
        var keyStatus: [String: RecipientKeyStatus] = [:]
        var recipientKeys: [String: KeyInfo] = [:]
        let localKeysByEmail: [String: KeyInfo]

        // Mark all as loading immediately so the UI shows spinners right away.
        for address in addresses {
            keyStatus[address.bareAddress] = .loading
            annotations[address] = .success(withLocalizedDescription: "Checking key…")
        }
        await MainActor.run { state.recipientKeyStatus = keyStatus }

        if shouldEncrypt {
            localKeysByEmail = [:]
        } else {
            do {
                localKeysByEmail = Dictionary(
                    try await GPGService.shared.listPublicKeys()
                        .filter { !$0.isRevoked && ($0.expiresAt.map { $0 > Date() } ?? true) }
                        .map { ($0.email.lowercased(), $0) },
                    uniquingKeysWith: { first, _ in first }
                )
            } catch {
                for address in addresses {
                    let email = address.bareAddress
                    keyStatus[email] = .notFound
                    annotations[address] = .warning(withLocalizedDescription: "Local key lookup failed")
                }

                await MainActor.run {
                    state.recipientKeyStatus = keyStatus
                    state.recipientKeys = [:]
                }
                return annotations
            }
        }

        // Look up each recipient's public key via XPC → GPG.
        for address in addresses {
            let email = address.bareAddress
            do {
                let key = shouldEncrypt
                    ? try await GPGService.shared.lookupKey(email: email)
                    : localKeysByEmail[email]

                if let key {
                    keyStatus[email] = .found
                    recipientKeys[email] = key
                    annotations[address] = .success(withLocalizedDescription: "Key: \(key.keyID)")
                } else {
                    keyStatus[email] = .notFound
                    let message = shouldEncrypt ? "No public key" : "No local public key"
                    annotations[address] = .warning(withLocalizedDescription: message)
                }
            } catch {
                keyStatus[email] = .notFound
                let message = shouldEncrypt ? "Key lookup failed" : "Local key lookup failed"
                annotations[address] = .warning(withLocalizedDescription: message)
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
        // X-MailGPG-SessionID lets MessageSecurityHandler.encode() look up the
        // correct ComposeSessionState even when multiple compose windows are open.
        // MEMessageSecurityHandler only receives MEMessage + MEComposeContext, with
        // no direct reference to the originating MEComposeSession — the header is
        // the only clean bridge between the two handler types.
        return [
            "X-MailGPG-SessionID": [session.sessionID.uuidString]
        ]
    }

    // MARK: - Send gate

    func allowMessageSendForSession(_ session: MEComposeSession, completion: @escaping (Error?) -> Void) {
        completion(nil)
    }
}
