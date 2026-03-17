// ComposeSessionHandler.swift
// MailGPGExtension

import MailKit

class ComposeSessionHandler: NSObject, MEComposeSessionHandler {

    // MARK: - Session lifecycle

    func mailComposeSessionDidBegin(_ session: MEComposeSession) {
        ComposeStateStore.shared.register(session)
    }

    func mailComposeSessionDidEnd(_ session: MEComposeSession) {
        ComposeStateStore.shared.remove(session.sessionID)
    }

    // MARK: - Recipient annotations

    func annotateAddressesForSession(_ session: MEComposeSession) async -> [MEEmailAddress: MEAddressAnnotation] {
        guard let state = ComposeStateStore.shared.state(for: session.sessionID) else { return [:] }

        var annotations: [MEEmailAddress: MEAddressAnnotation] = [:]
        var keyStatus: [String: RecipientKeyStatus] = [:]

        for address in session.mailMessage.allRecipientAddresses {
            let email = address.rawString.lowercased()
            // TODO: query GPG keychain / keyserver for the recipient's public key.
            // For now every address is marked as loading; the key lookup will update this.
            keyStatus[email] = .loading
            annotations[address] = .success(withLocalizedDescription: "Checking key…")
        }

        await MainActor.run { state.recipientKeyStatus = keyStatus }
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

        var headers: [String: [String]] = [:]
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

        if state.encryptEnabled && !state.canEncrypt {
            let error = NSError(
                domain: "com.mahaupt.mailgpg",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey:
                    "Encryption is enabled but one or more recipients are missing a public key. " +
                    "Turn off encryption or add the missing keys before sending."]
            )
            completion(error)
        } else {
            completion(nil)
        }
    }
}
