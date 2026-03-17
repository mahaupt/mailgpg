// MessageSecurityHandler.swift
// MailGPGExtension

import MailKit

class MessageSecurityHandler: NSObject, MEMessageSecurityHandler {

    static let shared = MessageSecurityHandler()

    // MARK: - Encoding (outgoing)

    func getEncodingStatus(for message: MEMessage, composeContext: MEComposeContext, completionHandler: @escaping (MEOutgoingMessageEncodingStatus) -> Void) {
        // Always report capability as available — the panel toggles control whether
        // signing/encryption actually happens in encode(_:composeContext:completionHandler:).
        completionHandler(MEOutgoingMessageEncodingStatus(canSign: true, canEncrypt: true, securityError: nil, addressesFailingEncryption: []))
    }

    func encode(_ message: MEMessage, composeContext: MEComposeContext, completionHandler: @escaping (MEMessageEncodingResult) -> Void) {
        // TODO: sign/encrypt via XPC bridge to host app
        completionHandler(MEMessageEncodingResult(encodedMessage: nil, signingError: nil, encryptionError: nil))
    }

    // MARK: - Decoding (incoming)

    func decodedMessage(forMessageData data: Data) -> MEDecodedMessage? {
        // TODO: decrypt/verify via XPC bridge to host app
        #if DEBUG
        return Self.makeDecodedMessage(data: data, status: Self.debugStatus)
        #else
        return nil
        #endif
    }

    static func makeDecodedMessage(data: Data, status: SecurityStatus) -> MEDecodedMessage? {
        let meSigners: [MEMessageSigner] = {
            switch status {
            case .signed(let signers), .encrypted(let signers):
                return signers.map {
                    MEMessageSigner(emailAddresses: [MEEmailAddress(rawString: $0.email)], signatureLabel: $0.keyID, context: nil)
                }
            default: return []
            }
        }()

        let securityInfo = MEMessageSecurityInformation(
            signers: meSigners,
            isEncrypted: { if case .encrypted = status { return true }; return false }(),
            signingError: { if case .signatureInvalid(let r) = status { return NSError(domain: "MailGPG", code: 1, userInfo: [NSLocalizedDescriptionKey: r]) }; return nil }(),
            encryptionError: { if case .decryptionFailed(let r) = status { return NSError(domain: "MailGPG", code: 2, userInfo: [NSLocalizedDescriptionKey: r]) }; return nil }()
        )

        let context = try? JSONEncoder().encode(status)
        return MEDecodedMessage(data: data, securityInformation: securityInfo, context: context)
    }

    // MARK: - UI

    func extensionViewController(signers messageSigners: [MEMessageSigner]) -> MEExtensionViewController? {
        return SecurityDetailViewController(status: Self.debugStatus)
    }

    func extensionViewController(messageContext context: Data) -> MEExtensionViewController? {
        guard let status = try? JSONDecoder().decode(SecurityStatus.self, from: context) else {
            return SecurityDetailViewController(status: .plain)
        }
        return SecurityDetailViewController(status: status)
    }

    func primaryActionClicked(forMessageContext context: Data, completionHandler: @escaping (MEExtensionViewController?) -> Void) {
        completionHandler(extensionViewController(messageContext: context))
    }

    // MARK: - Debug

    #if DEBUG
    private static let debugStatus: SecurityStatus = .signed(signers: [
        Signer(email: "alice@example.com", keyID: "AB12CD34", fingerprint: "AB12 CD34 EF56 7890 1234  5678 9ABC DEF0 1234 5678", trusted: true)
    ])
    #endif
}
