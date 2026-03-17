// MessageActionHandler.swift
// MailGPGExtension

import MailKit

class MessageActionHandler: NSObject, MEMessageActionHandler {

    static let shared = MessageActionHandler()

    func decideAction(for message: MEMessage, completionHandler: @escaping (MEMessageActionDecision?) -> Void) {
        // TODO: flag encrypted/signed messages (e.g. set background color)
        completionHandler(nil)
    }
}
