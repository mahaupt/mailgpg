// GPGServiceListener.swift
// MailGPG (host app only)

import Foundation

/// The Mach service name both sides must agree on.
/// Think of it like a port number — the extension dials this name,
/// the host app listens on it.
let GPGServiceName = "com.mahaupt.mailgpg.gpgservice"

/// Sets up and runs the XPC listener on the host-app side.
///
/// `NSXPCListener` is the server half of XPC. When the extension calls
/// `NSXPCConnection(machServiceName:)`, the OS routes that connection
/// request here. We then decide whether to accept it.
final class GPGServiceListener: NSObject, NSXPCListenerDelegate {

    private let listener: NSXPCListener

    override init() {
        listener = NSXPCListener(machServiceName: GPGServiceName)
        super.init()
        listener.delegate = self
    }

    /// Call once at app launch. The listener runs until the app quits.
    func start() {
        listener.resume()
        print("[GPGServiceListener] Listening on \(GPGServiceName)")
    }

    // MARK: - NSXPCListenerDelegate

    /// Called by XPC for every incoming connection attempt.
    /// Return `true` to accept, `false` to reject.
    func listener(
        _ listener: NSXPCListener,
        shouldAcceptNewConnection connection: NSXPCConnection
    ) -> Bool {

        // Security check: only accept connections from our own extension.
        // Without this, any app on the machine could ask us to run GPG.
        guard isConnectionFromOurExtension(connection) else {
            print("[GPGServiceListener] Rejected connection from unknown client")
            return false
        }

        // Tell XPC what protocol the remote side (extension) can call on us.
        connection.exportedInterface = NSXPCInterface(with: GPGXPCProtocol.self)

        // The object that actually handles the calls — created fresh per connection.
        connection.exportedObject = GPGServiceImpl()

        // Must call resume() or the connection stays suspended and nothing works.
        connection.resume()

        print("[GPGServiceListener] Accepted connection from extension")
        return true
    }

    // MARK: - Security validation

    private func isConnectionFromOurExtension(_ connection: NSXPCConnection) -> Bool {
        // We validate the connecting process by its code-signing identity.
        // `processIdentifier` gives us the PID; we hand that to the Security
        // framework which looks up the running process and checks its signature.
        //
        // Note: PID-based lookup has a theoretical TOCTOU race (the process
        // could be replaced between connection and validation), but this is
        // acceptable for validating our own extension on the same machine.
        let requirement = "identifier \"com.mahaupt.MailGPG.MailGPGExtension\""
        let pid = connection.processIdentifier

        var secCode: SecCode?
        let attrs = [kSecGuestAttributePid: pid] as CFDictionary

        guard SecCodeCopyGuestWithAttributes(nil, attrs, [], &secCode) == errSecSuccess,
              let code = secCode else {
            return false
        }

        var secRequirement: SecRequirement?
        guard SecRequirementCreateWithString(requirement as CFString, [], &secRequirement) == errSecSuccess,
              let req = secRequirement else {
            return false
        }

        return SecCodeCheckValidity(code, [], req) == errSecSuccess
    }
}
