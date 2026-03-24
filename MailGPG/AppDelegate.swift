// AppDelegate.swift
// MailGPG (host app only)

import AppKit

class AppDelegate: NSObject, NSApplicationDelegate {

    /// Kept alive for the entire lifetime of the app.
    /// If this is deallocated, the XPC listener stops accepting connections.
    private var serviceListener: GPGServiceListener?

    func applicationDidFinishLaunching(_ notification: Notification) {
        let listener = GPGServiceListener()
        listener.start()
        serviceListener = listener

        // Start gpg-agent in the background so it is ready before the first
        // sign / decrypt operation.  Failures are non-fatal — the agent will
        // start on demand when GPG needs it; this just avoids the initial delay.
        Task.detached(priority: .background) {
            try? GPGAgent.ensureRunning()
        }
    }
}
