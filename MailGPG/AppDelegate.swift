// AppDelegate.swift
// MailGPG (host app only)

import AppKit
import ServiceManagement

class AppDelegate: NSObject, NSApplicationDelegate {

    /// Kept alive for the entire lifetime of the app.
    /// If this is deallocated, the XPC listener stops accepting connections.
    private var serviceListener: GPGServiceListener?

    func applicationDidFinishLaunching(_ notification: Notification) {
        let listener = GPGServiceListener()
        listener.start()
        serviceListener = listener

        registerLoginItem()

        // Start gpg-agent in the background so it is ready before the first
        // sign / decrypt operation.  Failures are non-fatal — the agent will
        // start on demand when GPG needs it; this just avoids the initial delay.
        Task.detached(priority: .background) {
            try? GPGAgent.ensureRunning()
        }
    }

    // MARK: - Login item registration

    /// Registers the embedded LaunchAgent so MailGPG starts at login and the
    /// XPC Mach service is available to the extension. Shows as "MailGPG" in
    /// System Settings → General → Login Items.
    private func registerLoginItem() {
        let service = SMAppService.agent(plistName: "com.mahaupt.mailgpg.plist")
        guard service.status == .notRegistered else { return }
        do {
            try service.register()
        } catch {
            print("[AppDelegate] Failed to register login item: \(error)")
        }
    }
}
