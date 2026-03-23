// MailGPGApp.swift
// MailGPG

import SwiftUI

@main
struct MailGPGApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate

    var body: some Scene {
        // No windows — the host app runs headless as an XPC service.
        // All user interaction happens through the Mail extension.
        Settings { EmptyView() }
    }
}
