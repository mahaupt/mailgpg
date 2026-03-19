//
//  MailGPGApp.swift
//  MailGPG
//
//  Created by Marcel Haupt on 17.03.26.
//

import SwiftUI

@main
struct MailGPGApp: App {
    // Connects our AppDelegate to the SwiftUI lifecycle.
    // SwiftUI still owns the app loop; AppDelegate gets the launch callback.
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate

    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
