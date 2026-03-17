//
//  ContentView.swift
//  MailGPG
//
//  Created by Marcel Haupt on 17.03.26.
//

import SwiftUI

struct ContentView: View {
    var body: some View {
        VStack {
            Image(systemName: "globe")
                .imageScale(.large)
                .foregroundStyle(.tint)
            Text("Hello, world!")
            Button("GPG suchen") {
                do {
                    let path = try GPGLocator.locate()
                    let version = try GPGLocator.version(at: path)
                    print("Gefunden: \(path)")
                    print("Version: \(version)")
                } catch {
                    print("Fehler: \(error)")
                }
            }
        }
        .padding()
    }
}

#Preview {
    ContentView()
}
