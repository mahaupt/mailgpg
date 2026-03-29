// KeyserverSettingsView.swift
// MailGPGExtension

import SwiftUI

struct KeyserverSettingsView: View {
    @Environment(\.dismiss) private var dismiss

    @State private var servers: [String] = []
    @State private var newURL = ""
    @State private var addError: String?

    var body: some View {
        List {
            Section {
                Button(action: { dismiss() }) {
                    Label("Back", systemImage: "chevron.left")
                }
            }

            Section {
                ForEach(servers, id: \.self) { server in
                    HStack(alignment: .top, spacing: 8) {
                        Text(server)
                            .font(.system(.body, design: .monospaced))
                            .frame(maxWidth: .infinity, alignment: .leading)
                        HStack(spacing: 2) {
                            Button {
                                move(server: server, up: true)
                            } label: {
                                Image(systemName: "chevron.up")
                                    .imageScale(.small)
                            }
                            .disabled(servers.first == server)
                            Button {
                                move(server: server, up: false)
                            } label: {
                                Image(systemName: "chevron.down")
                                    .imageScale(.small)
                            }
                            .disabled(servers.last == server)
                            Button(role: .destructive) {
                                remove(server: server)
                            } label: {
                                Image(systemName: "trash")
                                    .imageScale(.small)
                            }
                        }
                        .buttonStyle(.borderless)
                    }
                }
                Text("Keyservers are tried in order. Use the trash icon to remove one.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } header: {
                Text("Keyservers")
            }

            Section {
                TextField("hkps://keys.example.com", text: $newURL)
                    .font(.system(.body, design: .monospaced))
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: .infinity)
                    .autocorrectionDisabled()
                    .onChange(of: newURL) { _, _ in addError = nil }
                if let addError {
                    Text(addError)
                        .font(.caption)
                        .foregroundStyle(.red)
                }
                Button("Add") {
                    addServer()
                }
                Text("Use hkps:// for encrypted or hkp:// for unencrypted connections.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } header: {
                Text("Add Keyserver")
            }

            Section {
                Button("Reset to Defaults", role: .destructive) {
                    servers = GPGService.defaultKeyservers
                    save()
                }
            }
        }
        .navigationTitle("Keyservers")
        .onAppear {
            servers = GPGService.shared.getKeyservers()
        }
    }

    private func addServer() {
        let trimmed = newURL.trimmingCharacters(in: .whitespaces)
        guard trimmed.hasPrefix("hkps://") || trimmed.hasPrefix("hkp://") else {
            addError = "URL must start with hkps:// or hkp://"
            return
        }
        let schemeLength = trimmed.hasPrefix("hkps://") ? 7 : 6
        guard trimmed.count > schemeLength else {
            addError = "Please enter a valid keyserver hostname."
            return
        }
        guard !servers.contains(trimmed) else {
            addError = "This keyserver is already in the list."
            return
        }
        servers.append(trimmed)
        save()
        newURL = ""
        addError = nil
    }

    private func move(server: String, up: Bool) {
        guard let idx = servers.firstIndex(of: server) else { return }
        let dest = up ? idx - 1 : idx + 1
        guard dest >= 0, dest < servers.count else { return }
        servers.swapAt(idx, dest)
        save()
    }

    private func remove(server: String) {
        servers.removeAll { $0 == server }
        save()
    }

    private func save() {
        GPGService.shared.setKeyservers(servers)
    }
}
