// ImportKeyView.swift
// MailGPGExtension

import SwiftUI

struct ImportKeyView: View {
    /// Called after a successful import so the parent list can reload.
    let onImported: () async -> Void

    @Environment(\.dismiss) private var dismiss

    // Paste section
    @State private var armoredText = ""
    @State private var isPasting = false
    @State private var pasteResult: Result<KeyInfo, Error>? = nil

    // Search section
    @State private var searchEmail = ""
    @State private var isSearching = false
    @State private var searchResult: Result<KeyInfo?, Error>? = nil

    var body: some View {
        NavigationStack {
            Form {
                // MARK: Paste armor
                Section {
                    TextEditor(text: $armoredText)
                        .font(.caption.monospaced())
                        .frame(minHeight: 120)
                        .overlay(
                            Group {
                                if armoredText.isEmpty {
                                    Text("Paste ASCII-armored public key here…")
                                        .font(.caption)
                                        .foregroundStyle(.tertiary)
                                        .allowsHitTesting(false)
                                        .padding(4)
                                }
                            },
                            alignment: .topLeading
                        )

                    Button {
                        importPasted()
                    } label: {
                        if isPasting {
                            HStack {
                                ProgressView().controlSize(.small)
                                Text("Importing…")
                            }
                        } else {
                            Text("Import")
                        }
                    }
                    .disabled(armoredText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || isPasting)

                    if let result = pasteResult {
                        switch result {
                        case .success(let key):
                            Label("\(key.name.isEmpty ? key.email : key.name) imported", systemImage: "checkmark.circle.fill")
                                .foregroundStyle(.green)
                                .font(.caption)
                        case .failure(let error):
                            Label(error.localizedDescription, systemImage: "xmark.circle.fill")
                                .foregroundStyle(.red)
                                .font(.caption)
                        }
                    }
                } header: {
                    Text("Paste Armored Key")
                }

                // MARK: Search by email
                Section {
                    TextField("Email address", text: $searchEmail)
                        .textContentType(.emailAddress)
                        .autocorrectionDisabled()
#if os(iOS)
                        .textInputAutocapitalization(.never)
                        .keyboardType(.emailAddress)
#endif

                    Button {
                        searchForKey()
                    } label: {
                        if isSearching {
                            HStack {
                                ProgressView().controlSize(.small)
                                Text("Searching…")
                            }
                        } else {
                            Text("Search")
                        }
                    }
                    .disabled(searchEmail.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || isSearching)

                    if let result = searchResult {
                        switch result {
                        case .success(let key):
                            if let key {
                                Label("\(key.name.isEmpty ? key.email : key.name) found & imported",
                                      systemImage: "checkmark.circle.fill")
                                    .foregroundStyle(.green)
                                    .font(.caption)
                            } else {
                                Label("No key found for this email address",
                                      systemImage: "questionmark.circle")
                                    .foregroundStyle(.secondary)
                                    .font(.caption)
                            }
                        case .failure(let error):
                            Label(error.localizedDescription, systemImage: "xmark.circle.fill")
                                .foregroundStyle(.red)
                                .font(.caption)
                        }
                    }
                } header: {
                    Text("Search by Email")
                } footer: {
                    Text("Searches WKD and public keyservers. The key is automatically imported if found.")
                        .font(.caption2)
                }
            }
            .navigationTitle("Import Key")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }

    // MARK: - Actions

    private func importPasted() {
        let text = armoredText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return }
        isPasting = true
        pasteResult = nil
        Task {
            do {
                let key = try await GPGService.shared.importKey(armoredKey: text)
                pasteResult = .success(key)
                await onImported()
            } catch {
                pasteResult = .failure(error)
            }
            isPasting = false
        }
    }

    private func searchForKey() {
        let email = searchEmail.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !email.isEmpty else { return }
        isSearching = true
        searchResult = nil
        Task {
            do {
                let key = try await GPGService.shared.lookupKey(email: email)
                searchResult = .success(key)
                if key != nil { await onImported() }
            } catch {
                searchResult = .failure(error)
            }
            isSearching = false
        }
    }
}
