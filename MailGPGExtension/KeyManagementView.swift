// KeyManagementView.swift
// MailGPGExtension

import SwiftUI

struct KeyManagementView: View {
    @State private var selectedTab = 0

    var body: some View {
        TabView(selection: $selectedTab) {
            MyKeysTab()
                .tabItem { Label("My Keys", systemImage: "key.fill") }
                .tag(0)

            PublicKeysTab()
                .tabItem { Label("All Public Keys", systemImage: "person.2.fill") }
                .tag(1)
        }
        .navigationTitle("Key Management")
    }
}

// MARK: - My Keys tab (secret keys)

private struct MyKeysTab: View {
    @State private var keys: [KeyInfo] = []
    @State private var defaultFingerprint: String? = nil
    @State private var isLoading = false
    @State private var errorMessage: String? = nil

    var body: some View {
        Group {
            if isLoading {
                ProgressView("Loading keys…")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if let error = errorMessage {
                ContentUnavailableView("Error", systemImage: "exclamationmark.triangle",
                                       description: Text(error))
            } else if keys.isEmpty {
                ContentUnavailableView("No Secret Keys",
                                       systemImage: "key.slash",
                                       description: Text("No GPG secret keys found on this device."))
            } else {
                List(keys) { key in
                    SecretKeyRow(key: key,
                                 isDefault: key.fingerprint == defaultFingerprint,
                                 onSelect: { setDefault(key.fingerprint) })
                }
            }
        }
        .task { await loadKeys() }
        .refreshable { await loadKeys() }
    }

    private func loadKeys() async {
        isLoading = true
        errorMessage = nil
        do {
            keys = try await GPGService.shared.listSecretKeys()
            defaultFingerprint = await GPGService.shared.getDefaultSigningKey()
        } catch {
            errorMessage = error.localizedDescription
        }
        isLoading = false
    }

    private func setDefault(_ fingerprint: String) {
        Task {
            await GPGService.shared.setDefaultSigningKey(fingerprint)
            defaultFingerprint = fingerprint
        }
    }
}

private struct SecretKeyRow: View {
    let key: KeyInfo
    let isDefault: Bool
    let onSelect: () -> Void

    var body: some View {
        Button(action: onSelect) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(key.name.isEmpty ? key.email : key.name)
                        .font(.callout)
                        .foregroundStyle(.primary)
                    Text(key.email)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    HStack(spacing: 4) {
                        Text("ID: \(key.keyID)")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                        if let expiry = key.expiresAt {
                            Text("· Expires \(expiry.formatted(date: .abbreviated, time: .omitted))")
                                .font(.caption2)
                                .foregroundStyle(expiry < Date() ? Color.red : Color.secondary)
                        }
                        if key.isRevoked {
                            Text("· REVOKED")
                                .font(.caption2)
                                .foregroundStyle(.red)
                        }
                    }
                }
                Spacer()
                if isDefault {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundStyle(.blue)
                }
            }
        }
        .buttonStyle(.plain)
    }
}

// MARK: - All Public Keys tab

private struct PublicKeysTab: View {
    @State private var keys: [KeyInfo] = []
    @State private var isLoading = false
    @State private var errorMessage: String? = nil
    @State private var searchText = ""
    @State private var showingImport = false

    private var filteredKeys: [KeyInfo] {
        if searchText.isEmpty { return keys }
        let q = searchText.lowercased()
        return keys.filter {
            $0.email.lowercased().contains(q) ||
            $0.name.lowercased().contains(q)
        }
    }

    var body: some View {
        Group {
            if isLoading {
                ProgressView("Loading keys…")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if let error = errorMessage {
                ContentUnavailableView("Error", systemImage: "exclamationmark.triangle",
                                       description: Text(error))
            } else if filteredKeys.isEmpty {
                ContentUnavailableView.search(text: searchText)
            } else {
                List(filteredKeys) { key in
                    NavigationLink {
                        KeyDetailView(key: key, onDeleted: { await loadKeys() })
                    } label: {
                        PublicKeyRow(key: key)
                    }
                }
                .searchable(text: $searchText, prompt: "Filter by name or email")
            }
        }
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button {
                    showingImport = true
                } label: {
                    Label("Import Key", systemImage: "square.and.arrow.down")
                }
            }
        }
        .sheet(isPresented: $showingImport) {
            ImportKeyView(onImported: { await loadKeys() })
        }
        .task { await loadKeys() }
        .refreshable { await loadKeys() }
    }

    private func loadKeys() async {
        isLoading = true
        errorMessage = nil
        do {
            keys = try await GPGService.shared.listPublicKeys()
                .sorted { $0.email.lowercased() < $1.email.lowercased() }
        } catch {
            errorMessage = error.localizedDescription
        }
        isLoading = false
    }
}

private struct PublicKeyRow: View {
    let key: KeyInfo

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack {
                Text(key.name.isEmpty ? key.email : key.name)
                    .font(.callout)
                Spacer()
                TrustLevelBadge(level: key.trustLevel)
            }
            Text(key.email)
                .font(.caption)
                .foregroundStyle(.secondary)
            HStack(spacing: 4) {
                Text("ID: \(key.keyID)")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                if let expiry = key.expiresAt {
                    Text("· Expires \(expiry.formatted(date: .abbreviated, time: .omitted))")
                        .font(.caption2)
                        .foregroundStyle(expiry < Date() ? Color.red : Color.secondary)
                }
                if key.isRevoked {
                    Text("· REVOKED")
                        .font(.caption2)
                        .foregroundStyle(.red)
                }
            }
        }
    }
}

// MARK: - Trust level badge

struct TrustLevelBadge: View {
    let level: TrustLevel

    private var color: Color {
        switch level {
        case .ultimate: return .blue
        case .full:     return .green
        case .marginal: return .yellow
        case .none:     return .secondary
        case .unknown:  return .secondary
        }
    }

    var body: some View {
        Text(level.displayName)
            .font(.caption2)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(color.opacity(0.15))
            .foregroundStyle(color)
            .clipShape(Capsule())
    }
}
