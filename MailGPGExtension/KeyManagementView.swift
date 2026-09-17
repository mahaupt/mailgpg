// KeyManagementView.swift
// MailGPGExtension

import SwiftUI

struct KeyManagementView: View {
    @State private var selectedTab = 0

    var body: some View {
        VStack(spacing: 0) {
            Picker("Tab", selection: $selectedTab) {
                Label("My Keys", systemImage: "key.fill").tag(0)
                Label("All Public Keys", systemImage: "person.2.fill").tag(1)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .padding(.horizontal)
            .padding(.vertical, 8)

            Divider()

            if selectedTab == 0 {
                MyKeysTab()
            } else {
                PublicKeysTab()
            }
        }
        .navigationTitle("Key Management")
    }
}

// MARK: - My Keys tab (secret keys)

private struct MyKeysTab: View {
    @State private var keys: [KeyInfo] = []
    @State private var defaultFingerprint: String? = nil
    /// Bare address → pinned fingerprint. Mirrors the shared-defaults dictionary.
    @State private var overrides: [String: String] = [:]
    @State private var isLoading = false
    @State private var errorMessage: String? = nil

    /// Keys that can actually sign right now — the same filter `selectSigningKey`
    /// applies, so the picker never offers a key the send path would skip.
    private var usableKeys: [KeyInfo] {
        keys.filter { !$0.isRevoked && ($0.expiresAt.map { $0 > Date() } ?? true) }
    }

    /// Every address that appears on any usable secret key, de-duplicated and sorted.
    ///
    /// Deliberately NOT filtered to the ambiguous (more than one key) addresses:
    /// that would make the control disappear the moment one of the two keys expires,
    /// which is exactly when the user goes looking for it.
    private var signableAddresses: [String] {
        Array(Set(usableKeys.flatMap(\.normalizedEmails))).sorted()
    }

    private func keys(for address: String) -> [KeyInfo] {
        usableKeys.filter { $0.normalizedEmails.contains(address) }
    }

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
                List {
                    Section("Default Signing Key") {
                        ForEach(keys) { key in
                            SecretKeyRow(key: key,
                                         isDefault: key.fingerprint == defaultFingerprint,
                                         onSelect: { setDefault(key.fingerprint) })
                        }
                    }

                    Section {
                        ForEach(signableAddresses, id: \.self) { address in
                            Picker(address, selection: binding(for: address)) {
                                Text("Automatic").tag(String?.none)
                                ForEach(keys(for: address)) { key in
                                    Text(label(for: key)).tag(Optional(key.fingerprint))
                                }
                            }
                            .pickerStyle(.menu)
                        }
                    } header: {
                        Text("Signing Key per Address")
                    } footer: {
                        Text("“Automatic” picks the key whose User ID matches the From "
                             + "address. Pin a key when one address has more than one "
                             + "usable key (e.g. an RSA and an ECC key).")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    }
                }
            }
        }
        .task { await loadKeys() }
        .refreshable { await loadKeys() }
    }

    private func label(for key: KeyInfo) -> String {
        key.name.isEmpty ? key.keyID : "\(key.name) (\(key.keyID))"
    }

    /// The tags must be `String?` on BOTH sides — a `String` tag against a `String?`
    /// selection makes the picker silently render blank instead of failing to build.
    private func binding(for address: String) -> Binding<String?> {
        Binding(
            get: { overrides[address] },
            set: { newValue in
                if let newValue {
                    overrides[address] = newValue
                } else {
                    overrides.removeValue(forKey: address)
                }
                GPGService.shared.setSigningKeyOverride(address: address,
                                                        fingerprint: newValue)
            })
    }

    private func loadKeys() async {
        isLoading = true
        errorMessage = nil
        do {
            keys = try await GPGService.shared.listSecretKeys()
            defaultFingerprint = await GPGService.shared.getDefaultSigningKey()
            overrides = GPGService.shared.getSigningKeyOverrides()
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
                    // Show every address, not just the primary UID: a key shared
                    // across two accounts is matched on any of them.
                    Text(key.normalizedEmails.joined(separator: ", "))
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

    private var filteredKeys: [KeyInfo] {
        if searchText.isEmpty { return keys }
        let q = searchText.lowercased()
        return keys.filter {
            // Search every UID address, not just the primary one — otherwise a key
            // filed under a second address cannot be found by that address.
            $0.normalizedEmails.contains(where: { $0.contains(q) }) ||
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
            }
        }
        .searchable(text: $searchText, prompt: "Filter by name or email")
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
                TrustLevelBadge(level: key.validity)
            }
            Text(key.normalizedEmails.joined(separator: ", "))
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

/// Displays the calculated key validity (lsign / web-of-trust result).
/// Shows nothing for unknown/unverified keys to avoid cluttering the list.
struct TrustLevelBadge: View {
    let level: TrustLevel

    var showUnverified: Bool

    init(level: TrustLevel, showUnverified: Bool = false) {
        self.level = level
        self.showUnverified = showUnverified
    }

    var body: some View {
        switch level {
        case .ultimate: badge("My Key",     color: .blue)
        case .full:     badge("Verified",   color: .green)
        case .marginal: badge("Marginal",   color: .yellow)
        case .none, .unknown:
            if showUnverified { badge("Unverified", color: .secondary) } else { EmptyView() }
        }
    }

    private func badge(_ text: String, color: Color) -> some View {
        Text(text)
            .font(.caption2)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(color.opacity(0.15))
            .foregroundStyle(color)
            .clipShape(Capsule())
    }
}
