// KeyDetailView.swift
// MailGPGExtension

import SwiftUI

struct KeyDetailView: View {
    let key: KeyInfo
    /// Called after a successful deletion so the parent list can reload.
    let onDeleted: () async -> Void

    @Environment(\.dismiss) private var dismiss

    @State private var selectedTrust: TrustLevel
    @State private var isSavingTrust = false
    @State private var isLsigning = false
    @State private var isVerified: Bool
    @State private var isDeleting = false
    @State private var showDeleteConfirm = false
    @State private var errorMessage: String? = nil

    init(key: KeyInfo, onDeleted: @escaping () async -> Void) {
        self.key = key
        self.onDeleted = onDeleted
        _selectedTrust = State(initialValue: key.trustLevel)
        _isVerified = State(initialValue: key.validity == .full || key.validity == .ultimate)
    }

    var body: some View {
        List {
            Section {
                Button(action: { dismiss() }) {
                    Label("Back", systemImage: "chevron.left")
                }
            }

            Section("Identity") {
                LabeledContent("Name", value: key.name.isEmpty ? "—" : key.name)
                LabeledContent("Email", value: key.email.isEmpty ? "—" : key.email)
                LabeledContent("Key ID", value: key.keyID)
                LabeledContent("Fingerprint") {
                    Text(formattedFingerprint(key.fingerprint))
                        .font(.caption.monospaced())
                        .textSelection(.enabled)
                }
            }

            Section("Details") {
                if let expiry = key.expiresAt {
                    LabeledContent("Expires") {
                        Text(expiry.formatted(date: .long, time: .omitted))
                            .foregroundStyle(expiry < Date() ? .red : .primary)
                    }
                } else {
                    LabeledContent("Expires", value: "Never")
                }
                LabeledContent("Has Secret Key", value: key.hasSecretKey ? "Yes" : "No")
                if key.isRevoked {
                    LabeledContent("Status") {
                        Text("REVOKED").foregroundStyle(.red).bold()
                    }
                }
            }

            Section("Verification") {
                if isVerified {
                    Label("You have verified this key", systemImage: "checkmark.seal.fill")
                        .foregroundStyle(.green)
                } else {
                    Button(action: lsignKey) {
                        if isLsigning {
                            HStack {
                                ProgressView().controlSize(.small)
                                Text("Verifying…")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        } else {
                            Label("I have verified and trust this key", systemImage: "checkmark.seal")
                        }
                    }
                    .disabled(isLsigning)
                }
                Text(isVerified
                     ? "This key is locally certified. Your mail client will show it as verified."
                     : "Only verify after confirming out-of-band that the fingerprint above belongs to this person.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section("Owner Trust") {
                Picker("Owner Trust", selection: $selectedTrust) {
                    ForEach(TrustLevel.allCases, id: \.self) { level in
                        Text(level.displayName).tag(level)
                    }
                }
                .onChange(of: selectedTrust) { _, newValue in
                    saveTrust(newValue)
                }
                if isSavingTrust {
                    HStack {
                        ProgressView()
                            .controlSize(.small)
                        Text("Saving…")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                Text("Controls how much GPG trusts this key owner to certify other keys in the web of trust. This is separate from verifying the key itself.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            if let error = errorMessage {
                Section {
                    Text(error)
                        .font(.caption)
                        .foregroundStyle(.red)
                }
            }

            Section {
                Button(role: .destructive) {
                    showDeleteConfirm = true
                } label: {
                    if isDeleting {
                        HStack {
                            ProgressView().controlSize(.small)
                            Text("Deleting…")
                        }
                    } else {
                        Label("Delete Key", systemImage: "trash")
                    }
                }
                .disabled(isDeleting)
            }
        }
        .navigationTitle(key.name.isEmpty ? key.email : key.name)
        .confirmationDialog(
            "Delete Key",
            isPresented: $showDeleteConfirm,
            titleVisibility: .visible
        ) {
            Button("Delete", role: .destructive) {
                deleteKey()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(key.hasSecretKey
                 ? "This removes the public key from your keychain. To delete the associated secret key, use the terminal: gpg --delete-secret-keys \(key.fingerprint)"
                 : "This will remove the public key from your keychain.")
        }
    }

    // MARK: - Actions

    private func lsignKey() {
        isLsigning = true
        errorMessage = nil
        Task {
            do {
                try await GPGService.shared.lsignKey(fingerprint: key.fingerprint)
                isVerified = true
            } catch {
                errorMessage = "Failed to verify key: \(error.localizedDescription)"
            }
            isLsigning = false
        }
    }

    private func saveTrust(_ level: TrustLevel) {
        isSavingTrust = true
        errorMessage = nil
        Task {
            do {
                try await GPGService.shared.setTrust(fingerprint: key.fingerprint, level: level)
            } catch {
                errorMessage = "Failed to set trust: \(error.localizedDescription)"
            }
            isSavingTrust = false
        }
    }

    private func deleteKey() {
        isDeleting = true
        errorMessage = nil
        Task {
            do {
                try await GPGService.shared.deleteKey(fingerprint: key.fingerprint)
                await onDeleted()
                dismiss()
            } catch {
                errorMessage = "Failed to delete key: \(error.localizedDescription)"
                isDeleting = false
            }
        }
    }

    // MARK: - Helpers

    private func formattedFingerprint(_ fp: String) -> String {
        // Group into 4-char blocks separated by spaces, with a double space at the midpoint.
        let chars = Array(fp)
        var groups: [String] = []
        var i = 0
        while i < chars.count {
            let end = min(i + 4, chars.count)
            groups.append(String(chars[i..<end]))
            i += 4
        }
        // Insert extra space between group 5 and 6 (the midpoint).
        if groups.count >= 6 {
            let left  = groups[0..<5].joined(separator: " ")
            let right = groups[5...].joined(separator: " ")
            return left + "  " + right
        }
        return groups.joined(separator: " ")
    }
}
