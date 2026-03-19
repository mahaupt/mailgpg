// ComposeSecurityView.swift
// MailGPGExtension

import Combine
import MailKit
import SwiftUI

// MARK: - Shared store

/// Singleton that owns all per-session states so both ComposeSessionHandler
/// and MessageSecurityHandler can read the same sign/encrypt toggles.
final class ComposeStateStore {
    static let shared = ComposeStateStore()

    private var states: [UUID: ComposeSessionState] = [:]

    @discardableResult
    func register(_ session: MEComposeSession) -> ComposeSessionState {
        let state = ComposeSessionState()
        states[session.sessionID] = state
        return state
    }

    func state(for sessionID: UUID) -> ComposeSessionState? {
        states[sessionID]
    }

    func remove(_ sessionID: UUID) {
        states.removeValue(forKey: sessionID)
    }

    /// Best-effort: returns the state for the only active session, or nil if ambiguous.
    var singleActiveState: ComposeSessionState? {
        states.count == 1 ? states.values.first : nil
    }
}

// MARK: - Shared state

/// Observable state shared between ComposeSessionHandler and ComposeSecurityView.
/// One instance is created per compose session.
final class ComposeSessionState: ObservableObject {
    /// Whether the outgoing message should be signed with the user's private key.
    @Published var signEnabled: Bool = true
    /// Whether the outgoing message should be encrypted.
    @Published var encryptEnabled: Bool = false
    /// Per-recipient key availability. Keyed by email address (lowercased).
    @Published var recipientKeyStatus: [String: RecipientKeyStatus] = [:]
    /// The `KeyInfo` for each recipient that has a key. Keyed by email address (lowercased).
    /// Used by `MessageSecurityHandler` to get fingerprints for encryption.
    @Published var recipientKeys: [String: KeyInfo] = [:]

    /// Encryption is only possible when every recipient has a known public key.
    var canEncrypt: Bool {
        !recipientKeyStatus.isEmpty &&
        recipientKeyStatus.values.allSatisfy { $0 == .found }
    }
}

enum RecipientKeyStatus: Equatable {
    case found
    case notFound
    case loading
}

// MARK: - View

struct ComposeSecurityView: View {
    @ObservedObject var state: ComposeSessionState

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("OpenPGP")
                .font(.headline)

            Divider()

            // Sign toggle
            HStack(spacing: 10) {
                Image(systemName: "signature")
                    .foregroundStyle(.blue)
                    .frame(width: 20, alignment: .center)
                VStack(alignment: .leading, spacing: 1) {
                    Text("Sign message")
                        .font(.callout)
                    Text("Proves the message comes from you.")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Toggle("", isOn: $state.signEnabled)
                    .toggleStyle(.switch)
                    .labelsHidden()
            }

            // Encrypt toggle
            HStack(spacing: 10) {
                Image(systemName: state.encryptEnabled ? "lock.fill" : "lock.open")
                    .foregroundStyle(state.canEncrypt ? .green : .secondary)
                    .frame(width: 20, alignment: .center)
                VStack(alignment: .leading, spacing: 1) {
                    Text("Encrypt message")
                        .font(.callout)
                    if !state.canEncrypt && !state.recipientKeyStatus.isEmpty {
                        Text("Some recipients are missing a public key.")
                            .font(.caption2)
                            .foregroundStyle(.orange)
                    } else {
                        Text("Only recipients can read the content.")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                }
                Spacer()
                Toggle("", isOn: encryptBinding)
                    .toggleStyle(.switch)
                    .labelsHidden()
                    .disabled(!state.canEncrypt)
            }

            // Recipient key status list
            if !state.recipientKeyStatus.isEmpty {
                Divider()

                VStack(alignment: .leading, spacing: 6) {
                    Text("Recipients")
                        .font(.caption)
                        .foregroundStyle(.secondary)

                    ForEach(
                        state.recipientKeyStatus.sorted(by: { $0.key < $1.key }),
                        id: \.key
                    ) { email, keyStatus in
                        RecipientRow(email: email, status: keyStatus)
                    }
                }
            }
        }
        .padding()
        .frame(minWidth: 280)
        // If encrypt was enabled but keys disappear, turn it off automatically
        .onChange(of: state.canEncrypt) { _, canEncrypt in
            if !canEncrypt { state.encryptEnabled = false }
        }
        .safeAreaInset(edge: .bottom) {
            XPCPingRow()
        }
    }

    /// Wraps the encrypt toggle so flipping it on when canEncrypt is false is a no-op.
    private var encryptBinding: Binding<Bool> {
        Binding(
            get: { state.encryptEnabled },
            set: { newValue in
                if newValue && !state.canEncrypt { return }
                state.encryptEnabled = newValue
            }
        )
    }
}

// MARK: - Subviews

private struct RecipientRow: View {
    let email: String
    let status: RecipientKeyStatus

    var body: some View {
        HStack(spacing: 6) {
            icon
            Text(email)
                .font(.caption)
                .textSelection(.enabled)
                .lineLimit(1)
            Spacer()
            statusLabel
        }
    }

    @ViewBuilder
    private var icon: some View {
        switch status {
        case .found:
            Image(systemName: "key.fill")
                .font(.caption)
                .foregroundStyle(.green)
        case .notFound:
            Image(systemName: "key.slash")
                .font(.caption)
                .foregroundStyle(.orange)
        case .loading:
            ProgressView()
                .controlSize(.mini)
        }
    }

    @ViewBuilder
    private var statusLabel: some View {
        switch status {
        case .found:
            Text("Key found")
                .font(.caption2)
                .foregroundStyle(.green)
        case .notFound:
            Text("No key")
                .font(.caption2)
                .foregroundStyle(.orange)
        case .loading:
            Text("Looking up…")
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
    }
}

// MARK: - XPC ping row

/// Debug row shown at the bottom of the compose panel.
/// Tapping "Ping" sends a round-trip XPC call to the host app and
/// displays the GPG version it found, confirming the bridge works.
private struct XPCPingRow: View {
    @State private var result = "–"
    @State private var pinging = false

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: "antenna.radiowaves.left.and.right")
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(result)
                .font(.caption2)
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .truncationMode(.tail)
            Spacer()
            Button("Ping") {
                pinging = true
                Task {
                    do {
                        let version = try await GPGService.shared.ping()
                        result = "✓ \(version)"
                    } catch {
                        result = "✗ \(error.localizedDescription)"
                    }
                    pinging = false
                }
            }
            .font(.caption2)
            .disabled(pinging)
        }
        .padding(.horizontal)
        .padding(.vertical, 6)
        .background(.quaternary)
    }
}

// MARK: - Previews

#Preview("All keys found") {
    let state = ComposeSessionState()
    state.recipientKeyStatus = [
        "alice@example.com": .found,
        "bob@example.com": .found,
    ]
    state.encryptEnabled = true
    return ComposeSecurityView(state: state)
}

#Preview("Missing key") {
    let state = ComposeSessionState()
    state.recipientKeyStatus = [
        "alice@example.com": .found,
        "carol@example.com": .notFound,
    ]
    return ComposeSecurityView(state: state)
}

#Preview("No recipients yet") {
    ComposeSecurityView(state: ComposeSessionState())
}
