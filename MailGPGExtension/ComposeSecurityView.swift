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

            // Status indicators
            HStack(spacing: 10) {
                Image(systemName: "signature")
                    .foregroundStyle(.blue)
                    .frame(width: 20, alignment: .center)
                VStack(alignment: .leading, spacing: 1) {
                    Text("Signing available")
                        .font(.callout)
                }
                Spacer()
                Image(systemName: "checkmark.circle.fill")
                    .foregroundStyle(.green)
            }

            HStack(spacing: 10) {
                Image(systemName: state.canEncrypt ? "lock.fill" : "lock.open")
                    .foregroundStyle(state.canEncrypt ? .green : .secondary)
                    .frame(width: 20, alignment: .center)
                VStack(alignment: .leading, spacing: 1) {
                    Text(state.canEncrypt ? "Encryption available" : "Encryption unavailable")
                        .font(.callout)
                    if !state.canEncrypt && !state.recipientKeyStatus.isEmpty {
                        Text("Some recipients are missing a public key.")
                            .font(.caption2)
                            .foregroundStyle(.orange)
                    }
                }
                Spacer()
                Image(systemName: state.canEncrypt ? "checkmark.circle.fill" : "xmark.circle.fill")
                    .foregroundStyle(state.canEncrypt ? .green : .orange)
            }

            Text("Use Mail's toolbar buttons to sign or encrypt.")
                .font(.caption2)
                .foregroundStyle(.secondary)

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

// MARK: - Previews

#Preview("All keys found") {
    let state = ComposeSessionState()
    state.recipientKeyStatus = [
        "alice@example.com": .found,
        "bob@example.com": .found,
    ]
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
