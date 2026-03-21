// SecurityDetailView.swift
// MailGPGExtension

import SwiftUI

struct SecurityDetailView: View {
    let status: SecurityStatus

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            // Header row
            HStack(spacing: 10) {
                Image(systemName: icon)
                    .font(.title2)
                    .foregroundStyle(color)

                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                        .font(.headline)
                    Text(subtitle)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            Divider()

            // Content rows
            switch status {
            case .encrypted(let signers), .signed(let signers):
                if signers.isEmpty {
                    LabeledRow(label: "Signers", value: "None")
                } else {
                    ForEach(signers, id: \.fingerprint) { signer in
                        SignerRow(signer: signer)
                    }
                }

            case .signatureInvalid(let reason), .decryptionFailed(let reason):
                LabeledRow(label: "Reason", value: reason)

            case .keyNotFound(let keyID):
                LabeledRow(label: "Key ID", value: keyID)
                Text("The signing key was not found in your local keychain and could not be retrieved from a keyserver.")
                    .font(.caption)
                    .foregroundStyle(.secondary)

            case .plain:
                Text("This message was sent without OpenPGP encryption or signing.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .padding()
        .frame(minWidth: 320)
    }

    // MARK: - Derived properties

    private var icon: String {
        switch status {
        case .encrypted:         return "lock.fill"
        case .signed:            return "checkmark.seal.fill"
        case .signatureInvalid:  return "exclamationmark.triangle.fill"
        case .decryptionFailed:  return "lock.slash.fill"
        case .keyNotFound:       return "questionmark.circle.fill"
        case .plain:             return "lock.open"
        }
    }

    private var color: Color {
        switch status {
        case .encrypted:         return .green
        case .signed:            return .blue
        case .signatureInvalid:  return .red
        case .decryptionFailed:  return .red
        case .keyNotFound:       return .orange
        case .plain:             return .gray
        }
    }

    private var title: String {
        switch status {
        case .encrypted(let signers): return signers.isEmpty ? "Encrypted" : "Encrypted & Signed"
        case .signed:            return "Signed"
        case .signatureInvalid:  return "Invalid Signature"
        case .decryptionFailed:  return "Decryption Failed"
        case .keyNotFound:       return "Key Not Found"
        case .plain:             return "No Encryption"
        }
    }

    private var subtitle: String {
        switch status {
        case .encrypted(let signers): return signers.isEmpty ? "This message was encrypted with OpenPGP." : "This message was encrypted and signed with OpenPGP."
        case .signed:            return "The message integrity has been verified."
        case .signatureInvalid:  return "The signature does not match the message content."
        case .decryptionFailed:  return "You may not have the correct private key."
        case .keyNotFound:       return "Signature could not be verified."
        case .plain:             return "Anyone could read or modify this message in transit."
        }
    }
}

// MARK: - Subviews

/// One row per signer showing email, key ID and trust badge.
private struct SignerRow: View {
    let signer: Signer

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(signer.email)
                    .font(.callout)
                    .textSelection(.enabled)
                Spacer()
                TrustLevelBadge(level: signer.trustLevel)
            }
            Text("Key ID: \(signer.keyID)")
                .font(.caption)
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
            Text("Fingerprint: \(signer.fingerprint)")
                .font(.caption2)
                .foregroundStyle(.tertiary)
                .textSelection(.enabled)
        }
        .padding(8)
        .background(.quaternary)
        .clipShape(RoundedRectangle(cornerRadius: 6))
    }
}

/// A simple two-column label/value row.
private struct LabeledRow: View {
    let label: String
    let value: String

    var body: some View {
        HStack(alignment: .top) {
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(width: 80, alignment: .leading)
            Text(value)
                .font(.caption)
                .textSelection(.enabled)
        }
    }
}

// MARK: - Previews

#Preview("Encrypted + signed") {
    SecurityDetailView(status: .encrypted(signers: [
        Signer(email: "alice@example.com", keyID: "AB12CD34", fingerprint: "AB12CD34EF5678901234567890ABCDEF01234567", trustLevel: .full),
        Signer(email: "bob@example.com",   keyID: "FF001122", fingerprint: "FF0011223344556677889900AABBCCDDEEFF0011", trustLevel: .unknown),
    ]))
}

#Preview("Signed") {
    SecurityDetailView(status: .signed(signers: [
        Signer(email: "alice@example.com", keyID: "AB12CD34", fingerprint: "AB12CD34EF5678901234567890ABCDEF01234567", trustLevel: .ultimate),
    ]))
}

#Preview("Key not found") {
    SecurityDetailView(status: .keyNotFound(keyID: "0xDEADBEEF"))
}

#Preview("Signature invalid") {
    SecurityDetailView(status: .signatureInvalid(reason: "Content modified after signing"))
}

#Preview("Plain") {
    SecurityDetailView(status: .plain)
}
