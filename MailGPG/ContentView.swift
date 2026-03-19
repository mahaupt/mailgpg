// ContentView.swift
// MailGPG

import SwiftUI

struct ContentView: View {

    // MARK: - State

    @State private var gpgPath    = ""
    @State private var gpgVersion = ""
    @State private var gpgError   = ""
    @State private var agentOK    = false
    @State private var pinentry   = GPGAgent.PinentryStatus.notInstalled
    @State private var fixing     = false

    // MARK: - Body

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {

            // ── Header ────────────────────────────────────────────────────────
            HStack(spacing: 10) {
                Image(systemName: "lock.shield.fill")
                    .font(.title2)
                    .foregroundStyle(.blue)
                Text("MailGPG")
                    .font(.title3.weight(.semibold))
                Spacer()
                Button { Task { await refresh() } } label: {
                    Image(systemName: "arrow.clockwise")
                }
                .buttonStyle(.plain)
                .foregroundStyle(.secondary)
                .help("Refresh status")
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)

            Divider()

            VStack(alignment: .leading, spacing: 12) {

                // ── GPG Installation ──────────────────────────────────────────
                SectionBox(title: "GPG Installation") {
                    if gpgError.isEmpty {
                        InfoRow(
                            icon: gpgPath.isEmpty ? "magnifyingglass" : "checkmark.circle.fill",
                            iconColor: gpgPath.isEmpty ? .secondary : .green,
                            primary: gpgPath.isEmpty ? "Checking…" : (gpgPath as NSString).lastPathComponent,
                            secondary: gpgPath.isEmpty ? nil : gpgPath
                        )
                        if !gpgVersion.isEmpty {
                            Text(gpgVersion)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .padding(.leading, 28)
                        }
                    } else {
                        InfoRow(
                            icon: "xmark.circle.fill",
                            iconColor: .red,
                            primary: "GPG not found",
                            secondary: gpgError
                        )
                    }
                }

                // ── Background Agent ──────────────────────────────────────────
                SectionBox(title: "Background Agent") {
                    InfoRow(
                        icon: agentOK ? "checkmark.circle.fill" : "exclamationmark.circle.fill",
                        iconColor: agentOK ? .green : .orange,
                        primary: agentOK ? "gpg-agent running" : "gpg-agent not running"
                    )

                    Divider().padding(.leading, 28)

                    HStack(alignment: .top, spacing: 8) {
                        pinentryIcon
                            .frame(width: 20)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(pinentryTitle).font(.callout)
                            if let sub = pinentrySubtitle {
                                Text(sub)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                        Spacer(minLength: 8)
                        if showPinentryFix {
                            Button(fixing ? "Fixing…" : "Fix") { applyPinentryFix() }
                                .controlSize(.small)
                                .disabled(fixing)
                        }
                    }
                    .padding(.vertical, 2)
                }

            }
            .padding(16)
        }
        .frame(minWidth: 380, maxWidth: 480)
        .task { await refresh() }
    }

    // MARK: - Pinentry helpers

    @ViewBuilder private var pinentryIcon: some View {
        switch pinentry {
        case .ok:
            Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
        case .fixable, .nonMac:
            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
        case .notInstalled:
            Image(systemName: "xmark.circle.fill").foregroundStyle(.red)
        }
    }

    private var pinentryTitle: String {
        switch pinentry {
        case .ok:               return "pinentry-mac configured"
        case .nonMac(let p, _): return "Non-GUI pinentry: \((p as NSString).lastPathComponent)"
        case .fixable:          return "pinentry-mac not configured"
        case .notInstalled:     return "pinentry-mac not installed"
        }
    }

    private var pinentrySubtitle: String? {
        switch pinentry {
        case .ok(let path):          return path
        case .nonMac(_, let fix?):   return "Passphrase prompts may hang. Tap Fix to switch to pinentry-mac."
        case .nonMac:                return "Passphrase prompts may hang. Install pinentry-mac via Homebrew."
        case .fixable(let path):     return "Found at \(path) — tap Fix to configure."
        case .notInstalled:          return "Run: brew install pinentry-mac"
        }
    }

    private var showPinentryFix: Bool {
        switch pinentry {
        case .fixable:              return true
        case .nonMac(_, let fix):   return fix != nil
        default:                    return false
        }
    }

    // MARK: - Actions

    private func refresh() async {
        do {
            let path = try GPGLocator.locate()
            let version = try GPGLocator.version(at: path)
            gpgPath    = path
            gpgVersion = version
            gpgError   = ""
        } catch {
            gpgPath    = ""
            gpgVersion = ""
            gpgError   = error.localizedDescription
        }
        let (ok, pe) = await Task.detached {
            let ok = (try? GPGAgent.ensureRunning()) ?? false
            let pe = GPGAgent.checkPinentry()
            return (ok, pe)
        }.value
        agentOK  = ok
        pinentry = pe
    }

    private func applyPinentryFix() {
        let path: String
        switch pinentry {
        case .fixable(let p):      path = p
        case .nonMac(_, let fix?): path = fix
        default:                   return
        }
        fixing = true
        Task.detached {
            do {
                try GPGAgent.configurePinentry(path: path)
                let pe = GPGAgent.checkPinentry()
                await MainActor.run { pinentry = pe; fixing = false }
            } catch {
                await MainActor.run { fixing = false }
            }
        }
    }

}

// MARK: - Reusable components

private struct SectionBox<Content: View>: View {
    let title: String
    @ViewBuilder let content: () -> Content

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(.subheadline.weight(.medium))
                .foregroundStyle(.secondary)
                .padding(.leading, 4)
            VStack(alignment: .leading, spacing: 6) {
                content()
            }
            .padding(10)
            .background(.quaternary, in: RoundedRectangle(cornerRadius: 8))
        }
    }
}

private struct InfoRow: View {
    let icon: String
    let iconColor: Color
    let primary: String
    var secondary: String? = nil

    var body: some View {
        HStack(alignment: secondary == nil ? .center : .top, spacing: 8) {
            Image(systemName: icon)
                .foregroundStyle(iconColor)
                .frame(width: 20)
            VStack(alignment: .leading, spacing: 2) {
                Text(primary).font(.callout)
                if let secondary {
                    Text(secondary)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            Spacer()
        }
        .padding(.vertical, 2)
    }
}

#Preview {
    ContentView()
}
