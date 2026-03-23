// DiagnosticsView.swift
// MailGPGExtension

import SwiftUI

struct DiagnosticsView: View {

    @State private var status: SystemStatus? = nil
    @State private var loading = true
    @State private var loadError: String? = nil
    @State private var fixInProgress = false
    @State private var fixError: String? = nil

    var body: some View {
        List {
            if loading {
                HStack {
                    ProgressView()
                        .controlSize(.small)
                    Text("Checking…")
                        .foregroundStyle(.secondary)
                }
            } else if let err = loadError {
                HStack {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                    Text(err)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            } else if let s = status {
                // MARK: GPG Binary
                Section("GPG Binary") {
                    if let path = s.gpgPath {
                        LabeledContent("Path", value: path)
                        LabeledContent("Version", value: s.gpgVersion ?? "Unknown")
                    } else {
                        HStack {
                            Image(systemName: "xmark.circle.fill")
                                .foregroundStyle(.red)
                            Text("GPG not found")
                            Spacer()
                        }
                        Text("Install GPG via Homebrew: brew install gnupg")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }

                // MARK: gpg-agent
                Section("GPG Agent") {
                    HStack {
                        Image(systemName: s.agentRunning ? "checkmark.circle.fill" : "xmark.circle.fill")
                            .foregroundStyle(s.agentRunning ? .green : .red)
                        Text(s.agentRunning ? "Running" : "Not running")
                    }
                }

                // MARK: Pinentry
                Section("Pinentry") {
                    switch s.pinentryState {
                    case .ok:
                        HStack {
                            Image(systemName: "checkmark.circle.fill")
                                .foregroundStyle(.green)
                            Text("Configured")
                        }
                        if let path = s.pinentryConfiguredPath {
                            Text(path)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }

                    case .fixable:
                        HStack {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .foregroundStyle(.yellow)
                            Text("Not configured")
                        }
                        Text("pinentry-mac is available but not set as the default. Fix to allow passphrase prompts.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        fixButton(availablePath: s.pinentryAvailablePath)

                    case .nonMac:
                        HStack {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .foregroundStyle(.orange)
                            Text("Non-GUI pinentry configured")
                        }
                        if let path = s.pinentryConfiguredPath {
                            Text("Configured: \(path)")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Text("This will hang in a background app. Switch to pinentry-mac.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        if s.pinentryAvailablePath != nil {
                            fixButton(availablePath: s.pinentryAvailablePath)
                        } else {
                            Text("Install pinentry-mac: brew install pinentry-mac")
                                .font(.caption)
                                .foregroundStyle(.red)
                        }

                    case .notInstalled:
                        HStack {
                            Image(systemName: "xmark.circle.fill")
                                .foregroundStyle(.red)
                            Text("pinentry-mac not installed")
                        }
                        Text("Install it via Homebrew: brew install pinentry-mac")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }

                    if let err = fixError {
                        Text(err)
                            .font(.caption)
                            .foregroundStyle(.red)
                    }
                }
            }
        }
        .navigationTitle("Diagnostics")
        .task { await reload() }
    }

    @ViewBuilder
    private func fixButton(availablePath: String?) -> some View {
        Button {
            Task { await applyFix() }
        } label: {
            if fixInProgress {
                HStack(spacing: 6) {
                    ProgressView().controlSize(.small)
                    Text("Fixing…")
                }
            } else {
                Label("Fix Automatically", systemImage: "wand.and.stars")
            }
        }
        .disabled(fixInProgress)
        if let path = availablePath {
            Text("Will configure: \(path)")
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
    }

    private func reload() async {
        loading = true
        loadError = nil
        fixError = nil
        do {
            status = try await GPGService.shared.getSystemStatus()
        } catch {
            loadError = error.localizedDescription
        }
        loading = false
    }

    private func applyFix() async {
        fixInProgress = true
        fixError = nil
        do {
            try await GPGService.shared.fixPinentry()
            await reload()
        } catch {
            fixError = error.localizedDescription
        }
        fixInProgress = false
    }
}
