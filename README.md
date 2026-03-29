# MailGPG

Native macOS Mail extension for OpenPGP — sign, encrypt, and decrypt emails using your local GPG installation, directly in Apple Mail.

## Requirements

- macOS 12 Monterey or later
- Apple Mail
- [GnuPG](https://gnupg.org) (`brew install gnupg`)
- [pinentry-mac](https://github.com/GPGTools/pinentry) (`brew install pinentry-mac`)

## Installation

```bash
brew install --cask mahaupt/mailgpg/mailgpg
```

Then enable the extension:
**Mail → Settings → Extensions → MailGPG ✓**

Restart Mail if it was already open.

If you do not have a private key yet, create one with GnuPG:
[How to create a new GPG key](https://docs.github.com/en/authentication/managing-commit-signature-verification/generating-a-new-gpg-key)

## Features

- **Sign** outgoing emails with your private key (RFC 3156 PGP/MIME)
- **Encrypt** outgoing emails to recipients with known public keys
- **Decrypt** incoming encrypted emails inline in Mail
- **Verify** signatures on incoming signed emails
- **Key lookup** — automatically fetches missing public keys from keyservers
- **Key management** — import, delete, set trust levels, manage public and private keys
- Per-compose controls via a panel in the Mail compose window

## Architecture

MailGPG uses a two-process design required by Apple's MailKit sandboxing:

- **Host app** (`MailGPG.app`) — runs unsandboxed as a background service; executes GPG subprocesses and exposes results over XPC
- **Mail extension** (`MailGPGExtension`) — sandboxed MailKit extension loaded by Mail; handles all UI and delegates GPG operations to the host app via XPC

The host app registers itself as a login item on first launch (`SMAppService`) and is automatically started at login.

## License

GPL-3.0
