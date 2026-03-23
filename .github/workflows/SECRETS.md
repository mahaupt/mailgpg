# Required GitHub Actions Secrets

Configure these at: https://github.com/mahaupt/mailgpg/settings/secrets/actions

| Secret | Description | How to get it |
|--------|-------------|---------------|
| `DEVELOPER_ID_CERTIFICATE_BASE64` | Developer ID Application certificate + private key as base64-encoded .p12 | Keychain Access → export cert as .p12, then `base64 -i cert.p12 \| pbcopy` |
| `DEVELOPER_ID_CERTIFICATE_PASSWORD` | Password set when exporting the .p12 | Set when exporting from Keychain Access |
| `DEVELOPMENT_TEAM` | Your 10-character Apple Team ID | `ZM4SAL8656` (from Xcode project settings) |
| `APPLE_ID` | Your Apple ID email used for notarization | e.g. `you@example.com` |
| `NOTARIZATION_PASSWORD` | App-specific password for notarytool | https://appleid.apple.com → Sign-In and Security → App-Specific Passwords |
| `PROVISIONING_PROFILE_HOST_BASE64` | Developer ID provisioning profile for `com.mahaupt.MailGPG` | developer.apple.com → Profiles → + → macOS Developer ID, then `base64 -i file.provisionprofile \| pbcopy` |
| `PROVISIONING_PROFILE_EXTENSION_BASE64` | Developer ID provisioning profile for `com.mahaupt.MailGPG.MailGPGExtension` | Same as above for the extension bundle ID |
| `TAP_TOKEN` | GitHub Personal Access Token with repo write access to mahaupt/homebrew-mailgpg | GitHub → Settings → Developer Settings → Personal Access Tokens (classic), scopes: `repo` |

## Triggering a release

```bash
git tag v1.0.0
git push origin v1.0.0
```

The pipeline will:
1. Build + archive with Xcode
2. Sign with Developer ID
3. Package as DMG
4. Notarize + staple
5. Create a GitHub Release with the DMG attached
6. Open a PR on mahaupt/homebrew-mailgpg updating version + SHA256

## One-time setup: create the Homebrew tap repo

1. Create a new GitHub repo named `homebrew-mailgpg` under `mahaupt`
2. Copy `.github/homebrew/mailgpg.rb` to `Casks/mailgpg.rb` in that repo
3. Users can then install with: `brew install --cask mahaupt/mailgpg/mailgpg`
