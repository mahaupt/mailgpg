# Certificate & Provisioning Profile Renewal

Developer ID Application certificates are valid for **5 years**. Provisioning profiles
tied to that certificate expire when the certificate does. This doc walks through
renewing everything when that happens.

---

## 1. Create a new Developer ID Application certificate

1. Go to [developer.apple.com](https://developer.apple.com) → Certificates, Identifiers & Profiles → Certificates → `+`
2. Select **Developer ID Application** → Continue
3. Select **G2 Sub-CA (Xcode 11.4.1 or later)** → Continue
4. Generate a CSR on your Mac:
   - Open **Keychain Access** → Menu → Certificate Assistant → **Request a Certificate from a Certificate Authority**
   - User Email: your Apple ID email
   - Common Name: `MailGPG Developer ID`
   - Request is: **Saved to disk**
5. Upload the `.certSigningRequest` file → Continue → Generate → **Download**
6. Double-click the downloaded `.cer` to install it into Keychain Access

---

## 2. Export the certificate as .p12

1. Open **Keychain Access** → **My Certificates**
2. Find **Developer ID Application: Marcel Haupt (ZM4SAL8656)**
3. Right-click → **Export** → format: **Personal Information Exchange (.p12)**
4. Set a strong password
5. Base64-encode and copy to clipboard:
   ```bash
   base64 -i DeveloperIDApplication.p12 | pbcopy
   ```
6. Update the GitHub secrets:
   - `DEVELOPER_ID_CERTIFICATE_BASE64` → paste new value
   - `DEVELOPER_ID_CERTIFICATE_PASSWORD` → update if password changed

---

## 3. Regenerate provisioning profiles

The existing profiles are tied to the old certificate and must be regenerated.

1. Go to [developer.apple.com](https://developer.apple.com) → Certificates, Identifiers & Profiles → Profiles
2. Find **MailGPG_DeveloperID** → Edit → select the new certificate → Save → Download
3. Find **MailGPGExtension_DeveloperID** → Edit → select the new certificate → Save → Download
4. Base64-encode both and update GitHub secrets:
   ```bash
   base64 -i MailGPG_DeveloperID.provisionprofile | pbcopy
   # → update PROVISIONING_PROFILE_HOST_BASE64

   base64 -i MailGPGExtension_DeveloperID.provisionprofile | pbcopy
   # → update PROVISIONING_PROFILE_EXTENSION_BASE64
   ```

---

## 4. Update the Xcode project

The new profiles must be selected in Xcode so the `.pbxproj` references are updated:

1. Open the project in Xcode
2. For each target (**MailGPG** and **MailGPGExtension**):
   - Signing & Capabilities → switch to **Release**
   - Click the Provisioning Profile dropdown → select the updated profile
3. Commit the `.pbxproj` change:
   ```bash
   git add MailGPG.xcodeproj/project.pbxproj
   git commit -m "Update provisioning profiles for renewed Developer ID certificate"
   git push
   ```

---

## 5. Verify

Trigger a release to confirm everything works:

```bash
git tag v<next-version>
git push origin v<next-version>
```

Check the GitHub Actions run — the Archive and Notarize steps should pass cleanly.

---

## Notarization password

The `NOTARIZATION_PASSWORD` app-specific password does **not** expire on a fixed schedule,
but Apple may invalidate it if you change your Apple ID password or revoke it manually.
If notarization starts failing with an authentication error, generate a new app-specific
password at [appleid.apple.com](https://appleid.apple.com) → Sign-In and Security →
App-Specific Passwords and update the `NOTARIZATION_PASSWORD` secret.
