---
name: auth0-presupport-debugger
description: Use before raising an Auth0 ESD ticket or GitHub issue for Android or Swift SDK problems - validates Auth0 dashboard configuration, SDK setup, callback URLs, manifest/plist files, and surfaces the most common root causes
---

# Auth0 Pre-Support Debugger — Android & Swift

Diagnose Auth0 integration issues in Android (auth0-android) and Swift/iOS (Auth0.swift) apps **before raising an ESD ticket or filing a GitHub issue**. This skill walks through every configuration layer, generates a structured diagnostic summary, and maps symptoms to known root causes.

---

## When to Use This Skill

- Login or logout flow is failing or hanging
- Callback / redirect URL is not resolving
- Tokens are not being returned or are invalid
- App crashes or throws exceptions during auth
- Auth0 dashboard is not logging any activity
- You are about to open an ESD case or GitHub issue and want to confirm the setup first

## When NOT to Use

- **React Native apps** — use `auth0-react-native` skill
- **Web SPAs or server apps** — use `auth0-react`, `auth0-nextjs`, `auth0-angular`, `auth0-vue`, or `auth0-express`
- **Auth0 Actions / Rules / Hooks** — out of scope for this skill
- **Auth0 Organizations / Enterprise Connections** — requires ESD escalation directly

---

## Quick Diagnostic Workflow

Run through each phase in order. Confirm every item before moving to the next phase. A single misconfiguration in an early phase will cause failures that look like later-phase issues.

### Phase 0 — Automated CLI Configuration Validation

Use the Auth0 CLI to **programmatically validate** the developer's Auth0 dashboard configuration against their local app config. This is the fastest way to catch mismatches before doing any manual inspection.

> **How this phase runs:** The AI assistant executes all CLI commands directly using its Bash tool. The user only needs to act for the `auth0 login` browser step — everything else is automated.

See the full [CLI Configuration Validation Reference](references/cli-config-validation.md) for all commands and the automated script.

#### Step 0a — Check CLI Installation (run directly)

```bash
auth0 --version
```

- **If installed:** proceed to Step 0b.
- **If not found:** detect OS with `uname -s`, then run the correct install command:
  - **macOS:** `brew tap auth0/auth0-cli && brew install auth0`
  - **Windows:** `scoop bucket add auth0 https://github.com/auth0/scoop-auth0-cli.git && scoop install auth0`
  - **Linux:** `curl -sSfL https://raw.githubusercontent.com/auth0/auth0-cli/main/install.sh | sh -s -- -b /usr/local/bin`
  - Re-run `auth0 --version` to confirm, then proceed to Step 0b.

#### Step 0b — Check CLI Authentication (run directly)

```bash
auth0 tenants list
```

- **If it lists tenants:** CLI is authenticated — proceed to Step 0c.
- **If it fails with `config.json file is missing`:** CLI is installed but never logged in. Run `auth0 login` using the Bash tool. The CLI will print a **device code URL** — tell the user to open it in their browser and complete the Auth0 authorization flow. The command blocks until auth completes, then continue automatically.
- After login, re-run `auth0 tenants list` to confirm the correct tenant is active.

#### Step 0c — Check jq (run directly)

```bash
jq --version
```

- **If not found:** run `brew install jq` (macOS) or `sudo apt-get install -y jq` (Linux).

#### Step 0d — Extract App Config from Source Files (run directly)

Ask the user ONE question: **"What is the path to your Android project root (or iOS project root)?"**

Then run the appropriate extraction commands from [CLI Config Validation — Automated Config Extraction](references/cli-config-validation.md#automated-config-extraction-from-project-files) to read Client ID, Domain, Package/Bundle ID, and Scheme directly from the source files. Do not ask the user to type these values manually.

#### Step 0e — Run the Full Validation (run directly)

Run `auth0 apps show <CLIENT_ID> --json` and validate each check below. Execute each CLI command with the Bash tool — do not ask the user to run them.

**Check each of the following via CLI (see [full reference](references/cli-config-validation.md) for commands):**

| # | Check | Pass Criteria |
|---|-------|---------------|
| 1 | Application exists | CLI returns JSON, no error |
| 2 | Application type | `"native"` |
| 3 | Callback URL registered | Dashboard contains expected `{scheme}://{domain}/{platform}/{appId}/callback` |
| 4 | Logout URL registered | Dashboard contains expected logout URL |
| 5 | Authorization Code grant enabled | `grant_types` includes `"authorization_code"` |
| 6 | Refresh Token grant enabled | `grant_types` includes `"refresh_token"` |
| 7 | Allowed Web Origins empty | Empty or null (correct for native apps) |
| 8 | Token endpoint auth method | `"none"` (PKCE, no client secret) |
| 9 | Refresh Token Rotation | `"rotating"` (recommended for native) |
| 10 | Connection enabled for app | At least one connection has this Client ID in `enabled_clients` |
| 11 | OIDC discovery reachable | `https://{domain}/.well-known/openid-configuration` returns valid JSON |
| | **DPoP (if used)** | |
| 12 | DPoP advertised in OIDC discovery | `dpop_signing_alg_values_supported` is non-empty (Early Access — contact Auth0 support) |
| 13 | Android minSdk ≥ 23 | DPoP requires API 23+ (Android 6.0) |
| | **Passkeys (if used)** | |
| 14 | Custom domain configured & verified | At least one domain with status `"ready"` (REQUIRED for passkeys) |
| 15 | Passkey (WebAuthn) grant type enabled | `grant_types` contains `webauthn` |
| 16 | `assetlinks.json` valid (Android) | Custom domain serves valid JSON with app's package + SHA-256 fingerprint |
| 17 | Credential Manager dependency (Android) | `androidx.credentials` present in `build.gradle` |
| 18 | Android minSdk ≥ 28 | Passkeys require API 28+ (Android 9) |

#### One-Command Full Validation

For a complete automated check, use the [full validation script](references/cli-config-validation.md#full-automated-validation-script) — fill in 5 variables and run:

```bash
# Fill in these values from the developer's project
CLIENT_ID="..."  AUTH0_DOMAIN="..."  PLATFORM="android"  APP_IDENTIFIER="..."  SCHEME="..."

# The script validates all 11 checks and prints ✅/❌/⚠️ for each
bash validate-auth0-config.sh
```

> **Scope:** This skill is diagnosis-only. It identifies root causes and reports findings — it does not apply fixes. If all Phase 0 checks pass, generate the All-Clear Report and stop. If any checks fail, continue to Phase 1 and collect all findings for the Diagnostic Summary.

---

### Phase 1 — Auth0 Dashboard Checklist

1. Log in to [manage.auth0.com](https://manage.auth0.com) and open the Application settings.
2. Confirm **Application Type** is set to **Native** (not SPA or Regular Web App).
3. Under **Allowed Callback URLs**, verify the exact URL(s) match what the SDK sends:
   - Android: `{scheme}://{auth0-domain}/android/{packageName}/callback`
   - Swift/iOS: `{bundleId}://{auth0-domain}/ios/{bundleId}/callback`
4. Under **Allowed Logout URLs**, verify the exact URL(s) match what the SDK sends.
5. Under **Allowed Web Origins** — leave blank for native apps.
6. Open **Advanced Settings → Grant Types** and confirm both are enabled:
   - `Authorization Code`
   - `Refresh Token`
7. Confirm the **Domain** shown in the dashboard (e.g. `your-tenant.auth0.com`) — no `https://` prefix.
8. Note the **Client ID** — you'll cross-check it against the app configuration in Phase 2.

> If anything in Phase 1 is wrong, fix it before continuing. Most "callback URL mismatch" errors originate here.

---

### Phase 2 — SDK Configuration Check

#### Android

See the full [Android Validation Checklist](references/android-checklist.md) for line-by-line verification. Key points:

- `build.gradle (app)` includes the `com.auth0.android:auth0` dependency at the correct version
- `INTERNET` permission is declared in `AndroidManifest.xml`
- `RedirectActivity` (or custom `AuthenticationActivity` intent-filter) is present and `exported="true"`
- `manifestPlaceholders` in `build.gradle` sets `auth0Domain` and `auth0Scheme` **or** the `<data>` element in the intent-filter uses the correct `android:host` and `android:pathPrefix`
- Domain and Client ID strings match the dashboard values exactly (no trailing slashes, no `https://`)

#### Swift / iOS

See the full [Swift/iOS Validation Checklist](references/swift-checklist.md) for line-by-line verification. Key points:

- `Auth0.plist` exists at the root of the app target (not only in the test target) with correct `Domain` and `ClientId` keys
- `Info.plist` declares a `CFBundleURLScheme` matching `$(PRODUCT_BUNDLE_IDENTIFIER)` (for custom scheme callbacks)
- If using Universal Links, the associated domain entitlement and `apple-app-site-association` file are configured
- `Credentials` / `CredentialsManager` is initialized with the correct domain and client ID
- The bundle identifier in Xcode matches what is registered in the Auth0 dashboard callback URL

---

### Phase 3 — Runtime Diagnostics

1. Enable verbose SDK logging to capture the exact error:

   **Android:**
   ```kotlin
   Auth0.getInstance(clientId, domain).networkingClient =
       DefaultClient(connectTimeout = 10, readTimeout = 10, enableLogging = true)
   ```

   **Swift:**
   ```swift
   Auth0.authentication().logging(enabled: true)
   Auth0.webAuth().logging(enabled: true)
   ```

2. Reproduce the failure and capture the **full log output**.
3. Check for these specific log patterns and map them to root causes — see [Common Issues](references/common-issues.md).

---

### Phase 4 — Final Report

> **This skill is diagnosis-only.** It reports root causes — it does not apply fixes.

#### Path A — All-Clear Report (all checks passed)

Generate this when every check across all phases passes:

```
## Auth0 Pre-Support Debugger — All Clear

All configuration checks passed. No misconfiguration detected.

### Environment
- Platform:
- SDK version:
- Auth0 Domain:
- Client ID (first 8 chars):
- Package / Bundle ID:

### Checks Passed
- [x] Phase 0: Automated CLI Configuration Validation — ALL PASSED
- [x] Phase 1: Auth0 Dashboard Checklist — ALL PASSED
- [x] Phase 2: SDK Configuration Check — ALL PASSED

### Recommendation
Auth0 dashboard and SDK configuration are correct. The reported symptom
may be caused by a runtime or device-specific issue. Enable verbose SDK
logging (Phase 3), reproduce the failure, and review the log output.
```

#### Path B — Diagnostic Summary (one or more checks failed)

Generate this when any check fails. For every ❌ item, fill in the Root Cause field with a precise description of what was found and what the correct value should be. Do not include fix commands.

```
## Auth0 Pre-Support Diagnostic

### Environment
- Platform: [ ] Android  [ ] iOS/Swift
- SDK version:
- Auth0 tenant region (e.g. US, EU, AU):
- Device OS version:
- Emulator / Simulator or physical device:

### Auth0 Dashboard
- Application type: Native / SPA / Regular Web App
- Allowed Callback URLs (exact values):
- Allowed Logout URLs (exact values):
- Grant types enabled (Authorization Code, Refresh Token):

### App Configuration
- Auth0 Domain used in code:
- Client ID used in code (first 8 chars only):
- Package name (Android) / Bundle ID (iOS):
- Callback URL constructed by SDK:

### Failure Description
- Step where failure occurs (login / logout / token exchange / silent auth):
- Error code / message from logs:
- Frequency: Always / Intermittent
- First occurrence: Always failing / Regression (worked before)

### Root Causes Found
(List each ❌ check with a precise description of what is wrong and what the correct value should be)

### Logs
(Paste relevant SDK log lines here)

### Checks Completed
- [ ] Phase 0: Automated CLI Configuration Validation
- [ ] Phase 1: Auth0 Dashboard Checklist
- [ ] Phase 2: SDK Configuration Check
- [ ] Phase 3: Runtime Diagnostics
```

---

## Detailed Documentation

- **[CLI Configuration Validation](references/cli-config-validation.md)** — Automated Auth0 CLI commands to validate dashboard config and full validation script
- **[Android Validation Checklist](references/android-checklist.md)** — Gradle, manifest, intent-filter, credentials, and ProGuard configuration
- **[Swift/iOS Validation Checklist](references/swift-checklist.md)** — Auth0.plist, Info.plist, Universal Links, Keychain, and SPM/CocoaPods setup
- **[Common Issues & Diagnostics](references/common-issues.md)** — Symptom-to-root-cause mapping, error codes, and fix snippets

---

## Common Mistakes

| Symptom | Likely Cause | Reference |
|---------|-------------|-----------|
| CLI returns "Unauthorized" | CLI not authenticated or wrong tenant | [CLI Validation](references/cli-config-validation.md#troubleshooting-the-cli-itself) |
| CLI shows app type is SPA | Dashboard app created as SPA instead of Native | [CLI Validation → Step 2](references/cli-config-validation.md#step-2-validate-application-type) |
| CLI reports callback URL not found | URL in dashboard doesn't match SDK-constructed URL | [CLI Validation → Step 3](references/cli-config-validation.md#step-3-validate-callback-urls) |
| CLI reports missing grant types | Authorization Code or Refresh Token grant not enabled | [CLI Validation → Step 5](references/cli-config-validation.md#step-5-validate-grant-types) |
| CLI shows no connections enabled | No database/social connection toggled on for the app | [CLI Validation → Step 8](references/cli-config-validation.md#step-8-validate-connections-enabled-for-the-application) |
| "Callback URL mismatch" error | URL in dashboard doesn't match SDK-constructed URL | [Common Issues](references/common-issues.md#callback-url-mismatch) |
| Browser opens but app never receives callback | Missing/incorrect intent-filter (Android) or URL scheme (iOS) | [Android Checklist](references/android-checklist.md#intent-filter) / [Swift Checklist](references/swift-checklist.md#url-scheme) |
| `NetworkErrorException` or timeout | INTERNET permission missing (Android) or network misconfiguration | [Android Checklist](references/android-checklist.md#permissions) |
| `Auth0Exception: invalid_grant` | Refresh token rotation misconfigured or reuse detected | [Common Issues](references/common-issues.md#token-errors) |
| `Auth0Exception: access_denied` | Connection not enabled for the application | [Common Issues](references/common-issues.md#access-denied) |
| App type not Native | Dashboard app created as SPA or Regular Web App | Phase 0 CLI check or Phase 1, Step 2 above |
| Silent auth returns no tokens | Offline access scope missing or refresh tokens not enabled | [Common Issues](references/common-issues.md#silent-auth) |
| `Auth0.plist` not found (iOS) | File not added to the correct app target in Xcode | [Swift Checklist](references/swift-checklist.md#auth0-plist) |
| Keychain access error (iOS) | Missing Keychain Sharing entitlement | [Swift Checklist](references/swift-checklist.md#keychain) |
| Crash on Android API < 21 | `minSdk` below SDK minimum requirement | [Android Checklist](references/android-checklist.md#gradle) |
| `DPoPException: UNSUPPORTED_ERROR` | DPoP used on Android < API 23 | [CLI Validation → Step 10](references/cli-config-validation.md#step-10-validate-dpop-demonstrating-proof-of-possession-configuration) |
| Tokens not DPoP-bound after login | DPoP not enabled at tenant level (Early Access) | [CLI Validation → Step 10](references/cli-config-validation.md#step-10-validate-dpop-demonstrating-proof-of-possession-configuration) |
| `DPoP.clearKeyPair()` not called on logout | Old DPoP key pair persists, causing key mismatch | [CLI Validation → DPoP Gotchas](references/cli-config-validation.md#dpop-configuration-gotchas) |
| Passkey registration fails | Custom domain not configured or not verified | [CLI Validation → Step 11](references/cli-config-validation.md#step-11-validate-passkeys-configuration) |
| `assetlinks.json` not found (Android passkeys) | Device Settings not configured in Auth0 dashboard | [CLI Validation → Step 11e](references/cli-config-validation.md#check-11e-verify-android-asset-links-digital-asset-links-for-passkeys) |
| "No credentials available" from Credential Manager | No passkeys registered, or RP ID mismatch with custom domain | [CLI Validation → Passkeys Gotchas](references/cli-config-validation.md#passkeys-configuration-gotchas) |
| Passkey WebAuthn grant type not recognized | Passkey grant type not enabled for the application | [CLI Validation → Step 11b](references/cli-config-validation.md#check-11b-verify-passkey-grant-type-is-enabled) |

---

## Related Skills

- `auth0-quickstart` — Initial Auth0 tenant and application setup
- `auth0-react-native` — React Native / Expo mobile authentication
- `auth0-mfa` — Multi-Factor Authentication configuration

---

## References

- [Auth0 CLI (auth0-cli)](https://github.com/auth0/auth0-cli) — Command-line tool for managing Auth0 tenants, apps, and connections
- [Auth0 CLI Documentation](https://auth0.com/docs/get-started/auth0-overview/create-applications/auth0-cli) — Official CLI usage guide
- [Auth0 Android SDK (auth0-android)](https://github.com/auth0/Auth0.Android)
- [Auth0 Android Quickstart](https://auth0.com/docs/quickstart/native/android)
- [Auth0 Swift SDK (Auth0.swift)](https://github.com/auth0/Auth0.swift)
- [Auth0 iOS/macOS Quickstart](https://auth0.com/docs/quickstart/native/ios-swift)
- [Auth0 Support Center](https://support.auth0.com)
