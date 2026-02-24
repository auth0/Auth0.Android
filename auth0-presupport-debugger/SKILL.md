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

### Phase 4 — Pre-Ticket Diagnostic Summary

Before raising an ESD case or GitHub issue, collect the following information. Paste it into your ticket.

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

### Logs
(Paste relevant SDK log lines here)

### Already Checked
- [ ] Phase 1: Auth0 Dashboard Checklist
- [ ] Phase 2: SDK Configuration Check
- [ ] Phase 3: Runtime Diagnostics
```

---

## Detailed Documentation

- **[Android Validation Checklist](references/android-checklist.md)** — Gradle, manifest, intent-filter, credentials, and ProGuard configuration
- **[Swift/iOS Validation Checklist](references/swift-checklist.md)** — Auth0.plist, Info.plist, Universal Links, Keychain, and SPM/CocoaPods setup
- **[Common Issues & Diagnostics](references/common-issues.md)** — Symptom-to-root-cause mapping, error codes, and fix snippets

---

## Common Mistakes

| Symptom | Likely Cause | Reference |
|---------|-------------|-----------|
| "Callback URL mismatch" error | URL in dashboard doesn't match SDK-constructed URL | [Common Issues](references/common-issues.md#callback-url-mismatch) |
| Browser opens but app never receives callback | Missing/incorrect intent-filter (Android) or URL scheme (iOS) | [Android Checklist](references/android-checklist.md#intent-filter) / [Swift Checklist](references/swift-checklist.md#url-scheme) |
| `NetworkErrorException` or timeout | INTERNET permission missing (Android) or network misconfiguration | [Android Checklist](references/android-checklist.md#permissions) |
| `Auth0Exception: invalid_grant` | Refresh token rotation misconfigured or reuse detected | [Common Issues](references/common-issues.md#token-errors) |
| `Auth0Exception: access_denied` | Connection not enabled for the application | [Common Issues](references/common-issues.md#access-denied) |
| App type not Native | Dashboard app created as SPA or Regular Web App | Phase 1, Step 2 above |
| Silent auth returns no tokens | Offline access scope missing or refresh tokens not enabled | [Common Issues](references/common-issues.md#silent-auth) |
| `Auth0.plist` not found (iOS) | File not added to the correct app target in Xcode | [Swift Checklist](references/swift-checklist.md#auth0-plist) |
| Keychain access error (iOS) | Missing Keychain Sharing entitlement | [Swift Checklist](references/swift-checklist.md#keychain) |
| Crash on Android API < 21 | `minSdk` below SDK minimum requirement | [Android Checklist](references/android-checklist.md#gradle) |

---

## Related Skills

- `auth0-quickstart` — Initial Auth0 tenant and application setup
- `auth0-react-native` — React Native / Expo mobile authentication
- `auth0-mfa` — Multi-Factor Authentication configuration

---

## References

- [Auth0 Android SDK (auth0-android)](https://github.com/auth0/Auth0.Android)
- [Auth0 Android Quickstart](https://auth0.com/docs/quickstart/native/android)
- [Auth0 Swift SDK (Auth0.swift)](https://github.com/auth0/Auth0.swift)
- [Auth0 iOS/macOS Quickstart](https://auth0.com/docs/quickstart/native/ios-swift)
- [Auth0 Support Center](https://support.auth0.com)
