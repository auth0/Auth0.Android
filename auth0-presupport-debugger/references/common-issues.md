# Common Issues & Diagnostics

This reference maps error messages and symptoms to confirmed root causes and fixes for the Auth0 Android and Swift SDKs.

---

## How to Enable Verbose Logging

Always enable SDK logging before reproducing an issue. Log output is required when opening an ESD case or GitHub issue.

**Android:**
```kotlin
val account = Auth0(clientId, domain)
account.networkingClient = DefaultClient(
    connectTimeout = 10,
    readTimeout = 10,
    enableLogging = true
)
```

**Swift:**
```swift
// In AppDelegate/App struct, before any Auth0 call
Auth0.authentication().logging(enabled: true)
Auth0.webAuth().logging(enabled: true)
```

---

## Callback URL Mismatch {#callback-url-mismatch}

### Symptom
- Browser opens, user completes login on Auth0 Universal Login, but the app is never called back
- Auth0 logs show `Callback URL mismatch` or no activity at all
- Android: `AuthenticationException` with code `a0.redirect_uri_mismatch`
- iOS: `WebAuthError.other` or silent hang after browser redirect

### Root Cause
The callback URL registered in Auth0 Dashboard → **Allowed Callback URLs** does not exactly match the URL the SDK constructs at runtime.

### Resolution

**Step 1:** Find the URL the SDK actually sends.

Enable logging (see above) and look for a line like:
```
redirect_uri=com.example.app%3A%2F%2Fyour-tenant.auth0.com%2Fandroid%2Fcom.example.app%2Fcallback
```
URL-decode it to get the raw callback URL.

**Step 2:** Compare against the dashboard.

The decoded URL must appear **verbatim** in Allowed Callback URLs. Auth0 performs an exact string match.

Common discrepancies:
| Dashboard URL | SDK-generated URL | Problem |
|---------------|-------------------|---------|
| `https://your-tenant.auth0.com/...` | `com.example.app://your-tenant.auth0.com/...` | Scheme mismatch — native apps use the app scheme, not HTTPS |
| `com.example.app://your-tenant.auth0.com/ios/com.Example.App/callback` | `com.example.app://your-tenant.auth0.com/ios/com.example.app/callback` | Case mismatch in bundle ID |
| URL has trailing slash | URL has no trailing slash | Trailing slash mismatch |
| `com.example.app://your-tenant.auth0.com/android/com.example.app/callback` | `com.example.app://your-tenant.auth0.com/android/com.example.app/callback ` | Invisible trailing space in dashboard |

**Step 3:** Add the exact URL to the dashboard and save.

---

## Browser Opens But App Never Receives Callback {#deep-link-not-working}

### Symptom
- Universal Login page loads, user completes authentication, but the browser tab stays open or the user is returned to the browser instead of the app

### Android Root Causes

1. **Missing or incorrect intent-filter** — The `RedirectActivity` intent-filter's `android:host`, `android:pathPrefix`, or `android:scheme` does not match the callback URL. See [Android Checklist → Intent-Filter](android-checklist.md#intent-filter).

2. **`android:exported` missing** — Required since Android 12 (API 31). The merged manifest must have `android:exported="true"` on `RedirectActivity`.

3. **Multiple apps with the same scheme** — Another app on the device claims the same URL scheme.

4. **Chrome Custom Tabs not resolving to the app** — Ensure the device is not in an unusual browser mode.

### iOS Root Causes

1. **URL scheme not declared in Info.plist** — See [Swift Checklist → URL Scheme](swift-checklist.md#url-scheme).

2. **`WebAuthentication.resume(with:)` not called** — The AppDelegate or SwiftUI `.onOpenURL` handler is missing or not reachable. See [Swift Checklist → AppDelegate](swift-checklist.md#appdelegate).

3. **Universal Links: AASA file not reachable or incorrect** — Verify the AASA file:
   ```bash
   curl -I https://your-tenant.auth0.com/.well-known/apple-app-site-association
   ```
   Must return `200 OK` with `Content-Type: application/json`.

4. **Universal Links: testing on Simulator** — Universal Links require a physical device.

---

## Token Errors {#token-errors}

### `invalid_grant`

| Scenario | Fix |
|----------|-----|
| Refresh token was rotated and the old one was reused | Ensure you are storing the new refresh token returned after each refresh. If using `CredentialsManager` (iOS) or `CredentialsManager` (Android), this is automatic. |
| Refresh token was revoked from the dashboard | Generate a new login flow |
| Clock skew between device and Auth0 servers | Sync device time; check `iat` / `exp` claims in the ID token |

### `access_denied` {#access-denied}

| Scenario | Fix |
|----------|-----|
| The Connection is not enabled for this Application | Dashboard → Application → Connections tab — ensure the connection (e.g., "Username-Password-Authentication", "google-oauth2") is toggled on |
| User does not have permission for the requested audience | Check API authorization policies in Auth0 Dashboard |
| MFA policy requires MFA but it is not set up | Prompt user to enroll in MFA |

### `unauthorized_client`

| Scenario | Fix |
|----------|-----|
| `Authorization Code` grant type not enabled | Dashboard → Application → Advanced Settings → Grant Types → enable Authorization Code |
| `Refresh Token` grant type not enabled | Dashboard → Application → Advanced Settings → Grant Types → enable Refresh Token |
| Application Type is not Native | Change Application Type to Native |

---

## Silent Auth / Token Refresh Failures {#silent-auth}

### Symptom
- `CredentialsManager.credentials()` always triggers a new login instead of silently refreshing
- Refresh token is null or expired immediately

### Root Causes & Fixes

1. **`offline_access` scope not requested at login**
   - Fix: Add `offline_access` to the scope in your login call. Without it, Auth0 does not issue a refresh token.

2. **Refresh Token Rotation enabled but old tokens not discarded**
   - Fix: After every token refresh, store the entire new `Credentials` object. The old refresh token is immediately invalidated.

3. **Refresh Token Expiry too short**
   - Fix: Dashboard → APIs → Settings → Token Settings → Refresh Token Expiration. Extend the idle/absolute expiry as needed.

4. **Absolute refresh token expiry reached**
   - Expected behavior — user must re-authenticate. Handle this in your UI.

---

## Network / Connectivity Errors {#network-errors}

### Android: `NetworkErrorException` or `SocketTimeoutException`

**Checklist:**
- `INTERNET` permission in `AndroidManifest.xml` — see [Android Checklist → Permissions](android-checklist.md#permissions)
- Emulator has internet access — test by opening a browser in the emulator
- No proxy or VPN blocking HTTPS to `*.auth0.com`
- `android:usesCleartextTraffic` restrictions are not inadvertently blocking requests

### iOS: `NSURLErrorDomain` / `CFNetworkErrors`

**Checklist:**
- App Transport Security (ATS) is not blocking HTTPS to `*.auth0.com` — Auth0 uses HTTPS so ATS should not be an issue, but check for custom `NSAppTransportSecurity` entries in `Info.plist`
- Simulator has internet access
- VPN or corporate network proxy is not intercepting Auth0 traffic

---

## App Type Misconfiguration

### Symptom
- Token exchange works but `id_token` or `access_token` is missing or malformed
- Browser login works but tokens cannot be used with Auth0 APIs
- PKCE flow not being used

### Root Cause
Application is set to **SPA** or **Regular Web App** instead of **Native**.

### Fix
Dashboard → Application → Settings → Application Type → change to **Native** → save.

PKCE (Proof Key for Code Exchange) is automatically enforced for Native apps. SPAs also use PKCE, but Regular Web Apps use a different flow (client secret + authorization code without PKCE), which is not appropriate for mobile.

---

## iOS-Specific: Auth0.plist Not Found

### Symptom
```
Auth0.swift fatal error: Auth0.plist file not found in the main bundle
```

### Root Cause
`Auth0.plist` is either:
- Not added to the app target (only the test target)
- Named incorrectly (e.g., `auth0.plist` — wrong case)
- Located in a subdirectory instead of the target root

### Fix
In Xcode:
1. Select `Auth0.plist` in the Project Navigator
2. Open the File Inspector (right panel)
3. Under **Target Membership**, ensure your **app target** is checked (not only the test target)

---

## iOS-Specific: Keychain Access Denied {#keychain}

### Symptom
```
OSStatus error -34018 (errSecMissingEntitlement)
```
or Keychain operations silently fail.

### Root Cause
The app is not signed with a provisioning profile that includes the correct Keychain entitlements, or the Keychain Sharing group is misconfigured.

### Fix
1. In Xcode: **Target → Signing & Capabilities** — ensure the provisioning profile is valid.
2. If using Keychain Sharing across extensions: ensure the access group is consistent across all targets.
3. Clean build folder and rebuild with a freshly downloaded provisioning profile.

---

## Android-Specific: ProGuard / R8 Stripping SDK Classes

### Symptom
- Works in debug builds, crashes or fails silently in release builds
- `ClassNotFoundException` or `NoSuchMethodException` at runtime in release

### Root Cause
ProGuard/R8 is removing or obfuscating Auth0 SDK classes.

### Fix
Add to `proguard-rules.pro`:

```
-keep class com.auth0.android.** { *; }
-keepnames class com.auth0.android.** { *; }
-dontwarn com.auth0.android.**
```

See [Android Checklist → ProGuard](android-checklist.md#proguard).

---

## Collecting Information for ESD / GitHub Issue

Before opening a ticket, include all of the following:

1. **SDK name and version** (e.g., `auth0-android:2.11.0` or `Auth0.swift:2.7.0`)
2. **Platform OS version** (e.g., Android 14 / iOS 17.4)
3. **Device type** (physical or emulator/simulator, model)
4. **Auth0 tenant region** (US / EU / AU — visible in the tenant domain)
5. **Application Type** in the dashboard (Native / SPA / Regular Web App)
6. **Full verbose SDK log output** for the failing flow
7. **Exact error code and description** from the SDK callback
8. **Callback URL registered in dashboard** (full URL)
9. **Callback URL the SDK is constructing** (from logs)
10. **Steps already tried** from this checklist

Use the diagnostic summary template in the main [SKILL.md](../SKILL.md#phase-4--pre-ticket-diagnostic-summary).
