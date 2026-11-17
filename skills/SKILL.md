---
name: auth0-android
description: >-
  Use when adding Auth0 authentication to a native Android app (Kotlin or Java)
  with the com.auth0.android:auth0 SDK: Gradle install, manifest placeholders and
  callback URLs, WebAuthProvider login and logout, storing and refreshing tokens
  with SecureCredentialsManager (including biometric protection), database
  login, signup, passwordless, password reset, Custom Tabs, error handling, and
  unit testing. Entry point for all Auth0.Android skills; use it even if the user
  only says "add login to my Android app".
metadata:
  type: core
  library: Auth0.Android
  library_version: 4.3.1
---

# Auth0.Android

Native Android authentication with `com.auth0.android:auth0` (v4, `minSdk` 26, Java 17).

These skills are not packaged in the AAR. Read them from the GitHub repo: `skills/` in [auth0/Auth0.Android](https://github.com/auth0/Auth0.Android/tree/main/skills). Deeper docs live in the same repo: [`EXAMPLES.md`](https://github.com/auth0/Auth0.Android/blob/main/EXAMPLES.md) indexes `examples/*.md` (one file per feature, Kotlin and Java). Raw URLs work too: `https://raw.githubusercontent.com/auth0/Auth0.Android/main/examples/<file>.md`.

## Sub-skills

| Task | Sub-skill |
|------|-----------|
| `mfa_required` handling, enroll, challenge, verify with `MfaApiClient` | [mfa/SKILL.md](./mfa/SKILL.md) |
| Passkey sign-in, signup, and enrollment with Credential Manager | [passkeys/SKILL.md](./passkeys/SKILL.md) |
| Organization login, invitations, reading `org_id` | [organizations/SKILL.md](./organizations/SKILL.md) |
| Exchange an external token for Auth0 tokens | [custom-token-exchange/SKILL.md](./custom-token-exchange/SKILL.md) |

For DPoP, My Account API, Native to Web SSO, PAR, Auth Tab and other features, see the matching file under `examples/` (linked from `EXAMPLES.md`).

## Prerequisites

- Android `minSdk` 26+ and Java 17 (apps below API 26 must stay on the v3 line)
- An Auth0 application of type **Native**

## Quick Start

### 1. Install

```groovy
// app/build.gradle
android {
    compileOptions {
        sourceCompatibility JavaVersion.VERSION_17
        targetCompatibility JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = '17' }
}

dependencies {
    implementation 'com.auth0.android:auth0:4.3.1'
}
```

Check [Releases](https://github.com/auth0/Auth0.Android/releases) for the latest version.

### 2. Configure the manifest

```xml
<uses-permission android:name="android.permission.INTERNET" />
```

```groovy
// app/build.gradle, inside android { defaultConfig { ... } }
manifestPlaceholders = [auth0Domain: "@string/com_auth0_domain", auth0Scheme: "https"]
```

`auth0Domain` and `auth0Scheme` are required: the library uses them to register the redirect intent-filter. `auth0Scheme` is `https` (Android App Links) or a lowercase custom scheme.

In the Auth0 Dashboard, add this URL to both **Allowed Callback URLs** and **Allowed Logout URLs**:

```
https://{YOUR_AUTH0_DOMAIN}/android/{YOUR_APP_PACKAGE_NAME}/callback
```

`{YOUR_APP_PACKAGE_NAME}` is the `applicationId`. With a custom scheme, replace `https` with it.

### 3. Create the Auth0 instance

```xml
<!-- res/values/strings.xml -->
<string name="com_auth0_client_id">YOUR_CLIENT_ID</string>
<string name="com_auth0_domain">YOUR_DOMAIN</string>
```

```kotlin
val account = Auth0.getInstance(context)
// or: Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN")
```

`getInstance(context)` throws `IllegalArgumentException` if either string resource is missing.

### 4. Log in and log out

```kotlin
WebAuthProvider.login(account)
    .withScope("openid profile email offline_access")
    .start(this, object : Callback<Credentials, AuthenticationException> {
        override fun onSuccess(result: Credentials) {
            credentialsManager.saveCredentials(result)
        }

        override fun onFailure(error: AuthenticationException) {
            when {
                error.isAuthenticationCanceled -> { /* user closed the browser */ }
                error.isBrowserAppNotAvailable -> { /* no browser installed */ }
                else -> { /* inspect error.getCode() / error.getDescription() */ }
            }
        }
    })

WebAuthProvider.logout(account)
    .start(this, object : Callback<Void?, AuthenticationException> {
        override fun onSuccess(result: Void?) {
            credentialsManager.clearCredentials()
        }

        override fun onFailure(error: AuthenticationException) { }
    })
```

Coroutines: `WebAuthProvider.login(account).await(context)` returns `Credentials` and `WebAuthProvider.logout(account).await(context)` returns `Unit`; both throw `AuthenticationException`.

Builder options on `login`: `withScope`, `withAudience`, `withConnection`, `withConnectionScope`, `withOrganization`, `withInvitationUrl`, `withParameters` (for example `mapOf("prompt" to "login")`), `withScheme`, `withRedirectUri`, `withCustomTabsOptions`, `withEphemeralBrowsing`, `withTrustedWebActivity`, `withAuthTab`, `withMaxAge`, `withNonce`, `withState`. The default scope is `openid profile email`; `openid` is always enforced. Details: [`examples/web-auth-configuration.md`](https://github.com/auth0/Auth0.Android/blob/main/examples/web-auth-configuration.md).

Use a custom scheme only if you did not set `auth0Scheme` to `https`: set the placeholder, add the callback URL in the Dashboard, and call `.withScheme("myapp")` on both `login` and `logout`.

### 5. Store and use credentials

```kotlin
val apiClient = AuthenticationAPIClient(account)
val storage = SharedPreferencesStorage(context)
val credentialsManager = SecureCredentialsManager(apiClient, context, storage)

credentialsManager.saveCredentials(credentials)

if (credentialsManager.hasValidCredentials()) {
    credentialsManager.getCredentials(object : Callback<Credentials, CredentialsManagerException> {
        override fun onSuccess(result: Credentials) {
            val accessToken = result.accessToken // refreshed automatically if expired
        }

        override fun onFailure(error: CredentialsManagerException) {
            when (error) {
                CredentialsManagerException.NO_CREDENTIALS,
                CredentialsManagerException.NO_REFRESH_TOKEN,
                CredentialsManagerException.RENEW_FAILED -> { /* send the user to login */ }
                else -> { /* see examples/credentials-manager.md */ }
            }
        }
    })
}
```

Coroutines: `credentialsManager.awaitCredentials()` throws `CredentialsManagerException`. Refresh needs a refresh token, so request `offline_access`. `CredentialsManager(apiClient, storage)` stores without encryption; prefer `SecureCredentialsManager`. In v4, `clearCredentials()` calls `Storage.removeAll()`, so it wipes everything in that storage, API credentials included; use a dedicated storage name if you share it. Full reference: [`examples/credentials-manager.md`](https://github.com/auth0/Auth0.Android/blob/main/examples/credentials-manager.md).

`CredentialsManagerException` has no string `code`. Compare against its companion constants (`NO_CREDENTIALS`, `NO_REFRESH_TOKEN`, `RENEW_FAILED`, `STORE_FAILED`, `DPOP_KEY_MISSING`, `SESSION_EXPIRED`, the `BIOMETRIC_*` family, and so on). `isDeviceIncompatible` is true on devices missing required crypto algorithms.

### 6. Call an API

Request the API audience at login with `.withAudience("https://api.example.com")`, then attach `credentials.accessToken` as `Authorization: Bearer <token>`. For a different audience later, use `getApiCredentials` / `awaitApiCredentials(audience, scope)`, which exchange the refresh token.

## Biometric-protected credentials

Pass a `FragmentActivity` and `LocalAuthenticationOptions`:

```kotlin
val options = LocalAuthenticationOptions.Builder()
    .setTitle("Authenticate")
    .setDescription("Access your credentials")
    .setAuthenticationLevel(AuthenticationLevel.STRONG)
    .setNegativeButtonText("Cancel")
    .setDeviceCredentialFallback(false)
    .setPolicy(BiometricPolicy.Session(300))
    .build()

val credentialsManager = SecureCredentialsManager(apiClient, context, storage, fragmentActivity, options)
```

- `setTitle` is required; `build()` throws without it.
- `AuthenticationLevel`: `STRONG`, `WEAK`, `DEVICE_CREDENTIAL`.
- `BiometricPolicy`: `Always` (default), `Session(timeoutInSeconds)`, `AppLifecycle(timeoutInSeconds = 3600)`. Call `clearBiometricSession()` to force a new prompt.
- `STRONG` with device-credential fallback is rejected on API 28 and 29, and `DEVICE_CREDENTIAL` alone needs API 30+. These surface as `BIOMETRIC_ERROR_*` exceptions.

## Direct authentication (`AuthenticationAPIClient`)

Direct calls skip the browser and do not validate the ID token unless you ask. Always chain `.validateClaims()` on requests that return `Credentials`.

```kotlin
val authentication = AuthenticationAPIClient(account)

// Database login
authentication.login("user@example.com", "password", "Username-Password-Authentication")
    .validateClaims()
    .setScope("openid profile email offline_access")
    .start(callback)

// Sign up (creates the user, then logs in)
authentication.signUp("user@example.com", "password", connection = "Username-Password-Authentication")
    .validateClaims()
    .start(callback)

// Reset password
authentication.resetPassword("user@example.com", "Username-Password-Authentication")
    .start(voidCallback)

// Passwordless email code: request, then log in
authentication.passwordlessWithEmail("user@example.com", PasswordlessType.CODE, "email")
    .start(voidCallback)
authentication.loginWithEmail("user@example.com", "123456", "email")
    .validateClaims()
    .start(callback)
```

- `signUp` returns a `SignUpRequest` that yields `Credentials`, not `Void`.
- Passwordless needs the **Passwordless OTP** grant type on the application. SMS: `passwordlessWithSMS` and `loginWithPhoneNumber`.
- If a login fails with `error.isMultifactorRequired`, continue with the [mfa](./mfa/SKILL.md) skill.
- Direct password login requires the **Password** grant type enabled on the application and the Native app type.

More: [`examples/authentication-api/`](https://github.com/auth0/Auth0.Android/tree/main/examples/authentication-api).

## Custom Tabs

```kotlin
val tabs = CustomTabsOptions.newBuilder()
    .withToolbarColor(R.color.toolbar)
    .showTitle(true)
    .build()

WebAuthProvider.login(account).withCustomTabsOptions(tabs).start(this, callback)
```

Other builder methods: `withBrowserPicker`, `withDisabledCustomTabsPackages`, and partial-sheet options (`withInitialHeight`, `withInitialWidth`, `withResizable`, `withToolbarCornerRadius`, `withSideSheetBreakpoint`, `withBackgroundInteractionEnabled`). See [`examples/custom-tabs-ui.md`](https://github.com/auth0/Auth0.Android/blob/main/examples/custom-tabs-ui.md).

## Error handling

`AuthenticationException` exposes `getCode()`, `getDescription()`, `statusCode`, and the flags `isNetworkError`, `isBrowserAppNotAvailable`, `isAuthenticationCanceled`, `isMultifactorRequired`, `isInvalidCredentials`, `isAccessDenied`, `isTooManyAttempts`, `isRefreshTokenDeleted`, `isPasswordNotStrongEnough`, `isIdTokenValidationError`. In Kotlin call `getCode()` and `getDescription()` as functions; `.code` does not compile. Descriptions are for debugging, not UI.

## Testing

Unit tests that touch the SDK can fail with `Method getMainLooper in android.os.Looper not mocked`. Use Robolectric, or a JUnit 4 rule that replaces `CommonThreadSwitcher` with a synchronous delegate. See [`examples/unit-testing.md`](https://github.com/auth0/Auth0.Android/blob/main/examples/unit-testing.md).

Manual checks: login and logout on a device, credentials survive an app restart, refresh works after the access token expires, cancelling the browser calls `onFailure` with `isAuthenticationCanceled`.

## Common Mistakes

| Mistake | Fix |
|---------|-----|
| Missing `auth0Domain` / `auth0Scheme` manifest placeholders | Add both to `defaultConfig`. The build fails or the redirect never returns to the app without them. |
| Callback URL not in Allowed Callback URLs and Allowed Logout URLs | Add `{scheme}://{domain}/android/{applicationId}/callback` to both fields. If it is missing the browser stays open. |
| Dashboard application type is not Native | Create a Native application. |
| Custom scheme with uppercase letters, or `withScheme` not matching the placeholder | Android schemes must be lowercase. Use the same value in the placeholder, Dashboard, and `withScheme`. |
| Missing `INTERNET` permission | Add `<uses-permission android:name="android.permission.INTERNET" />`. |
| Skipping `.validateClaims()` on `AuthenticationAPIClient` calls that return `Credentials` | Add it. `WebAuthProvider` validates the ID token for you; direct calls do not. |
| Passing `(context, apiClient, storage)` to the credentials manager | The order is `(apiClient, context, storage)`. |
| Reading `error.code` on `CredentialsManagerException`, or `credentials.claims` | Compare to `CredentialsManagerException.NO_CREDENTIALS` etc. Read claims from `credentials.user` (`getExtraInfo()` for custom claims). |
| No `offline_access` scope | Without a refresh token `getCredentials` cannot renew an expired access token. |
| Storing tokens in plain `SharedPreferences`, or logging them | Use `SecureCredentialsManager`. Never log tokens. |
| Login callback lost on rotation or process death | See [`examples/configuration-changes.md`](https://github.com/auth0/Auth0.Android/blob/main/examples/configuration-changes.md). |

## Troubleshooting

| Symptom | Cause and fix |
|---------|---------------|
| Browser opens but never returns to the app | Placeholders or callback URL do not match. Rebuild after changing placeholders. For `https`, the Auth0 domain must serve a valid Digital Asset Links file for your app signing certificate. |
| `isBrowserAppNotAvailable` | No Custom Tabs-capable browser. Install one or use another browser on the device. |
| "Invalid state" or login stuck after long idle | The authorization session was lost (process death, long delay). Start login again. |
| `getCredentials` fails with `NO_REFRESH_TOKEN` | Login did not request `offline_access`, or the refresh token was not issued. |
| `getCredentials` fails with `RENEW_FAILED` | Refresh token expired or revoked. Send the user to login. |
| `LARGE_MIN_TTL` | The requested `minTtl` exceeds the access token lifetime. Lower it or raise the API token expiration. |
| Credentials gone after a lock-screen change | Keystore keys were invalidated (`CRYPTO_EXCEPTION`). Log in again. |
| Release build crashes in the SDK | Proguard rules ship with the AAR. If you merge them manually, include `proguard-okio.pro`, `proguard-gson.pro` and `proguard-jetpack.pro` from the [proguard directory](https://github.com/auth0/Auth0.Android/tree/main/proguard). |

## Security

- Never put a client secret in the app. Native apps are public clients; `WebAuthProvider` uses PKCE automatically.
- Prefer `https` (App Links) over custom schemes, which can be impersonated.
- Store tokens only through `SecureCredentialsManager`; do not log access, ID, or refresh tokens.
- Prefer `AuthenticationLevel.STRONG` and an explicit `BiometricPolicy` when gating credentials behind biometrics.
- Consider DPoP to bind tokens to the device: [`examples/dpop.md`](https://github.com/auth0/Auth0.Android/blob/main/examples/dpop.md).

## Quick Reference

| Class | Purpose |
|-------|---------|
| `Auth0` | Holds client ID and domain |
| `WebAuthProvider` | Universal Login: `login`, `logout` |
| `AuthenticationAPIClient` | Direct API calls, `mfaClient`, passkeys, token exchange |
| `SecureCredentialsManager` / `CredentialsManager` | Store, refresh, and clear credentials |
| `LocalAuthenticationOptions`, `BiometricPolicy`, `AuthenticationLevel` | Biometric gating |
| `MyAccountAPIClient` | My Account API (authentication methods, passkey enrollment) |
| `Credentials` | `idToken`, `accessToken`, `refreshToken`, `expiresAt`, `scope`, `user` |
