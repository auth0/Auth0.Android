# Android SDK Validation Checklist

Use this checklist to verify every layer of an Auth0 Android integration before raising a support ticket. Work through each section in order.

---

## 1. Gradle Configuration {#gradle}

### `build.gradle` (project-level)
Confirm `mavenCentral()` is in the repositories block (required for auth0-android ≥ 2.x):

```groovy
// settings.gradle (Gradle 7+) or build.gradle (older)
dependencyResolutionManagement {
    repositories {
        mavenCentral()
        google()
    }
}
```

### `build.gradle` (app module)

```groovy
android {
    defaultConfig {
        // Must be 21 or higher
        minSdk 21

        // auth0Scheme and auth0Domain are used by the intent-filter via manifestPlaceholders
        manifestPlaceholders = [
            auth0Domain: "@string/com_auth0_domain",
            auth0Scheme: "${applicationId}"
        ]
    }
}

dependencies {
    // Use the latest stable version — check https://github.com/auth0/Auth0.Android/releases
    implementation 'com.auth0.android:auth0:2.+'
}
```

**Checklist:**
- [ ] `minSdk` is `21` or higher
- [ ] `com.auth0.android:auth0` dependency is present
- [ ] `manifestPlaceholders` declares `auth0Domain` and `auth0Scheme` (if using the default intent-filter approach)
- [ ] Dependency version is not pinned to a very old release (check latest on Maven Central)

---

## 2. Permissions {#permissions}

Open `app/src/main/AndroidManifest.xml` and confirm:

```xml
<manifest ...>
    <!-- Required: allows SDK to reach Auth0 endpoints -->
    <uses-permission android:name="android.permission.INTERNET" />
    ...
</manifest>
```

**Checklist:**
- [ ] `INTERNET` permission is declared at the top level of the manifest, outside `<application>`
- [ ] No `android:usesCleartextTraffic="false"` that would block HTTP (Auth0 uses HTTPS, but this can cause unexpected issues)

---

## 3. Intent-Filter / RedirectActivity {#intent-filter}

The SDK needs to handle the callback from the browser after login. There are two approaches:

### Approach A — Default `manifestPlaceholders` (Recommended)

The SDK's manifest merge will automatically insert the correct intent-filter if `manifestPlaceholders` is set (see Section 1). Verify the merged manifest:

```
Build → Analyze APK → AndroidManifest.xml
```

Look for an activity like:

```xml
<activity
    android:name="com.auth0.android.provider.RedirectActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data
            android:host="YOUR_TENANT.auth0.com"
            android:pathPrefix="/android/com.your.package/callback"
            android:scheme="com.your.package" />
    </intent-filter>
</activity>
```

### Approach B — Custom Declaration

If you override the intent-filter manually, ensure all of the following are correct:

```xml
<activity
    android:name="com.auth0.android.provider.RedirectActivity"
    android:exported="true"
    tools:node="replace">
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data
            android:host="${auth0Domain}"
            android:pathPrefix="/android/${applicationId}/callback"
            android:scheme="${auth0Scheme}" />
    </intent-filter>
</activity>
```

**Checklist:**
- [ ] `android:exported="true"` is present (required for Android 12+)
- [ ] `android:host` matches your Auth0 domain exactly (e.g. `your-tenant.auth0.com`)
- [ ] `android:pathPrefix` is `/android/{applicationId}/callback`
- [ ] `android:scheme` matches your application ID (package name)
- [ ] The `<action>`, `<category android:name="DEFAULT">`, and `<category android:name="BROWSABLE">` are all present

### Constructing the Expected Callback URL

The URL the SDK sends to Auth0 is built as:

```
{scheme}://{auth0Domain}/android/{packageName}/callback
```

Example: `com.example.myapp://your-tenant.auth0.com/android/com.example.myapp/callback`

**This URL must be listed verbatim in Auth0 Dashboard → Application → Allowed Callback URLs.**

---

## 4. Auth0 Credentials in Code {#credentials}

### Recommended: String Resources

`app/src/main/res/values/strings.xml`:

```xml
<resources>
    <string name="com_auth0_domain">your-tenant.auth0.com</string>
    <string name="com_auth0_client_id">YOUR_CLIENT_ID</string>
</resources>
```

Usage:

```kotlin
val account = Auth0(
    getString(R.string.com_auth0_client_id),
    getString(R.string.com_auth0_domain)
)
```

**Checklist:**
- [ ] Domain does **not** include `https://` prefix
- [ ] Domain does **not** have a trailing slash
- [ ] Client ID matches the value in Auth0 Dashboard exactly
- [ ] Secrets are not hardcoded in source-controlled files (use `local.properties` or environment injection for CI)

---

## 5. Authentication Call {#auth-call}

A minimal login call:

```kotlin
WebAuthProvider.login(account)
    .withScheme(getString(R.string.com_auth0_scheme))  // matches android:scheme in manifest
    .withScope("openid profile email offline_access")
    .start(this, object : Callback<Credentials, AuthenticationException> {
        override fun onSuccess(result: Credentials) {
            // Handle success
        }
        override fun onFailure(error: AuthenticationException) {
            Log.e("Auth0", "Login failed: ${error.getCode()} — ${error.getDescription()}")
        }
    })
```

**Checklist:**
- [ ] `withScheme()` matches `android:scheme` in the intent-filter (typically `applicationId`)
- [ ] `offline_access` scope is included if refresh tokens are required
- [ ] Error handler logs both `getCode()` and `getDescription()`

---

## 6. Logout Call {#logout-call}

```kotlin
WebAuthProvider.logout(account)
    .withScheme(getString(R.string.com_auth0_scheme))
    .start(this, object : Callback<Void?, AuthenticationException> {
        override fun onSuccess(result: Void?) {
            // Handle success
        }
        override fun onFailure(error: AuthenticationException) {
            Log.e("Auth0", "Logout failed: ${error.getCode()} — ${error.getDescription()}")
        }
    })
```

The logout return URL (`returnTo`) must be registered in **Auth0 Dashboard → Allowed Logout URLs**. The format is the same as the callback URL:

```
{scheme}://{auth0Domain}/android/{packageName}/callback
```

**Checklist:**
- [ ] Allowed Logout URL in dashboard matches the value the SDK sends
- [ ] `withScheme()` is the same value used in login

---

## 7. Credentials Manager (Token Storage) {#credentials-manager}

If you are using `CredentialsManager` or `SecureCredentialsManager`:

```kotlin
val credentialsManager = CredentialsManager(authenticationAPIClient, storage)
// or
val secureCredentialsManager = SecureCredentialsManager(context, authenticationAPIClient, storage)
```

**Checklist:**
- [ ] `offline_access` scope was requested during login (required for token refresh)
- [ ] Refresh token rotation is configured consistently between the dashboard and SDK
- [ ] If using `SecureCredentialsManager`, the device has a secure lock screen set up (required for biometric prompt)
- [ ] Token expiry is handled — `getCredentials()` will auto-refresh if a valid refresh token is available

---

## 8. ProGuard / R8 Rules {#proguard}

If your release build uses code shrinking, add these rules to `proguard-rules.pro`:

```
-keep class com.auth0.android.** { *; }
-keepnames class com.auth0.android.** { *; }
-dontwarn com.auth0.android.**
```

**Checklist:**
- [ ] ProGuard/R8 rules are added for release builds
- [ ] Issue does not only reproduce in release builds while debug builds work (classic ProGuard symptom)

---

## 9. Network & Emulator Considerations {#network}

**Checklist:**
- [ ] Emulator has internet connectivity (test with a browser in the emulator)
- [ ] Emulator is not using a proxy that blocks outbound HTTPS to `*.auth0.com`
- [ ] Auth0 tenant is not in a region that the device/emulator can't reach (check tenant region in dashboard URL: `manage.auth0.com` vs regional endpoints)
- [ ] Custom domain is set up correctly if applicable

---

## 10. Version Compatibility Matrix

| auth0-android | Min SDK | Min AGP | Notes |
|---------------|---------|---------|-------|
| 2.x           | 21      | 7.0     | Current major version |
| 1.x           | 21      | —       | Legacy, no longer maintained |

- Always use the latest `2.x` release.
- Check the [releases page](https://github.com/auth0/Auth0.Android/releases) for any breaking changes.

---

## Quick Callback URL Builder

Fill in the blanks and paste the result into Auth0 Dashboard → Allowed Callback URLs:

```
Scheme      : {applicationId}         e.g. com.example.myapp
Domain      : {auth0Domain}           e.g. your-tenant.auth0.com
Package     : {applicationId}         e.g. com.example.myapp

Callback URL: {scheme}://{domain}/android/{package}/callback
Example     : com.example.myapp://your-tenant.auth0.com/android/com.example.myapp/callback
```
