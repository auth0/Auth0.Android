# Migration Guide from SDK v3 to v4

> **Note:** This guide is actively maintained during the v4 development phase. As new changes are merged, this document will be updated to reflect the latest breaking changes and migration steps.

v4 of the Auth0 Android SDK includes significant build toolchain updates, updated default values for better out-of-the-box behavior, and behavior changes to simplify credential management. This guide documents the changes required when migrating from v3 to v4.

---

## Table of Contents

- [**Requirements Changes**](#requirements-changes)
  + [Java Version](#java-version)
  + [Gradle and Android Gradle Plugin](#gradle-and-android-gradle-plugin)
  + [Kotlin Version](#kotlin-version)
- [**Breaking Changes**](#breaking-changes)
  + [Classes Removed](#classes-removed)
  + [DPoP Configuration Moved to Builder](#dpop-configuration-moved-to-builder)
- [**Default Values Changed**](#default-values-changed)
  + [Credentials Manager minTTL](#credentials-manager-minttl)
- [**Behavior Changes**](#behavior-changes)
  + [clearCredentials() Now Clears All Storage](#clearCredentials-now-clears-all-storage)
  + [Storage Interface: New removeAll() Method](#storage-interface-new-removeall-method)
- [**Dependency Changes**](#dependency-changes)
  + [Gson 2.8.9 → 2.11.0](#️-gson-289--2110-transitive-dependency)
  + [DefaultClient.Builder](#defaultclientbuilder)

---

## Requirements Changes

### Java Version

v4 requires **Java 17** or later (previously Java 8+).

Update your `build.gradle` to target Java 17:

```groovy
android {
    compileOptions {
        sourceCompatibility JavaVersion.VERSION_17
        targetCompatibility JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = '17'
    }
}
```

### Gradle and Android Gradle Plugin

v4 requires:

- **Gradle**: 8.11.1 or later
- **Android Gradle Plugin (AGP)**: 8.10.1 or later

Update your `gradle/wrapper/gradle-wrapper.properties`:

```properties
distributionUrl=https\://services.gradle.org/distributions/gradle-8.11.1-all.zip
```

Update your root `build.gradle`:

```groovy
buildscript {
    dependencies {
        classpath 'com.android.tools.build:gradle:8.10.1'
    }
}
```

### Kotlin Version

v4 uses **Kotlin 2.0.21**. If you're using Kotlin in your project, you may need to update your
Kotlin version to ensure compatibility.

```groovy
buildscript {
    ext.kotlin_version = "2.0.21"
}
```

## Breaking Changes

### Classes Removed

- The `com.auth0.android.provider.PasskeyAuthProvider` class has been removed. Use the APIs from
  the [AuthenticationAPIClient](auth0/src/main/java/com/auth0/android/authentication/AuthenticationAPIClient.kt)
  class for passkey operations:
    - [passkeyChallenge()](auth0/src/main/java/com/auth0/android/authentication/AuthenticationAPIClient.kt#L366-L387) -
      Request a challenge to initiate passkey login flow
    - [signinWithPasskey()](auth0/src/main/java/com/auth0/android/authentication/AuthenticationAPIClient.kt#L235-L253) -
      Sign in a user using passkeys
    - [signupWithPasskey()](auth0/src/main/java/com/auth0/android/authentication/AuthenticationAPIClient.kt#L319-L344) -
      Sign up a user and returns a challenge for key generation

### DPoP Configuration Moved to Builder

The `useDPoP(context: Context)` method has been moved from the `WebAuthProvider` object to the login
`Builder` class. This change allows DPoP to be configured per-request instead of globally.

**v3 (global configuration — no longer supported):**

```kotlin
// ❌ This no longer works
WebAuthProvider
    .useDPoP(context)
    .login(account)
    .start(context, callback)
```

**v4 (builder-based configuration — required):**

```kotlin
// ✅ Use this instead
WebAuthProvider
    .login(account)
    .useDPoP(context)
    .start(context, callback)
```

This change ensures that DPoP configuration is scoped to individual login requests rather than
persisting across the entire application lifecycle.

## Default Values Changed

### Credentials Manager `minTTL`

**Change:** The default `minTtl` value changed from `0` to `60` seconds.

This change affects the following Credentials Manager methods:

- `getCredentials(callback)` / `awaitCredentials()`
- `getCredentials(scope, minTtl, callback)` / `awaitCredentials(scope, minTtl)`
- `getCredentials(scope, minTtl, parameters, callback)` / `awaitCredentials(scope, minTtl, parameters)`
- `getCredentials(scope, minTtl, parameters, forceRefresh, callback)` / `awaitCredentials(scope, minTtl, parameters, forceRefresh)`
- `getCredentials(scope, minTtl, parameters, headers, forceRefresh, callback)` / `awaitCredentials(scope, minTtl, parameters, headers, forceRefresh)`
- `hasValidCredentials()`

**Impact:** Credentials will be renewed if they expire within 60 seconds, instead of only when already expired.

<details>
  <summary>Migration example</summary>

```kotlin
// v3 - minTtl defaulted to 0, had to be set explicitly
credentialsManager.getCredentials(scope = null, minTtl = 60, callback = callback)

// v4 - minTtl defaults to 60 seconds
credentialsManager.getCredentials(callback)

// v4 - use 0 to restore v3 behavior
credentialsManager.getCredentials(scope = null, minTtl = 0, callback = callback)
```
</details>

**Reason:** A `minTtl` of `0` meant credentials were not renewed until expired, which could result in delivering access tokens that expire immediately after retrieval, causing subsequent API requests to fail. Setting a default value of `60` seconds ensures the access token remains valid for a reasonable period.

## Behavior Changes

### `clearCredentials()` Now Clears All Storage

**Change:** `clearCredentials()` now calls `Storage.removeAll()` instead of removing individual credential keys.

In v3, `clearCredentials()` removed only specific credential keys (access token, refresh token, ID token, etc.) from the underlying `Storage`.

In v4, `clearCredentials()` calls `Storage.removeAll()`, which clears **all** values in the storage — including any API credentials stored for specific audiences.

**Impact:** If you need to remove only the primary credentials while preserving other stored data, consider using a separate `Storage` instance for API credentials.

**Reason:** This simplifies credential cleanup and ensures no stale data remains in storage after logout. It aligns the behavior with the Swift SDK's `clear()` method, which also clears all stored values.

### `Storage` Interface: New `removeAll()` Method

**Change:** The `Storage` interface now includes a `removeAll()` method with a default empty implementation.

**Impact:** Existing custom `Storage` implementations will continue to compile and work without changes. Override `removeAll()` to provide the actual clearing behavior if your custom storage is used with `clearCredentials()`.

## Dependency Changes

### ⚠️ Gson 2.8.9 → 2.11.0 (Transitive Dependency)

v4 updates the internal Gson dependency from **2.8.9** to **2.11.0**. While the SDK does not expose
Gson types in its public API, Gson is included as a transitive runtime dependency. If your app also
uses Gson, be aware of the following changes introduced in Gson 2.10+:

- **`TypeToken` with unresolved type variables is rejected at runtime.** Code like
  `object : TypeToken<List<T>>() {}` (where `T` is a generic parameter) will throw
  `IllegalArgumentException`. Use Kotlin `reified` type parameters or pass concrete types instead.
- **Strict type coercion is enforced.** Gson no longer silently coerces JSON objects or arrays to
  `String`. If your code relies on this behavior, you will see `JsonSyntaxException`.
- **Built-in ProGuard/R8 rules are included.** Gson 2.11.0 ships its own keep rules, so you may be
  able to remove custom Gson ProGuard rules from your project.

If you need to pin Gson to an older version, you can use Gradle's `resolutionStrategy`:

```groovy
configurations.all {
    resolutionStrategy.force 'com.google.code.gson:gson:2.8.9'
}
```

Alternatively, you can exclude Gson from the SDK entirely and provide your own version:

```groovy
implementation('com.auth0.android:auth0:<version>') {
    exclude group: 'com.google.code.gson', module: 'gson'
}
implementation 'com.google.code.gson:gson:2.8.9' // your preferred version
```

> **Note:** Pinning or excluding is not recommended long-term, as the SDK has been tested and
> validated against Gson 2.11.0.

### DefaultClient.Builder

v4 introduces a `DefaultClient.Builder` for configuring the HTTP client. This replaces the
constructor-based approach with a more flexible builder pattern that supports additional options
such as write/call timeouts, custom interceptors, and custom loggers.

**v3 (constructor-based — deprecated):**

```kotlin
// ⚠️ Deprecated: still compiles but shows a warning
val client = DefaultClient(
    connectTimeout = 30,
    readTimeout = 30,
    enableLogging = true
)
```

**v4 (builder pattern — recommended):**

```kotlin
val client = DefaultClient.Builder()
    .connectTimeout(30)
    .readTimeout(30)
    .writeTimeout(30)
    .callTimeout(120)
    .enableLogging(true)
    .build()
```

The legacy constructor is deprecated but **not removed** — existing code will continue to compile
and run. Your IDE will show a deprecation warning with a suggested `ReplaceWith` quick-fix to
migrate to the Builder.

## Getting Help

If you encounter issues during migration:

- [GitHub Issues](https://github.com/auth0/Auth0.Android/issues) - Report bugs or ask questions
- [Auth0 Community](https://community.auth0.com/) - Community support