# AI Agent Guidelines for Auth0.Android SDK

This document gives practical, codebase-accurate guidance for AI coding assistants working on Auth0.Android.

## Project Snapshot

Auth0.Android is a native Android SDK for authentication and authorization with Auth0, including:

- Web authentication via Universal Login and browser-based flows
- Direct authentication APIs (database, passwordless, token operations)
- Credential persistence and automatic renewal
- Secure credential storage with Android Keystore and biometrics
- Kotlin-first APIs with Java interoperability and coroutine support

## Repository Structure

```
Auth0.Android/
├── auth0/                                  # Main SDK library module
│   ├── src/main/java/com/auth0/android/
│   │   ├── authentication/                 # Authentication API client, grants, MFA, and storage
│   │   ├── callback/                       # Callback interfaces
│   │   ├── dpop/                           # DPoP proof-of-possession support
│   │   ├── myaccount/                      # My Account API client
│   │   ├── provider/                       # Browser authentication providers
│   │   ├── request/                        # Request abstractions
│   │   ├── result/                         # Response and error models
│   │   └── Auth0.kt                        # Main account/config entry point
│   └── src/test/                           # Unit tests (Robolectric/JUnit)
├── sample/                                 # Demo app module
├── .github/workflows/                      # CI and release workflows
├── gradle/versioning.gradle                # Version resolution from .version
├── gradle/maven-publish.gradle             # Maven publishing config
└── .version                                # SDK version source of truth
```

## Current Technical Baseline

Source of truth: `auth0/build.gradle`, `sample/build.gradle`, and root `build.gradle`.

- Minimum SDK: API 26
- Compile SDK: 36
- Target SDK: 36
- Java source/target compatibility: 17
- Kotlin JVM target: 17
- Kotlin Gradle plugin: 2.0.21
- Android Gradle Plugin: 8.10.1
- Kotlin explicit API mode: **strict** (`-Xexplicit-api=strict`) — all public declarations must have explicit visibility modifiers and return types

## Core Development Principles

1. Preserve dual async APIs when applicable:
   - Callback-based methods for Java/legacy consumers
   - Coroutine/suspend alternatives for Kotlin consumers
2. Follow existing builder-style ergonomics for browser auth flows.
3. Keep error handling typed and actionable:
   - `AuthenticationException`
   - `CredentialsManagerException`
   - Other `Auth0Exception` subclasses
4. Maintain backward compatibility for public SDK APIs unless the change is explicitly breaking and documented.
5. Do not weaken security defaults (PKCE, token handling, Keystore usage, DPoP behavior).

## Testing Expectations

### Required Coverage for Changes

- Add or update unit tests for each behavior change.
- Cover success and failure/error paths.
- Mock network and Android framework dependencies as needed.
- Keep tests deterministic (control time, threading, and async execution in tests).

### Current Test Stack

From `auth0/build.gradle`:

- JUnit 4 (`junit:junit:4.13.2`)
- Robolectric (`org.robolectric:robolectric:4.15.1`)
- Mockito Core + Mockito Kotlin
- Hamcrest
- MockWebServer + OkHttp TLS test helpers
- Awaitility
- Kotlin Coroutines Test
- Espresso Intents (for relevant Android interaction test cases)

### Commands

```bash
# Match current CI unit/lint pipeline
./gradlew testReleaseUnitTest jacocoTestReleaseUnitTestReport lintRelease --continue --console=plain

# Full lint (all variants)
./gradlew lint

# Build sample app
./gradlew sample:assembleDebug
```

## Common Task Playbooks

### Adding or Changing Authentication APIs

1. Implement request/client behavior under `auth0/src/main/java/com/auth0/android/`.
2. Ensure both callback and suspend usage remains coherent when relevant.
3. Add/update unit tests under `auth0/src/test/`.
4. Update public documentation/examples (`EXAMPLES.md`, `README.md`) for public API changes.

### Browser Authentication Changes

Primary files typically include:

- `provider/WebAuthProvider.kt`
- `provider/AuthenticationActivity.kt`
- `provider/OAuthManager.kt`
- PKCE and browser option helpers in `provider/`

### Credentials Storage Changes

Primary files typically include:

- `authentication/storage/CredentialsManager.kt`
- `authentication/storage/SecureCredentialsManager.kt`
- storage and crypto helper classes used by those managers

## Quick Integration Examples

Use these as reference snippets when implementing or reviewing code changes.

### Initialize Core Classes

```kotlin
val account = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN")
val authClient = AuthenticationAPIClient(account)

val storage = SharedPreferencesStorage(context)
val secureCredentialsManager = SecureCredentialsManager(context, account, storage)
```

### Trigger Web Auth Login and Logout

```kotlin
WebAuthProvider.login(account)
   .withScheme("https")
   .withScope("openid profile email")
   .start(activity, object : Callback<Credentials, AuthenticationException> {
      override fun onSuccess(result: Credentials) {
         // Save or use credentials
      }

      override fun onFailure(error: AuthenticationException) {
         // Handle cancellation, browser unavailable, or auth errors
      }
   })

WebAuthProvider.logout(account)
   .withScheme("https")
   .start(activity, object : Callback<Void?, AuthenticationException> {
      override fun onSuccess(result: Void?) {
         // Session cleared
      }

      override fun onFailure(error: AuthenticationException) {
         // Handle logout error
      }
   })
```

Coroutine style:

```kotlin
try {
   val credentials = WebAuthProvider.login(account)
      .withScheme("https")
      .await(activity)

   // Use credentials
} catch (e: AuthenticationException) {
   // Handle auth error
}
```

### Make Authentication API Calls

Database login:

```kotlin
authClient
   .login("user@example.com", "password", "Username-Password-Authentication")
   .validateClaims()
   .start(object : Callback<Credentials, AuthenticationException> {
      override fun onSuccess(result: Credentials) {
         secureCredentialsManager.saveCredentials(result)
      }

      override fun onFailure(error: AuthenticationException) {
         // Handle API auth errors
      }
   })
```

Get user profile:

```kotlin
authClient
   .userInfo("ACCESS_TOKEN")
   .start(object : Callback<UserProfile, AuthenticationException> {
      override fun onSuccess(result: UserProfile) {
         // Use profile
      }

      override fun onFailure(error: AuthenticationException) {
         // Handle API error
      }
   })
```

Coroutine style:

```kotlin
try {
   val credentials = authClient
      .login("user@example.com", "password", "Username-Password-Authentication")
      .validateClaims()
      .await()

   secureCredentialsManager.saveCredentials(credentials)

   val profile = authClient.userInfo(credentials.accessToken ?: "").await()
   // Use profile
} catch (e: AuthenticationException) {
   // Handle API/authentication errors
}
```

## Class Responsibilities and Where to Modify

Use this as a quick decision guide when implementing new features.

### Core Class Responsibilities

- `Auth0` (`Auth0.kt`)
   - SDK configuration entry point (client ID, domain, networking client).
   - Update when adding new global SDK configuration knobs.

- `AuthenticationAPIClient` (`authentication/AuthenticationAPIClient.kt`)
   - Direct Authentication API operations (login/signup/passwordless/token/user info/MFA entry points).
   - Update for new auth endpoints, grants, or request options.

- `WebAuthProvider` (`provider/WebAuthProvider.kt`)
   - Browser-based login/logout builder APIs and options.
   - Update when adding Web Auth options or flow behavior.

- `OAuthManager` (`provider/OAuthManager.kt`)
   - Internal browser flow orchestration, URL construction, state/PKCE interactions.
   - Update for protocol-level web auth flow changes.

- `AuthenticationActivity` (`provider/AuthenticationActivity.kt`)
   - Redirect handling and callback resume behavior for browser auth.
   - Update for redirect parsing, lifecycle, and result-delivery changes.

- `CredentialsManager` (`authentication/storage/CredentialsManager.kt`)
   - Token caching and refresh orchestration for non-biometric manager.
   - Update for refresh and credential lifecycle logic.

- `SecureCredentialsManager` (`authentication/storage/SecureCredentialsManager.kt`)
   - Encrypted credential storage, biometric/local authentication policy integration.
   - Update for secure storage behavior, biometric policy, and key handling.

- `SharedPreferencesStorage` (`authentication/storage/SharedPreferencesStorage.kt`)
   - Persistence adapter used by credentials managers.
   - Update only when changing storage key/value persistence mechanics.

- `MfaApiClient` (`authentication/mfa/MfaApiClient.kt`)
   - MFA operations: list authenticators, enroll, challenge, and verify.
   - Update when adding new MFA factor types or verification flows.

- `MyAccountAPIClient` (`myaccount/MyAccountAPIClient.kt`)
   - My Account API operations (passkey enrollment, authentication method management).
   - Update when adding new self-service account management capabilities.

- `DPoP` and `DPoPKeyStore` (`dpop/`)
   - DPoP proof generation, key pair management, and header construction.
   - Update for DPoP protocol changes, key lifecycle, or nonce handling.

- `AuthenticationException` and `CredentialsManagerException`
   - Typed error surfaces for API/storage failures.
   - Update when introducing new error conditions or mappings.

### Feature-to-Class Mapping

- New Authentication API capability:
   - Start in `authentication/AuthenticationAPIClient.kt`
   - Add/update request models under `request/`
   - Add/update result/error models under `result/`

- New Web Auth builder option:
   - Start in `provider/WebAuthProvider.kt`
   - If flow internals change, also update `provider/OAuthManager.kt`

- Browser callback/redirect behavior change:
   - Start in `provider/AuthenticationActivity.kt`
   - Validate interactions with `provider/WebAuthProvider.kt`

- Credential save/load/refresh behavior change:
   - Start in `authentication/storage/CredentialsManager.kt`
   - Mirror secure variant behavior in `authentication/storage/SecureCredentialsManager.kt` when applicable

- Biometric or local-auth policy change:
   - Start in `authentication/storage/SecureCredentialsManager.kt`
   - Update related local-auth option/policy classes in `authentication/storage/` as needed

- New MFA factor or verification flow:
   - Start in `authentication/mfa/MfaApiClient.kt`
   - Add/update MFA-specific models and exceptions in `authentication/mfa/`

- New My Account API capability:
   - Start in `myaccount/MyAccountAPIClient.kt`
   - Add/update result models and exceptions in `myaccount/`

- DPoP behavior or key management change:
   - Start in `dpop/DPoP.kt` or `dpop/DPoPKeyStore.kt`
   - Validate integration with `CredentialsManager`/`SecureCredentialsManager` refresh paths

- New SDK-wide option affecting all requests:
   - Start in `Auth0.kt`
   - Validate propagation into networking/request creation paths

### Testing Targets by Change Type

- Auth API behavior: `auth0/src/test/java/com/auth0/android/authentication/`
- Web Auth/provider behavior: `auth0/src/test/java/com/auth0/android/provider/`
- Credentials/storage behavior: `auth0/src/test/java/com/auth0/android/authentication/storage/`
- MFA behavior: `auth0/src/test/java/com/auth0/android/authentication/mfa/`
- My Account behavior: `auth0/src/test/java/com/auth0/android/myaccount/`
- DPoP behavior: `auth0/src/test/java/com/auth0/android/dpop/`
- Request/response parsing: `auth0/src/test/java/com/auth0/android/request/` and `auth0/src/test/java/com/auth0/android/result/`

## Security and Compatibility Notes

- PKCE is a core OAuth defense and should remain enabled for relevant flows.
- DPoP support is present and has active maintenance; preserve nonce/retry correctness.
- Keystore/biometric paths must continue to fail safely with clear exception mapping.
- Redirect URI and scheme/app-link configuration must be exact to avoid browser callback failures.

## Release and Versioning Workflow

- `.version` is the source of truth for SDK versioning.
- `CHANGELOG.md` must be updated with user-facing changes.
- Release automation is defined in `.github/workflows/release.yml` and `.github/workflows/java-release.yml`.
- CI test workflow is defined in `.github/workflows/test.yml`.

## Documentation to Keep in Sync

- `README.md` for onboarding and requirements
- `EXAMPLES.md` for usage patterns
- `FAQ.md` for known pitfalls
- Migration guides (`V2_MIGRATION_GUIDE.md`, `V3_MIGRATION_GUIDE.md`, `V4_MIGRATION_GUIDE.md`) for breaking changes

## Agent Dos and Don'ts

### Do

- Do preserve public API behavior unless the change is explicitly breaking and documented.
- Do maintain callback and coroutine parity when adding user-facing async APIs.
- Do add/update unit tests for both success and failure paths for every behavior change.
- Do keep changes focused to the feature area and follow existing package/class patterns.
- Do update `EXAMPLES.md` whenever adding a new feature or modifying existing feature behavior.
- Do keep `README.md` and other relevant docs in sync with user-visible behavior and API usage.
- Do validate security-sensitive flows carefully (PKCE, DPoP, keystore/biometric behavior, redirect handling).
- Do keep error handling typed and actionable, and map new failures to existing exception patterns.

### Don't

- Don't remove or weaken secure defaults (PKCE, token protections, keystore usage, DPoP checks).
- Don't introduce callback-only or coroutine-only APIs when both styles are already expected.
- Don't silently change token storage/refresh semantics without matching tests and documentation updates.
- Don't modify unrelated modules/files when implementing a scoped fix.
- Don't rely on brittle string matching of error messages in tests or SDK logic; use typed errors/codes.
- Don't bypass CI-relevant checks; run the repo's unit/lint workflow command before finalizing.
- Don't merge docs/code changes that drift from source-of-truth Gradle and workflow configs.

## Agent Checklist Before Finishing a Change

1. Confirm implementation follows existing SDK patterns (builder style, callbacks + coroutines where applicable).
2. Add/adjust tests and run the relevant Gradle tasks.
3. Validate no regression in public API behavior unless intended.
4. Update `README.md`, `EXAMPLES.md`, and other relevant docs when behavior or API shape changes.
5. Flag any security-sensitive changes explicitly in PR notes.

