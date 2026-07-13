# CLAUDE.md — Auth0.Android SDK

Guidance for AI coding assistants working on the Auth0.Android SDK.

## Project Overview

**Auth0.Android** is a native Android SDK for authentication and authorization with Auth0. It provides:

- Web authentication via Universal Login and browser-based OAuth flows (WebAuthProvider)
- Direct authentication APIs (database, passwordless, OTP, token operations)
- Credential persistence and automatic token renewal via CredentialsManager
- Secure credential storage using Android Keystore with biometric integration
- Kotlin-first APIs with full Java interoperability and coroutine support
- MFA (Multi-Factor Authentication) support with flexible factor enrollment and verification
- My Account API for self-service authentication method management
- DPoP (Demonstration of Proof-of-Possession) for sender-constrained tokens
- Passkey support for passwordless FIDO2 authentication

**Technology Stack:**
- **Language:** Kotlin (with Java interoperability)
- **Min SDK:** API 26, Compile/Target: API 36
- **Java source/target:** 17
- **Kotlin JVM target:** 17
- **Build System:** Gradle 8.10.1 with Android Gradle Plugin 8.10.1
- **Kotlin:** 2.0.21 with explicit API mode (strict)
- **Package Manager:** Gradle + Maven Central
- **Current Version:** 4.0.0

---

## Commands

```bash
# Run unit tests and generate coverage reports (matching CI pipeline)
./gradlew testReleaseUnitTest jacocoTestReleaseUnitTestReport lintRelease --continue --console=plain

# Run all lint checks
./gradlew lint

# Build the SDK library
./gradlew auth0:assemble

# Build sample/demo app
./gradlew sample:assembleDebug

# Build release AAR for publishing
./gradlew auth0:assembleRelease

# Build and run all tests with output
./gradlew test --info

# Clean build artifacts
./gradlew clean

# Check Kotlin API surface for breaking changes (explicit API mode strict)
./gradlew auth0:compileReleaseKotlin
```

---

## Testing

**Framework & Tools:**
- JUnit 4 (4.13.2)
- Robolectric 4.15.1 (Android framework mocking)
- Mockito Core 5.14.0 + Mockito Kotlin 5.4.0
- MockWebServer (4.12.0) + OkHttp TLS helpers for HTTP mocking
- Hamcrest matchers
- Awaitility (async verification)
- Kotlin Coroutines Test
- Espresso Intents (for browser interaction tests)

**Test Locations:**
```
auth0/src/test/
├── java/com/auth0/android/
│   ├── authentication/          # Auth API client tests
│   ├── provider/                # WebAuthProvider/browser tests
│   ├── authentication/storage/  # CredentialsManager tests
│   ├── authentication/mfa/      # MFA API tests
│   ├── dpop/                    # DPoP tests
│   ├── myaccount/               # My Account API tests
│   └── result/                  # Response parsing tests
```

**Coverage Requirements:**
- Minimum target: 80% for patch changes
- Ignored from coverage: `CryptoUtil.java` (Android framework-dependent encryption)
- Both success and failure/error paths required for new behavior
- Async code must use Awaitility or coroutine test helpers to control execution

**Testing Patterns:**
- Use `@RunWith(RobolectricTestRunner.class)` for Android component tests
- Mock HTTP responses with MockWebServer; validate URLs/headers with matchers
- Mock `Context` with Mockito for framework interactions
- Use `coroutineScope.advanceUntilIdle()` or Awaitility for async/callback verification
- Avoid `PowerMock`; prefer constructor/method injection with mocks (project is removing PowerMock)

---

## Project Structure

```
Auth0.Android/
├── auth0/                                      # Main SDK library module
│   ├── src/main/java/com/auth0/android/
│   │   ├── Auth0.kt                            # SDK config entry point (client ID, domain, networking)
│   │   ├── Auth0Exception.kt                   # Base exception type
│   │   ├── authentication/
│   │   │   ├── AuthenticationAPIClient.kt      # Direct auth API (login, signup, MFA, passwordless)
│   │   │   ├── AuthenticationException.kt      # Auth API error type
│   │   │   ├── storage/
│   │   │   │   ├── CredentialsManager.kt       # Token caching and refresh (callback + coroutine APIs)
│   │   │   │   ├── SecureCredentialsManager.kt # Encrypted storage + biometric integration
│   │   │   │   └── SharedPreferencesStorage.kt # Persistence adapter
│   │   │   ├── mfa/
│   │   │   │   ├── MfaApiClient.kt             # MFA enrollment, challenge, verify
│   │   │   │   └── MfaException.kt
│   │   │   └── passwordless/
│   │   │       └── PasswordlessClient.kt       # Passwordless flows
│   │   ├── provider/
│   │   │   ├── WebAuthProvider.kt              # Browser login/logout builder + coroutines
│   │   │   ├── AuthenticationActivity.kt       # Redirect callback handling
│   │   │   ├── OAuthManager.kt                 # Internal flow orchestration
│   │   │   └── [browser option helpers]
│   │   ├── myaccount/
│   │   │   ├── MyAccountAPIClient.kt           # My Account API (authentication method management)
│   │   │   └── MyAccountException.kt
│   │   ├── dpop/
│   │   │   ├── DPoP.kt                         # DPoP proof generation and nonce handling
│   │   │   ├── DPoPKeyStore.kt                 # Key pair management
│   │   │   ├── DPoPException.kt
│   │   │   └── SenderConstraining.kt           # DPoP integration interface
│   │   ├── request/
│   │   │   ├── Request<T>                      # Async request interface (callback + suspend)
│   │   │   ├── AuthenticationRequest.kt        # Auth-specific request type
│   │   │   ├── [domain-specific request types]
│   │   │   └── [adapters and factories]
│   │   ├── result/
│   │   │   ├── Credentials.kt                  # Access/ID/refresh token container
│   │   │   ├── UserProfile.kt                  # User info response
│   │   │   ├── [other response models]
│   │   │   └── [error response mappings]
│   │   ├── callback/
│   │   │   └── Callback<T, E>                  # Generic callback interface
│   │   ├── annotation/
│   │   │   └── ExperimentalAuth0Api.kt         # API stability marker
│   │   └── util/
│   │       └── [HTTP matchers, user agent, helpers]
│   ├── src/test/java/com/auth0/android/       # Unit tests (Robolectric/JUnit 4)
│   ├── build.gradle                            # SDK module build config
│   └── src/main/AndroidManifest.xml
├── sample/                                      # Demo app module (build.gradle, src/, res/)
├── gradle/
│   ├── versioning.gradle                        # Version resolution from .version
│   ├── maven-publish.gradle                     # Maven Central publishing
│   ├── jacoco.gradle                            # Code coverage config
│   └── [other shared build logic]
├── .github/workflows/
│   ├── test.yml                                 # CI: unit tests + linting
│   ├── release.yml                              # CI: trigger release workflow
│   ├── java-release.yml                         # Maven Central publish automation
│   ├── codeql.yml                               # Security scanning
│   └── sca_scan.yml                             # Dependency scanning
├── .version                                     # SDK version source of truth (4.0.0)
├── .editorconfig                                # EditorConfig (LF line endings)
├── README.md                                    # User onboarding and requirements
├── EXAMPLES.md                                  # Usage patterns and API examples
├── CHANGELOG.md                                 # Release notes and breaking changes
├── V4_MIGRATION_GUIDE.md                        # Migration from v3 to v4
├── FAQ.md                                       # Known issues and troubleshooting
├── build.gradle.kts                             # Root Gradle build
├── codecov.yml                                  # Code coverage thresholds
└── gradle.properties                            # Gradle system properties
```

---

## Code Style

**Naming Conventions:**

| Element | Pattern | Example |
|---------|---------|---------|
| Package | `com.auth0.android.{domain}` | `com.auth0.android.authentication` |
| Class (Kotlin) | PascalCase, `-Kt` suffix for files | `Auth0.kt`, `WebAuthProvider.kt` |
| Class (Java) | PascalCase | `Auth0.java` |
| Exception | `{Domain}Exception` | `AuthenticationException`, `CredentialsManagerException` |
| Interface | PascalCase, often `{Operation}er` or `{Operation}able` | `Callback<T, E>`, `SenderConstraining` |
| Function/Method | camelCase | `login()`, `saveCredentials()` |
| Property | camelCase (private with `_` prefix if internal) | `clientId`, `_innerState` |
| Constant | UPPER_SNAKE_CASE | `DEFAULT_TIMEOUT_SECONDS`, `KEY_TOKENS` |
| Enum | PascalCase members | `Factor.OTP`, `Factor.SMS` |

**Kotlin Idioms (Preferred):**

```kotlin
// ✅ Use suspend/coroutine APIs alongside callbacks for Kotlin consumers
suspend fun login(email: String, password: String): Credentials = withContext(Dispatchers.IO) { ... }

// ✅ Use builder pattern for complex configurations
WebAuthProvider.login(account)
    .withScope("openid profile email")
    .withAudience("https://api.example.com")
    .start(activity, callback)

// ✅ Use sealed classes or `when` for comprehensive error handling
sealed class AuthResult {
    data class Success(val credentials: Credentials) : AuthResult()
    data class Failure(val error: AuthenticationException) : AuthResult()
}

when (result) {
    is AuthResult.Success -> handleSuccess(result.credentials)
    is AuthResult.Failure -> handleError(result.error)
}

// ✅ Use inline classes or data classes for typed value holders
data class Credentials(
    val accessToken: String?,
    val idToken: String?,
    val refreshToken: String?,
    val expiresAt: Date?
)

// ✅ Use explicit visibility modifiers (required by strict API mode)
public class Auth0 { /* ... */ }
private val internalConfig = ...

// ✅ Extension functions for readability
private fun Request<Credentials>.validateClaims(): Request<Credentials> = ...
```

**Java Interoperability:**

```java
// ✅ Preserve callback-based APIs for Java consumers
authClient.login("user@example.com", "password", "connection")
    .validateClaims()
    .start(new Callback<Credentials, AuthenticationException>() {
        @Override
        public void onSuccess(Credentials result) { /* ... */ }
        
        @Override
        public void onFailure(AuthenticationException error) { /* ... */ }
    });
```

**Error Handling Pattern:**

```kotlin
// ✅ Use specific exception types; don't catch generic Exception
try {
    val creds = secureCredsManager.getCredentials()
} catch (e: CredentialsManagerException) {
    when (e.statusCode) {
        CredentialsManagerException.EMPTY_CREDENTIALS -> handleEmpty()
        CredentialsManagerException.NO_CREDENTIALS -> handleMissing()
        CredentialsManagerException.REFRESH_FAILED -> handleRefreshError(e)
        else -> handleUnknown(e)
    }
}

// ✅ For API calls, map errors to typed exceptions
when {
    response.isSuccessful -> Credentials(response.body())
    response.code() == 401 -> throw AuthenticationException(response)
    response.code() == 403 -> throw AuthenticationException(response)
    else -> throw NetworkErrorException(response)
}
```

**PKCE and Security:**

```kotlin
// ✅ PKCE is enabled by default and required for browser flows
// Do not add options to disable it — it's a security boundary.

// ✅ DPoP is opt-in but secure by default when enabled
WebAuthProvider.login(account)
    .useDPoP()  // Adds DPoP nonce to request; SDK manages proof lifecycle
    .start(activity, callback)

// ✅ Secure credential storage is the default
SecureCredentialsManager(context, account, storage)
    // Biometric + local auth are enabled by default; use .enableBiometric(false) to disable
```

**Comments and Documentation:**

- Default: no comments unless the WHY is non-obvious
- Comment only hidden constraints, subtle invariants, workarounds for specific bugs, or behavior that would surprise readers
- Example of good comment: `// Retry with new DPoP nonce on 401; nonce has likely expired`
- Example of bad comment: `// Loop through credentials and save them` (obvious from code)
- Use KDoc for public API (especially builder methods and entry points)

---

## Git Workflow

**Branch Naming:**
- Feature: `feature/{feature-name}` or `feat/{feature-name}`
- Fix: `fix/{issue-id}-{name}` or `hotfix/{name}`
- Chore: `chore/{name}`
- Refactor: `refactor/{name}`
- Release: `release/{version}` (e.g., `release/4.0.0`)
- Port/backport: `port/{issue-id}-{name}` (e.g., `port/992-mfa-dpop`)

**Commit Messages:**
- Format: `{type}: {short description}` or `{type}({scope}): {short description}`
- Types: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`, `perf`, `ci`
- Scope: optional, use package or feature name (e.g., `dpop`, `storage`, `mfa`)
- Example: `feat(dpop): support DPoP for MFA requests` or `fix: address session expiry race condition`
- Keep under 70 characters total
- Use imperative mood ("add", "fix", not "adds", "fixed")

**Pull Requests:**
- Title: same as commit message (under 70 characters)
- Description: explain the why, not just the what
- Reference related issues: `Closes #NNN` or `Related to #NNN`
- Always request review before merging
- Squash/rebase to keep linear history (per project preference)
- Ensure CI passes before merge (test.yml, codeql.yml, sca_scan.yml)

**Pre-commit Checklist:**
- Run `./gradlew testReleaseUnitTest jacocoTestReleaseUnitTestReport lintRelease --continue --console=plain`
- Verify no new linting errors or coverage regressions
- Update `README.md` and/or `EXAMPLES.md` if behavior or API changes
- Update `CHANGELOG.md` with user-facing changes
- Never commit secrets (API keys, tokens, credentials) — use environment variables or `.gitignore`

---

## Boundaries

### Always Do

1. **Run the full test/lint pipeline before committing:**
   ```bash
   ./gradlew testReleaseUnitTest jacocoTestReleaseUnitTestReport lintRelease --continue --console=plain
   ```
   Failures must be resolved before merging to main or any protected branch.

2. **Add unit tests for every behavior change:**
   - Test success paths
   - Test all error conditions
   - Test async/callback patterns for both Kotlin and Java consumers
   - Use Robolectric and Mockito for Android/network dependencies

3. **Update `README.md` and `EXAMPLES.md` when changing public API or behavior:**
   - Document new methods, parameters, and options
   - Provide Kotlin and Java examples
   - Verify examples compile and match the current SDK version
   - Update installation/requirements sections if dependencies or min SDK changes

4. **Preserve public API backward compatibility unless explicitly breaking:**
   - Deprecate before removing (v3 → v4 pattern)
   - Document breaking changes in `CHANGELOG.md` and migration guides
   - Test with sample app to validate end-user experience

5. **Maintain callback and coroutine dual APIs for async operations:**
   - If a feature exists as `callback.start(callback)`, also provide `suspend` variant
   - Ensure both paths use the same underlying logic (no divergence)
   - Example: `AuthenticationAPIClient.login()` supports both callback and suspend

6. **Use typed, actionable exceptions:**
   - Catch specific exception types (e.g., `AuthenticationException`, `CredentialsManagerException`)
   - Map API errors to typed codes, not string messages
   - Avoid generic `catch (Exception e)` — be specific

7. **Never weaken security defaults:**
   - PKCE is mandatory for browser flows
   - Token handling and storage defaults to secure (Keystore + biometric)
   - DPoP nonce retry logic must preserve request/response integrity
   - Redirect URI and scheme validation must be exact

8. **Respect the explicit API mode constraint (`-Xexplicit-api=strict`):**
   - All public declarations must have explicit visibility modifiers
   - All public functions/properties must have explicit return types
   - Compilation will fail if implicit visibility is used

9. **Verify no regressions in existing features:**
   - Run the sample app with your changes
   - Test the golden path: login, get credentials, refresh, logout
   - Test edge cases: session expiry, refresh failures, network errors

10. **Document security-sensitive changes explicitly in PR notes:**
    - Flag any changes to PKCE, token storage, DPoP, Keystore, or redirect handling
    - Explain the rationale for the change
    - Validate with security team if required

---

### Ask First

1. **Removing or deprecating public APIs:**
   - Confirm with team that removal is intentional and necessary
   - Plan deprecation period (typically one major version)
   - Document in migration guide

2. **Adding new dependencies:**
   - Confirm the library is necessary
   - Verify it's compatible with min SDK (26) and Java 17
   - Check for transitive dependency conflicts or bloat

3. **Changing default behavior that affects existing apps:**
   - Confirm backward compatibility or explicit opt-in mechanism
   - Document in changelog and migration guide

4. **Major refactors or architectural changes:**
   - Discuss scope and impact with the team
   - Plan for staged rollout or feature-gated behavior if necessary

5. **Security-sensitive changes (PKCE, Keystore, DPoP, token handling):**
   - Get explicit sign-off before merging
   - Include threat model and validation approach in PR description

---

### Never Do

1. **Commit secrets, API keys, tokens, or credentials to the repository:**
   - Use environment variables (e.g., `$API_KEY`) in examples or CI configs
   - Use `.gitignore` to exclude sensitive files
   - Scan commits with tools before pushing

2. **Bypass CI checks or skip tests before merging:**
   - Never use `git push --force` to bypass CI
   - Never merge PRs with failing tests or lint errors
   - Never skip hooks with `--no-verify`

3. **Remove or weaken secure defaults:**
   - PKCE must remain mandatory for browser flows
   - Do not add an option to disable Keystore encryption
   - Do not bypass DPoP nonce validation

4. **Use generic `catch (Exception e)` or swallow errors silently:**
   - Catch specific exception types
   - Log or propagate errors with context
   - Avoid `catch (e: Exception) { }` (at least rethrow or warn)

5. **Introduce callback-only or coroutine-only APIs:**
   - Maintain parity: if a feature is callback-based, also provide suspend
   - Don't force Java consumers to use only callbacks or vice versa

6. **Modify unrelated modules when implementing a scoped fix:**
   - Keep changes focused to the feature/bug area
   - Avoid refactoring unrelated code in the same PR

7. **Rely on brittle string matching for error handling:**
   - Use typed error codes and exception classes
   - Don't parse error messages to determine behavior
   - Example: ❌ `if (error.message.contains("invalid_grant"))` → ✅ `if (error.statusCode == 401)`

8. **Commit changes without updating `CHANGELOG.md` and migration guides:**
   - User-facing changes must be documented
   - Breaking changes must have a migration guide entry

9. **Skip Android resource validation or manifest changes:**
   - Verify `AndroidManifest.xml` changes are syntactically correct
   - Validate that redirect schemes and app links are configured correctly
   - Test with actual device/emulator, not just mock tests

10. **Ignore lint or code coverage warnings:**
    - Fix linting errors before merging
    - Maintain or improve coverage ratios (target: 80% for patches)
    - Use `lintRelease` to match CI exactly

---

## Security Considerations

**PKCE (Proof Key for Code Exchange):**
- Mandatory for all browser-based OAuth flows via `WebAuthProvider`
- Prevents authorization code interception attacks
- SDK generates code challenge and verifier automatically; don't bypass

**DPoP (Demonstration of Proof-of-Possession):**
- Optional but secure-by-default when enabled
- SDK manages key pair lifecycle via `DPoPKeyStore` (Android Keystore-backed)
- Nonce retry logic prevents replay attacks
- Validate DPoP proofs match sender's public key

**Credential Storage:**
- `SecureCredentialsManager` uses Android Keystore for key storage (hardware-backed on supported devices)
- Credentials are encrypted before persisting to SharedPreferences
- Biometric/local auth integration is enabled by default; can be disabled with `.enableBiometric(false)`
- Token refresh happens transparently; failures are propagated to caller

**Redirect URI Validation:**
- Exact URI matching is enforced (no wildcards)
- Scheme/domain must match the configured app link or custom URL scheme
- Prevents open redirect attacks

**Session Management:**
- Access tokens are short-lived; SDK automatically refreshes via refresh token
- Session expiry ceiling prevents infinite extension loops
- Logout clears all cached credentials

**Biometric/Lock-Based Authentication:**
- Biometric/pin verification is transparent to caller but required before accessing credentials in `SecureCredentialsManager`
- Uses `androidx.biometric` library (tested on API 26+)

---

## Dependencies

**Core Production Dependencies:**

| Dependency | Version | Purpose |
|------------|---------|---------|
| `kotlin-stdlib` | 2.0.21 | Kotlin runtime |
| `androidx.core:core-ktx` | 1.15.0 | Android KTX extensions |
| `androidx.appcompat:appcompat` | 1.7.0 | Android app compatibility |
| `androidx.browser:browser` | 1.10.0 | Custom Tabs and browser integration |
| `androidx.biometric:biometric` | 1.1.0 | Biometric/lock-based auth |
| `kotlinx-coroutines-core` | 1.10.2 | Kotlin coroutines (async/await) |
| `okhttp3:okhttp` | 4.12.0 | HTTP client |
| `okhttp3:logging-interceptor` | 4.12.0 | HTTP request/response logging |
| `gson` | 2.11.0 | JSON serialization |
| `androidbrowserhelper` | 2.5.0 | Trusted Web Activity support |

**Test Dependencies:**

| Dependency | Version | Purpose |
|------------|---------|---------|
| `junit` | 4.13.2 | Unit testing framework |
| `robolectric` | 4.15.1 | Android framework mocking |
| `mockito-core` | 5.14.0 | Mock objects |
| `mockito-kotlin` | 5.4.0 | Kotlin-friendly Mockito API |
| `hamcrest` | 2.0.0.0 | Matchers for assertions |
| `okhttp3:mockwebserver` | 4.12.0 | HTTP mock server |
| `okhttp3:okhttp-tls` | 4.12.0 | TLS support for mock server |
| `awaitility` | 1.7.0 | Async verification helpers |
| `kotlinx-coroutines-test` | 1.10.2 | Coroutine testing utilities |
| `espresso-intents` | 3.6.1 | Intent verification for Android tests |

**Plugins:**

| Plugin | Version | Purpose |
|--------|---------|---------|
| `com.android.library` | 8.10.1 | Android library compilation |
| `kotlin-android` | 2.0.21 | Kotlin compiler for Android |
| `org.jetbrains.dokka` | 1.9.20 | KDoc HTML generation |
| `io.github.gradle-nexus.publish-plugin` | 2.0.0 | Maven Central publishing |

---

## Release Process

**Versioning:**
- Source of truth: `.version` file at repository root (e.g., `4.0.0`)
- Format: `MAJOR.MINOR.PATCH` (semantic versioning)
- Snapshots use `-SNAPSHOT` suffix (e.g., `4.0.0-SNAPSHOT`)

**Release Steps:**

1. **Create a release branch:**
   ```bash
   git checkout -b release/X.Y.Z
   ```

2. **Update version and changelog:**
   - Update `.version` to the release version (remove `-SNAPSHOT`)
   - Update `CHANGELOG.md` with release highlights and breaking changes
   - Commit: `chore: bump version to X.Y.Z`

3. **Open PR and merge to main:**
   - Ensure CI passes (test.yml, codeql.yml, sca_scan.yml)
   - Request review from team
   - Merge with squash or rebase (per project preference)

4. **Trigger release workflow:**
   - Push to main or use GitHub Actions "Run Workflow" button
   - `.github/workflows/release.yml` is triggered on merge of `release/X.Y.Z` branches
   - Workflow runs RL Scanner for security (via devsecops-tooling)
   - Calls `java-release.yml` which publishes to Maven Central

5. **Release workflow details (`java-release.yml`):**
   - Builds release AAR: `./gradlew :auth0:assembleRelease`
   - Signs artifacts with GPG key (env var `SIGNING_KEY`)
   - Publishes to Sonatype OSS Repository (Maven Central)
   - Requires credentials: `OSSR_USERNAME`, `OSSR_TOKEN`, `SIGNING_KEY`, `SIGNING_PASSWORD`

6. **Post-release:**
   - Update `.version` to next snapshot (e.g., `4.0.1-SNAPSHOT`)
   - Create GitHub release with tag `vX.Y.Z` and changelog excerpt

**Changelog Format:**
- Use [Keep a Changelog](https://keepachangelog.com/) format
- Sections: Added, Changed, Deprecated, Removed, Fixed, Security
- Group by type (breaking changes first)
- Include PR/issue numbers

---

## Common Pitfalls

1. **Forgetting to update `EXAMPLES.md` when changing public API:**
   - Example: Adding a new parameter to `WebAuthProvider.login()` without updating the examples
   - Impact: Users follow outdated examples; frustration and support overhead
   - Prevention: CI should validate that examples match current API (manual for now)

2. **Async race conditions in tests:**
   - Forgetting to use Awaitility or `advanceUntilIdle()` for callback tests
   - Callbacks fire after test assertion completes; test passes but logic is untested
   - Prevention: Use `@get:Rule` with Awaitility or coroutine test rules; never do `Thread.sleep()`

3. **Token expiry edge cases with session ceiling:**
   - Session expiry check must happen before API call, not just on refresh
   - If access token is expired but refresh fails, old token should not be used
   - Prevention: Test explicit and implicit expiry scenarios with mocked time

4. **Redirect URI and custom URL scheme mismatches:**
   - App link declaration in `AndroidManifest.xml` must match configured `returnToUrl`
   - Custom URL schemes must be unique app-wide (prevents conflicts)
   - Prevention: Validate manifest against Auth0 app configuration; test with real browser

5. **DPoP nonce expiry and retry logic:**
   - Server nonce expiry requires retry with new DPoP proof
   - If retry logic is missing, requests fail with 401/nonce errors
   - Prevention: Test server-side nonce expiry scenarios; validate retry count limits

6. **Keystore unavailability or initialization failure:**
   - Keystore might not be available on non-Play Store devices or on first-run
   - Falling back to insecure storage is not acceptable; must fail explicitly
   - Prevention: Test on various device configurations; fail fast with clear exception

7. **Biometric auth failures due to policy changes:**
   - Biometric auth might fail after device lock, re-enrollment, or disable
   - SDK must gracefully degrade to local auth or reauthentication
   - Prevention: Test biometric state transitions; validate fallback behavior

8. **Forgetting Java interoperability:**
   - Kotlin APIs (suspend, extension functions) don't have Java equivalents by default
   - Java consumers need explicit callback-based APIs
   - Prevention: Add Java tests for public APIs; validate dual async paths

9. **Generic exception catches hiding bugs:**
   - `catch (e: Exception)` masks specific errors (network, auth, storage)
   - Makes debugging difficult and error handling unreliable
   - Prevention: Use specific exception types; linter should warn on generic catches

10. **Lint errors and coverage drops in CI:**
    - Merging with lint failures or coverage below threshold blocks CI pipeline
    - Always run `./gradlew testReleaseUnitTest jacocoTestReleaseUnitTestReport lintRelease --continue` before committing
    - Prevention: Run locally first; configure IDE to highlight linting issues in real-time

---

## External References

- **[Auth0 Quickstart](https://auth0.com/docs/quickstart/native/android)** — onboarding guide
- **[Sample App](https://github.com/auth0-samples/auth0-android-sample)** — working example
- **[JavaDoc](https://javadoc.io/doc/com.auth0.android/auth0/latest/index.html)** — API reference
- **[FAQs](https://github.com/auth0/auth0.android/blob/main/FAQ.md)** — troubleshooting
- **[Android Biometric Library](https://developer.android.com/jetpack/androidx/releases/biometric)** — biometric auth docs
- **[OkHttp Documentation](https://square.github.io/okhttp/)** — HTTP client reference
- **[OAuth 2.0 PKCE](https://tools.ietf.org/html/rfc7636)** — PKCE spec
- **[DPoP (Draft)](https://tools.ietf.org/html/draft-ietf-oauth-dpop)** — DPoP spec
- **[Android Keystore](https://developer.android.com/training/articles/keystore)** — secure key storage

---

## Docs Update Rules

**Current Documentation Status:**

| File | Status | Notes |
|------|--------|-------|
| `README.md` | ✅ Current | Requirements (API 26+, Java 17), installation, configuration, and getting started sections are up-to-date. |
| `EXAMPLES.md` | ✅ Current | Comprehensive examples for all major features (auth, credentials, MFA, DPoP, My Account, etc.). Kotlin and Java patterns shown throughout. |
| `CHANGELOG.md` | ✅ Current | Latest release (4.0.0) fully documented with breaking changes highlighted. |
| `V4_MIGRATION_GUIDE.md` | ✅ Current | Migration from v3 to v4 is comprehensive (breaking API changes, new requirements, deprecations). |
| `FAQ.md` | ✅ Current | Known issues, ProGuard rules, and troubleshooting tips documented. |

**Code-to-Docs Mapping:**

| Public API | Location in Code | Documentation |
|------------|------------------|---------------|
| `Auth0.getInstance()` | `auth0/src/main/java/com/auth0/android/Auth0.kt` | README.md → "Getting Started" section |
| `WebAuthProvider.login()` / `logout()` | `auth0/src/main/java/com/auth0/android/provider/WebAuthProvider.kt` | EXAMPLES.md → "Authenticate with any Auth0 connection" + "Specify a Custom Logout URL" sections |
| `SecureCredentialsManager` | `auth0/src/main/java/com/auth0/android/authentication/storage/SecureCredentialsManager.kt` | EXAMPLES.md → "Secure Credentials Manager" section + "Requiring Authentication" subsection |
| `AuthenticationAPIClient.login()` / passwordless / MFA | `auth0/src/main/java/com/auth0/android/authentication/AuthenticationAPIClient.kt` | EXAMPLES.md → "Authentication API" section (all subsections) |
| `DPoP` support | `auth0/src/main/java/com/auth0/android/dpop/` | EXAMPLES.md → "DPoP" sections (both WebAuth and Authentication API) |
| `MyAccountAPIClient` | `auth0/src/main/java/com/auth0/android/myaccount/MyAccountAPIClient.kt` | EXAMPLES.md → "My Account API" section (all subsections) |
| `MfaApiClient` | `auth0/src/main/java/com/auth0/android/authentication/mfa/MfaApiClient.kt` | EXAMPLES.md → "MFA Flexible Factors Grant" subsection |
| Passkey support | `auth0/src/main/java/com/auth0/android/` | EXAMPLES.md → "Passkeys" section |
| `CredentialsManager` | `auth0/src/main/java/com/auth0/android/authentication/storage/CredentialsManager.kt` | EXAMPLES.md → "Credentials Manager" section |

**Update Rules:**

1. **When adding a new public method/class to the SDK:**
   - Add entry to `EXAMPLES.md` with Kotlin and Java examples
   - Update `README.md` if it's a major feature or requirement change
   - Add entry to `CHANGELOG.md` under "Added" section

2. **When modifying an existing public API:**
   - Update relevant examples in `EXAMPLES.md`
   - Update parameter descriptions and usage patterns
   - Add migration note to `CHANGELOG.md` under "Changed" section
   - If breaking: add full entry to migration guide

3. **When removing a public API (breaking change):**
   - Add migration guide entry with old → new mapping
   - Update `CHANGELOG.md` under "Removed" section with deprecation history
   - Remove related examples from `EXAMPLES.md` and note removal

4. **When changing default behavior:**
   - Update `README.md` "Getting Started" or relevant section
   - Provide before/after examples in `EXAMPLES.md`
   - Document in `CHANGELOG.md` under "Changed" section

5. **When updating requirements (min SDK, Java version, etc.):**
   - Update `README.md` "Requirements" section immediately
   - Add note to `CHANGELOG.md`
   - Update migration guide if it's a major version bump

**Every PR that changes public API, configuration, or supported integration patterns MUST update `README.md` and/or `EXAMPLES.md` in the same commit.**

---

### Agent Checklist Before Finishing a Change

1. ✅ **Implementation follows existing patterns:**
   - Builder style for browser auth (`WebAuthProvider`)
   - Callback + coroutine/suspend dual APIs for async
   - Specific exception types (not generic `Exception`)
   - Explicit visibility modifiers and return types (strict API mode)

2. ✅ **Tests pass and coverage maintained:**
   - Run: `./gradlew testReleaseUnitTest jacocoTestReleaseUnitTestReport lintRelease --continue --console=plain`
   - All tests pass
   - Coverage >= 80% for patches
   - Both success and failure paths tested

3. ✅ **No regressions in existing features:**
   - Tested golden path: login → get credentials → refresh → logout
   - Sample app builds and runs
   - Edge cases work (expiry, network errors, biometric failures)

4. ✅ **Public API changes documented:**
   - `README.md` updated if requirements or onboarding changes
   - `EXAMPLES.md` updated with new/changed API usage (Kotlin + Java)
   - `CHANGELOG.md` entry added

5. ✅ **Security-sensitive changes flagged:**
   - PKCE, DPoP, Keystore, token handling, redirect validation changes noted in PR
   - Rationale explained in PR description
   - Reviewed by security team (if applicable)

6. ✅ **No secrets committed:**
   - Scanned for API keys, tokens, credentials
   - Environment variable references used instead

---

**Generated:** 2026-07-13  
**Current Version:** 4.0.0  
**Language:** Kotlin (Java interoperable)  
**Min SDK:** API 26 | Target: API 36 | Java 17
