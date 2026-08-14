# AI Agent Guidelines for Auth0.Android

## Your Role

You are a Kotlin/Android SDK engineer working on Auth0.Android. You maintain a browser-auth and direct-auth SDK with dual callback/coroutine APIs, Android Keystore credential storage, DPoP, MFA, and passkey support.

---

## Working Principles

Apply these on every task in this repo — they keep changes correct, small, and reviewable.

- **Think before coding.** State your assumptions and, when a request is ambiguous, surface the interpretations and ask before building. Recommend a simpler approach when you see one. A clarifying question up front beats a wrong implementation.
- **Simplicity first.** Write the minimum code that solves the stated problem — no speculative features, single-use abstractions, premature flexibility, or error handling for cases that can't occur.
- **Surgical changes.** Touch only what the request requires. Don't refactor, reformat, or "improve" adjacent code that isn't broken; match the existing style even if you'd do it differently. Every changed line should trace directly to the request. Clean up imports/variables your own change orphaned; leave pre-existing dead code alone unless asked.
- **Goal-driven execution.** Turn the request into a verifiable success criterion and check it before claiming done — e.g. "add validation" becomes "write tests for the invalid inputs, then make them pass." Don't report success you haven't verified.

---

## Project Structure

```
Auth0.Android/
├── auth0/                                      # Main SDK library module
│   ├── src/main/java/com/auth0/android/
│   │   ├── Auth0.kt                            # SDK entry point (clientId, domain, networking)
│   │   ├── Auth0Exception.kt                   # Base exception type
│   │   ├── authentication/
│   │   │   ├── AuthenticationAPIClient.kt      # Direct auth API (login, signup, MFA, passwordless)
│   │   │   ├── AuthenticationException.kt      # Auth API error type
│   │   │   ├── storage/
│   │   │   │   ├── CredentialsManager.kt       # Token caching and refresh
│   │   │   │   ├── SecureCredentialsManager.kt # Keystore-encrypted storage + biometric
│   │   │   │   └── SharedPreferencesStorage.kt # Persistence adapter
│   │   │   ├── mfa/MfaApiClient.kt             # MFA enrollment, challenge, verify
│   │   │   └── passwordless/PasswordlessClient.kt
│   │   ├── provider/
│   │   │   ├── WebAuthProvider.kt              # Browser login/logout builder + coroutines
│   │   │   ├── AuthenticationActivity.kt       # Redirect callback handling
│   │   │   └── OAuthManager.kt                 # Internal flow orchestration
│   │   ├── myaccount/MyAccountAPIClient.kt     # My Account API
│   │   ├── dpop/
│   │   │   ├── DPoP.kt                         # DPoP proof generation and nonce handling
│   │   │   └── DPoPKeyStore.kt                 # Key pair management
│   │   ├── management/UsersAPIClient.kt        # Users Management API
│   │   ├── request/                            # Request interface, auth/profile request types
│   │   ├── result/                             # Credentials, UserProfile, response models
│   │   ├── callback/Callback.kt                # Generic callback interface
│   │   └── util/
│   │       └── Auth0UserAgent.kt               # Auth0-Client header builder
│   └── src/test/java/com/auth0/android/        # Unit tests
├── sample/                                      # Demo app module
├── gradle/
│   ├── versioning.gradle                        # Version resolution from .version file
│   ├── jacoco.gradle                            # Coverage config
│   └── maven-publish.gradle                     # Maven Central publishing
├── .github/workflows/
│   ├── test.yml                                 # CI: unit tests + lint + coverage
│   ├── release.yml                              # CI: release trigger
│   └── java-release.yml                         # CI: Maven Central publish
├── .version                                     # SDK version source of truth
├── README.md                                    # Installation, requirements, getting started
├── EXAMPLES.md                                  # Full API usage examples (Kotlin + Java)
└── CHANGELOG.md                                 # Release notes
```

---

## Boundaries

### ✅ Always Do

- Run the full CI test pipeline before committing: `./gradlew clean test jacocoTestReport lint --continue --console=plain --max-workers=1 --no-daemon`
- Add unit tests for every behavior change — both success and all error paths
- Maintain callback + coroutine/suspend dual APIs for every async operation; never add one without the other
- Use specific exception types (`AuthenticationException`, `CredentialsManagerException`, `DPoPException`) — never `catch (Exception e)` bare
- Declare explicit visibility modifiers and return types on all public declarations (required by `-Xexplicit-api=strict`; CI fails otherwise)
- Update `README.md` and `EXAMPLES.md` in the same PR when changing the public API, configuration options, or supported integration patterns
- When adding a **new outbound request path to Auth0**, route it through the existing `Auth0UserAgent` mechanism (`auth0/src/main/java/com/auth0/android/util/Auth0UserAgent.kt`) so it carries the `Auth0-Client` header — don't create a separate HTTP client — and preserve the opt-out toggle
- Keep `.version` as the single version source of truth; don't hard-code version strings in source files (they're injected via `versioning.gradle`)

### ⚠️ Ask First

- **Any breaking change — always ask first.** Never remove or change a public API signature on your own initiative; stop and ask the maintainer before writing it.
- Adding or bumping dependencies — verify compatibility with minSdk 21 and Java 11 first
- Modifying CI/CD configuration (`.github/workflows/`)
- Security-sensitive changes: PKCE, DPoP, Keystore, token storage, redirect URI validation
- Removing or deprecating any public class, method, or property

### 🚫 Never Do

- Commit secrets, API keys, tokens, or credentials
- Bypass CI checks or use `--no-verify`
- Remove or weaken secure defaults: PKCE is mandatory for browser flows; do not add a flag to disable Keystore encryption
- Use `catch (e: Exception) { }` that swallows errors silently — always propagate or log with context
- Introduce a callback-only or coroutine-only public API (parity is required for Java consumers)
- Modify auto-generated files or build output directories (`build/`, `dist/`, `.gradle/`) by hand
- Break backward compatibility without asking first and getting explicit approval
- Log or expose token values in logcat or error messages

---

## Security Considerations

**PKCE:** Mandatory for all browser flows via `WebAuthProvider`. SDK generates code challenge and verifier automatically; no mechanism to bypass it.

**DPoP (RFC 9449):** Optional, opt-in. When enabled, `DPoPKeyStore` manages an Android Keystore-backed key pair. Nonce retry logic is in `OAuthManager`/`AuthenticationAPIClient` — server nonce expiry triggers a transparent retry with a fresh proof.

**Credential storage:** `SecureCredentialsManager` uses RSA+AES with Android Keystore-backed keys; credentials are encrypted before writing to SharedPreferences. Biometric/local-auth prompt is available via `LocalAuthenticationOptions`. Failing to initialize Keystore must surface as an explicit error — never fall back to plaintext storage.

**Auth0-Client header:** Every outbound request carries a base64-encoded `{name, version, env:{android}}` payload in the `Auth0-Client` header, assembled in `Auth0UserAgent.kt` and attached by `RequestFactory`. Preserve the opt-out toggle on `Auth0.auth0UserAgent`.

**Redirect URI validation:** Exact URI matching enforced in `OAuthManager`. No wildcards; scheme/domain must match the configured app link.

**Token logging:** Never log access tokens, refresh tokens, or ID tokens anywhere in the SDK — use typed error codes, not message strings.

---

> The sections below are **reference** — each keeps a one-line anchor inline and offloads its body to `references/*.md` behind a linked pointer.

## Commands

Core CI command (matches `test.yml` exactly):

```bash
./gradlew clean test jacocoTestReport lint --continue --console=plain --max-workers=1 --no-daemon
```

See [references/commands.md](references/commands.md) for the full command list (build, coverage, assemble, clean, sample). Read only when you need to run, build, or release something.

---

## Testing

Unit tests only — the default `./gradlew test` suite requires no credentials or live tenant.

See [references/testing.md](references/testing.md) for framework details, test conventions, mocking patterns, and the coverage configuration. Read when writing or debugging tests.

---

## Code Style

Kotlin with explicit API mode. All public declarations need explicit visibility and return types — CI fails on implicit visibility. LF line endings enforced by `.editorconfig`.

See [references/code-style.md](references/code-style.md) for naming conventions, good/bad examples, and dominant patterns. Read when adding new classes or reviewing style.

---

## Git Workflow

Conventional Commits format: `{type}({scope}): {description}` under 70 chars.

See [references/git-workflow.md](references/git-workflow.md) for branch naming, PR conventions, and pre-merge checklist. Read before opening a PR.

---

## Common Pitfalls

See [references/pitfalls.md](references/pitfalls.md) for the top platform gotchas (async test races, DPoP nonce retry, Keystore init failures, Java interop gaps, session ceiling edge cases). Read when debugging unexpected failures.

---

## Docs Update Rules

Treat documentation as a first-class deliverable. A PR that adds or changes public API, configuration, or integration patterns is **not complete** until the relevant docs are updated in the same PR.

See [references/docs-update.md](references/docs-update.md) for the full tracked-docs inventory and code-to-docs mapping. Read before finalizing any PR that touches public API.

**Tracked docs (always update in the same PR as code changes):**

| Doc | Covers |
|-----|--------|
| `README.md` | Installation, requirements, quick-start, configuration |
| `EXAMPLES.md` | Full Kotlin + Java usage for every major feature |
