# AI Agent Guidelines for Auth0.Android

## Your Role

You are a Kotlin/Android SDK engineer working on Auth0.Android — browser-auth and direct-auth SDK with dual callback/coroutine APIs, Keystore credential storage, DPoP, MFA, and passkey support.

---

## Working Principles

Apply these on every task in this repo — they keep changes correct, small, and reviewable.

- **Think before coding.** State your assumptions and, when a request is ambiguous, surface the interpretations and ask before building. Recommend a simpler approach when you see one. A clarifying question up front beats a wrong implementation.
- **Simplicity first.** Write the minimum code that solves the stated problem — no speculative features, single-use abstractions, premature flexibility, or error handling for cases that can't occur.
- **Surgical changes.** Touch only what the request requires. Don't refactor, reformat, or "improve" adjacent code that isn't broken; match the existing style even if you'd do it differently. Every changed line should trace directly to the request. Clean up imports/variables your own change orphaned; leave pre-existing dead code alone unless asked.
- **Goal-driven execution.** Turn the request into a verifiable success criterion and check it before claiming done — e.g. "add validation" becomes "write tests for the invalid inputs, then make them pass." Don't report success you haven't verified.

---

## Project Structure

```text
Auth0.Android/
├── auth0/src/main/java/com/auth0/android/
│   ├── Auth0.kt                            # SDK entry point
│   ├── authentication/
│   │   ├── AuthenticationAPIClient.kt      # Direct auth (login, signup, MFA, passwordless)
│   │   ├── storage/
│   │   │   ├── CredentialsManager.kt       # Token caching + refresh
│   │   │   └── SecureCredentialsManager.kt # Keystore-encrypted storage + biometric
│   │   └── mfa/MfaApiClient.kt
│   ├── provider/
│   │   ├── WebAuthProvider.kt              # Browser login/logout + coroutines
│   │   └── OAuthManager.kt                 # OAuth flow orchestration
│   ├── myaccount/MyAccountAPIClient.kt     # My Account API
│   ├── dpop/                               # DPoP proof generation + key management
│   ├── request/                            # Request types, auth/profile requests
│   ├── result/                             # Credentials, UserProfile, response models
│   └── util/Auth0UserAgent.kt              # Auth0-Client header builder
├── auth0/src/test/java/com/auth0/android/  # Unit tests (Robolectric/JUnit 4)
├── sample/                                  # Demo app
├── gradle/versioning.gradle                 # Reads version from .version
├── .github/workflows/test.yml               # CI: tests + lint + coverage
├── .version                                 # Single version source of truth
├── README.md                                # User onboarding and requirements
├── EXAMPLES.md                              # Index linking to examples/
├── examples/                                # Usage patterns, one file per feature
└── V4_MIGRATION_GUIDE.md                    # v3 → v4 migration
```

---

## Boundaries

### ✅ Always Do

- Run CI pipeline before committing: `./gradlew testReleaseUnitTest jacocoTestReleaseUnitTestReport lintRelease --continue --console=plain` (locally you can skip `jacocoTestReleaseUnitTestReport` to save time — CI always runs it)
- Add unit tests for every change — both success and error paths
- Provide both callback and `suspend` variants for every async public method (Java consumers need callbacks)
- Declare explicit visibility modifiers and return types on all public declarations (`-Xexplicit-api=strict` — CI fails on implicit visibility)
- Use specific exception types (`AuthenticationException`, `CredentialsManagerException`, `DPoPException`) — never bare `catch (Exception e)`
- Update `README.md` and the relevant file under `examples/` in the same PR when changing public API, configuration, or integration patterns — examples must include Kotlin callback, coroutine, and Java samples for every async method
- Route new outbound requests through `RequestFactory` so they carry the `Auth0-Client` header via `Auth0UserAgent` — don't create a separate HTTP client
- Keep `.version` as the sole version source of truth (injected via `gradle/versioning.gradle`)

### ⚠️ Ask First

- **Any breaking change — always ask first**; never remove or change a public API on your own initiative
- Adding or bumping dependencies (verify minSdk 26 + Java 17 compatibility)
- Modifying CI/CD config (`.github/workflows/`)
- Security-sensitive changes: PKCE, DPoP, Keystore, token storage, redirect URI validation

### 🚫 Never Do

- Commit secrets, tokens, or API keys
- Bypass CI with `--no-verify`
- Weaken secure defaults — PKCE is mandatory for browser flows; no flag to disable Keystore encryption
- Swallow errors silently with empty `catch` blocks
- Add a callback-only or coroutine-only public API (parity required)
- Log or expose token values in logcat or error messages

---

## Security Considerations

**PKCE:** Mandatory for all `WebAuthProvider` browser flows; SDK generates challenge/verifier automatically with no bypass mechanism.

**DPoP (RFC 9449):** Opt-in. `DPoPKeyStore` manages an Android Keystore-backed key pair; nonce retry on 401 is handled transparently in `RetryInterceptor`.

**Credential storage:** `SecureCredentialsManager` uses RSA+AES with Keystore-backed keys; credentials are encrypted before SharedPreferences writes. Keystore init failure must throw explicitly — never fall back to plaintext.

**Auth0-Client header:** Every eligible request carries a base64-encoded `{name, version, env}` payload assembled in `Auth0UserAgent.kt` and attached by `RequestFactory`, unless the `Auth0.auth0UserAgent` opt-out is enabled.

**Token logging:** Never log access/refresh/ID tokens — use typed error codes only.

---

> Reference sections below are loaded on demand via linked pointers.

## Commands

CI command (from `test.yml`): `./gradlew testReleaseUnitTest jacocoTestReleaseUnitTestReport lintRelease --continue --console=plain`

See [references/commands.md](references/commands.md) for the full list (assemble, clean, sample, coverage). Read when you need to build or release.

## Testing

Unit-only — no credentials or live tenant required.

See [references/testing.md](references/testing.md) for framework versions, test locations, mocking patterns, and coverage config (80% patch target). Read when writing or debugging tests.

## Code Style

Kotlin, explicit API mode. CI-enforced: explicit `public` visibility on all declarations, explicit return types, LF line endings (`.editorconfig`).

See [references/code-style.md](references/code-style.md) for naming conventions, dual-API pattern, and good/bad examples. Read when adding new classes.

## Git Workflow

Conventional Commits: `{type}({scope}): {description}` under 70 chars.

See [references/git-workflow.md](references/git-workflow.md) for branch naming, PR conventions, and pre-merge checklist. Read before opening a PR.

## Common Pitfalls

See [references/pitfalls.md](references/pitfalls.md) for async test races, DPoP nonce retry gaps, Keystore init failures, Java interop misses, and explicit-API-mode surprises. Read when debugging failures.

## Docs Update Rules

A PR touching public API, config, or integration patterns is not complete until docs are updated in the same PR.

| Doc | Covers |
|-----|--------|
| `README.md` | Installation, requirements, quick-start, config |
| `EXAMPLES.md` + `examples/` | `EXAMPLES.md` is an index; each feature has its own file under `examples/` with full Kotlin + Java usage |

See [references/docs-update.md](references/docs-update.md) for the full code-to-docs mapping. Read before finalizing any public API PR.
