# Testing Reference — Auth0.Android

## Framework versions

| Tool | Version |
|------|---------|
| JUnit | 4.13.2 |
| Robolectric | 4.15.1 |
| Mockito Core | 5.14.0 |
| Mockito-Kotlin | 5.4.0 (`org.mockito.kotlin`) |
| MockWebServer | 4.12.0 |
| okhttp-tls | 4.12.0 |
| Awaitility | 1.7.0 |
| kotlinx-coroutines-test | 1.10.2 |
| Espresso Intents | 3.6.1 |

## Test locations

```text
auth0/src/test/java/com/auth0/android/
├── authentication/          # AuthenticationAPIClient + request tests
├── authentication/storage/  # CredentialsManager + SecureCredentialsManager tests
├── dpop/                    # DPoP tests
├── myaccount/               # MyAccountAPIClient tests
├── provider/                # WebAuthProvider + browser flow tests
├── request/                 # Request interface + internal tests
└── result/                  # Response parsing tests
```

## Coverage

- Tool: JaCoCo (`gradle/jacoco.gradle`)
- Excluded: `CryptoUtil.java` (hardware Keystore-dependent)
- Patch target: 80% (Codecov `codecov.yml`)

## Run command

```bash
# Safe unit-only — no credentials required
./gradlew testReleaseUnitTest jacocoTestReleaseUnitTestReport lintRelease --continue --console=plain
```

## Conventions

**Runner:** `@RunWith(RobolectricTestRunner::class)` for any test needing Android framework APIs.

**HTTP mocking:** `MockWebServer` with `okhttp-tls`; use `AuthenticationAPIMockServer` fixtures in `src/test/.../util/`.

**Async — callbacks:** Use `Awaitility.await().atMost(...)` — never `Thread.sleep()`.

**Async — coroutines:** Use `runTest { }` from `kotlinx-coroutines-test`.

**Mocking:** Mockito-Kotlin (`mock<T>()`, `whenever`, `verify`, `argumentCaptor`). Avoid PowerMock in new tests — the project is removing it.

**Coverage:** Every new public method needs at least one success test and one failure test. For callbacks verify `onSuccess` and `onFailure` separately.

**Biometric/Keystore:** Mock `CryptoUtil` via constructor injection — Robolectric does not support hardware-backed keys.
