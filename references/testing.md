# Testing Reference — Auth0.Android

## Framework & Versions

| Tool | Version |
|------|---------|
| JUnit | 4.13.2 |
| Robolectric | 4.8.1 |
| Mockito Core | 3.12.4 |
| Mockito-Kotlin | 2.2.0 (`com.nhaarman.mockitokotlin2`) |
| MockWebServer | 4.12.0 |
| okhttp-tls | 4.12.0 |
| Awaitility | 1.7.0 |
| kotlinx-coroutines-test | 1.6.2 |
| Espresso Intents | 3.5.1 |
| PowerMock | 2.0.9 (being removed — avoid in new tests) |

## Test Location

```
auth0/src/test/java/com/auth0/android/
├── authentication/          # AuthenticationAPIClient tests
├── authentication/request/  # Request type tests
├── authentication/storage/  # CredentialsManager + SecureCredentialsManager tests
├── dpop/                    # DPoP tests
├── management/              # UsersAPIClient tests
├── myaccount/               # MyAccountAPIClient tests
├── provider/                # WebAuthProvider + browser flow tests
├── request/                 # Request interface tests
├── result/                  # Response parsing / model tests
└── util/                    # Utility + mock server helpers
```

## Coverage Configuration

- **Tool:** JaCoCo (configured in `gradle/jacoco.gradle`)
- **Excluded from coverage:** `auth0/src/main/java/com/auth0/android/authentication/storage/CryptoUtil.java` (Android Keystore-dependent)
- **Patch target:** 80% (enforced by Codecov; see `codecov.yml`)
- **Project degradation threshold:** 1%

## Running the Default Test Suite

```bash
# Unit tests only (no credentials required)
./gradlew test

# Unit tests + JaCoCo coverage report
./gradlew test jacocoTestReport

# Full CI pipeline (recommended before committing)
./gradlew clean test jacocoTestReport lint --continue --console=plain --max-workers=1 --no-daemon
```

The default `test` task is unit-only — no Auth0 tenant, no network, no credentials needed.

## Test Conventions

**Runner:** `@RunWith(RobolectricTestRunner::class)` for any test that needs Android framework APIs (Context, Base64, SharedPreferences, etc.).

**HTTP mocking:** Use `MockWebServer` with `okhttp-tls` for HTTPS. The helper `AuthenticationAPIMockServer` in `src/test/java/.../util/` provides pre-built response fixtures.

**Async verification:**
- For callback-based APIs: use `Awaitility` (`await().atMost(...)`) — never `Thread.sleep()`.
- For coroutine-based APIs: use `runTest { ... }` from `kotlinx-coroutines-test`.
- For `advanceUntilIdle()` patterns: use `TestCoroutineDispatcher` or the coroutine test rule.

**Mocking:** Use Mockito-Kotlin (`mock<T>()`, `whenever`, `verify`, `argumentCaptor`) for Kotlin-friendly mocks. Avoid PowerMock for new tests — the project is actively removing it.

**Naming:** Test method names use backtick strings for readability: `` `should save credentials when getCredentials succeeds`() ``. Nested class grouping by scenario is common.

**Error paths:** Every new public method needs at least one success test and one failure test. For callbacks: verify `onSuccess` and `onFailure` separately. For coroutines: verify the returned value and the thrown exception.

**Biometric / Keystore tests:** Mock `CryptoUtil` via constructor injection (see `SecureCredentialsManagerTest`). Don't rely on real Keystore operations in unit tests — Robolectric doesn't support hardware-backed keys.

## Mocking Patterns

```kotlin
// HTTP mock — use MockWebServer
val server = MockWebServer()
server.enqueue(MockResponse().setBody(json).setResponseCode(200))
server.start()

// Mockito-Kotlin mock
val mockStorage = mock<Storage>()
whenever(mockStorage.retrieveString(KEY_TOKENS)).thenReturn(null)
verify(mockStorage).store(eq(KEY_TOKENS), any())

// Coroutine test
@Test
fun `should return credentials`() = runTest {
    val result = credentialsManager.awaitCredentials()
    assertThat(result.accessToken, equalTo("token"))
}

// Awaitility for callback
var result: Credentials? = null
credentialsManager.getCredentials(callback = object : Callback<Credentials, CredentialsManagerException> {
    override fun onSuccess(credentials: Credentials) { result = credentials; latch.countDown() }
    override fun onFailure(error: CredentialsManagerException) { latch.countDown() }
})
await().atMost(5, TimeUnit.SECONDS).until { result != null }
```
