# Common Pitfalls — Auth0.Android

## 1. Async test races — callback fires after assertion

**Problem:** Writing a callback test without Awaitility or `runTest` causes the callback to fire after the `assertThat` line, making the test always pass regardless of behavior.

**Fix:** Use `Awaitility.await().atMost(...)` for callback tests, and `runTest { }` for coroutine tests. Never use `Thread.sleep()`.

```kotlin
// ❌ Race — callback may not have fired yet
credentialsManager.getCredentials(callback)
assertThat(result, notNullValue())  // flaky

// ✅ Correct — Awaitility waits for the flag
val latch = CountDownLatch(1)
credentialsManager.getCredentials(object : Callback<...> {
    override fun onSuccess(r: Credentials) { result = r; latch.countDown() }
    override fun onFailure(e: CredentialsManagerException) { latch.countDown() }
})
latch.await(5, TimeUnit.SECONDS)
assertThat(result, notNullValue())
```

## 2. DPoP nonce expiry — missing retry on 401

**Problem:** Server DPoP nonce expiry returns a 401 with a `DPoP-Nonce` header. If the retry logic is missing or capped, all DPoP-enabled requests will fail after nonce refresh.

**Fix:** Validate that the nonce-retry path in `OAuthManager` and `AuthenticationAPIClient` is exercised by a test that mocks a 401 + new nonce header followed by a successful 200.

## 3. Keystore unavailability — silent fallback to plaintext

**Problem:** On some devices or rooted environments the Android Keystore fails to initialize. Falling back to unencrypted storage is a security regression.

**Fix:** `SecureCredentialsManager` must throw a `CredentialsManagerException` with a clear message when Keystore init fails — never silently downgrade. If you modify `CryptoUtil` or `SecureCredentialsManager`, ensure the error path is explicit.

## 4. Forgetting Java interoperability

**Problem:** Adding a new public API as a `suspend` function only means Java consumers can't call it without a coroutine adapter. This breaks Java sample apps and the majority of existing integrations.

**Fix:** Every new async public method needs both a callback form and a `suspend` form. Verify by checking the Java test files or writing a Java snippet.

## 5. Explicit API mode violation fails silently in IDE but loudly in CI

**Problem:** IntelliJ may not highlight missing visibility modifiers, but `./gradlew compileReleaseKotlin` fails with an explicit error. Agents sometimes miss this because it's only a compile-time check.

**Fix:** After adding any new public class, function, or property, run `./gradlew auth0:compileReleaseKotlin` locally before committing. Every `public` declaration needs an explicit `public` keyword and an explicit return type.

## 6. Token expiry edge cases with session ceiling

**Problem:** Access token expiry check happens at credential retrieval time. If the check is done after the API call (optimistic), an expired token can be used for one request.

**Fix:** Always check expiry before making the call in `CredentialsManager.getCredentials`. Test both the case where the access token is expired-but-refreshable and where the refresh token is also expired (should throw).

## 7. Auth0-Client header missing on new request paths

**Problem:** Creating a new `OkHttpClient` or `NetworkingClient` instance outside the existing `RequestFactory` flow means the `Auth0-Client` header won't be set.

**Fix:** Always route new outbound requests through `RequestFactory`, which attaches `Auth0UserAgent.value` as the `Auth0-Client` header automatically. See `auth0/src/main/java/com/auth0/android/request/internal/RequestFactory.kt`.
