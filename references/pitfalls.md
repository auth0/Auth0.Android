# Common Pitfalls — Auth0.Android

## 1. Async test race — callback fires after assertion

Always use `Awaitility.await()` for callback tests and `runTest {}` for coroutine tests. A bare `assertThat` after starting a callback operation is a race — the callback may not have fired yet.

## 2. DPoP nonce expiry — missing retry on 401

Server DPoP nonce expiry returns 401 + `DPoP-Nonce` header. Ensure the retry path in `RetryInterceptor` is covered by a test mocking 401-then-200 with a new nonce. Missing it means all DPoP requests fail after nonce refresh.

## 3. Keystore init failure — silent fallback to plaintext

`SecureCredentialsManager` must throw a `CredentialsManagerException` on Keystore init failure — never silently downgrade to unencrypted storage. If you touch `CryptoUtil` or `SecureCredentialsManager`, verify the failure path is explicit.

## 4. Forgetting Java interoperability

Adding a `suspend`-only public method breaks Java consumers. Every new async public method needs both callback and `suspend` forms. Verify by checking or writing a Java test.

## 5. Explicit API mode fails in CI but not always in IDE

IntelliJ may not flag missing visibility modifiers, but `./gradlew auth0:compileReleaseKotlin` will reject them. Run it locally after adding any new public class, function, or property.

## 6. New request path missing Auth0-Client header

Creating an `OkHttpClient` or `NetworkingClient` outside `RequestFactory` bypasses the `Auth0-Client` header. Always route new outbound requests through `RequestFactory`.
