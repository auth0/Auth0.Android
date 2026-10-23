# Time-based One-Time Password (TOTP)

TOTP (authenticator-app codes) reuses the existing `verifyOtp` — only the `OtpType` differs.
When the flow reaches a TOTP challenge, the server advertises a `NextAction.VerifyOtp` with
`channel = TOTP`; the user reads the 6-digit code from their authenticator app and you verify
it. `verifyOtp` is terminal: it returns `Credentials` on success.

```kotlin
val embedded = EmbeddedAuthClient(Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN"))

try {
    val credentials = embedded.verifyOtp(code = "123456", type = OtpType.TOTP).await()
    // credentials.accessToken, credentials.idToken, ...
} catch (e: EmbeddedAuthException) {
    when (e.error) {
        is EmbeddedAuthError.InsufficientAuthorization -> { /* wrong code or more MFA — re-prompt */ }
        EmbeddedAuthError.TooManyWrongOtpAttempts -> { /* too many wrong codes */ }
        else -> { /* other terminal error */ }
    }
}
```

<details>
  <summary>Using Java</summary>

```java
Auth0 auth0 = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN");
EmbeddedAuthClient embedded = new EmbeddedAuthClient(auth0);

embedded.verifyOtp("123456", OtpType.TOTP)
    .start(new Callback<Credentials, EmbeddedAuthException>() {
        @Override public void onSuccess(Credentials credentials) {
            // credentials.getAccessToken()
        }
        @Override public void onFailure(@NonNull EmbeddedAuthException e) { }
    });
```
</details>
