# Username & Password — first factor

Authenticate with a username and password. The sequence is `authorize` → `identify` (username) →
`verifyPassword`; the server decides what follows by advertising `NextAction` entries (see
[authorize.md](authorize.md) for the next-action pattern).

Each non-terminal step completes by throwing an `EmbeddedAuthException` whose `error` is
`EmbeddedAuthError.InsufficientAuthorization`. `verifyPassword` is terminal when no further factor is
required and returns `Credentials`; if the tenant requires MFA it instead throws an
`InsufficientAuthorization` continuation carrying the MFA next actions (see
[phone-authorize.md](phone-authorize.md), [push-oob-polling.md](push-oob-polling.md),
[totp.md](totp.md), [recovery-code.md](recovery-code.md)).

```kotlin
val embedded = EmbeddedAuthClient(Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN"))

// 1. Start the flow — always continues with the next actions (e.g. IdentifyUsername).
try {
    embedded.authorize("Username-Password-Authentication").await()
} catch (e: EmbeddedAuthException) { /* inspect (e.error as InsufficientAuthorization).nextActions */ }

// 2. Identify by username. The server continues with a VerifyPassword action.
try {
    embedded.identify("jane", IdentifierType.USERNAME).await()
} catch (e: EmbeddedAuthException) { /* continuation → VerifyPassword */ }

// 3. Verify the password. Terminal — returns Credentials on success.
try {
    val credentials = embedded.verifyPassword("the-password").await()
    // credentials.accessToken, credentials.idToken, ...
} catch (e: EmbeddedAuthException) {
    when (val error = e.error) {
        is EmbeddedAuthError.InsufficientAuthorization -> {
            if (error.reason == EmbeddedAuthError.InsufficientAuthorization.Reason.INVALID_IDENTIFIER_OR_PASSWORD) {
                /* wrong username or password — re-prompt and call verifyPassword again */
            } else {
                /* more MFA required — act on error.nextActions */
            }
        }
        else -> { /* other terminal error */ }
    }
}
```

<details>
  <summary>Using callbacks</summary>

```kotlin
embedded.identify("jane", IdentifierType.USERNAME)
    .start(object : Callback<Void?, EmbeddedAuthException> {
        override fun onSuccess(result: Void?) { }
        override fun onFailure(error: EmbeddedAuthException) { /* continuation → VerifyPassword */ }
    })

embedded.verifyPassword("the-password")
    .start(object : Callback<Credentials, EmbeddedAuthException> {
        override fun onSuccess(result: Credentials) { /* signed in */ }
        override fun onFailure(error: EmbeddedAuthException) { /* wrong password or MFA required */ }
    })
```
</details>

<details>
  <summary>Using Java</summary>

```java
Auth0 auth0 = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN");
EmbeddedAuthClient embedded = new EmbeddedAuthClient(auth0);

embedded.identify("jane", IdentifierType.USERNAME)
    .start(new Callback<Void, EmbeddedAuthException>() {
        @Override public void onSuccess(Void result) { }
        @Override public void onFailure(@NonNull EmbeddedAuthException e) {
            // continuation → verifyPassword(...)
        }
    });

embedded.verifyPassword("the-password")
    .start(new Callback<Credentials, EmbeddedAuthException>() {
        @Override public void onSuccess(Credentials credentials) {
            // credentials.getAccessToken()
        }
        @Override public void onFailure(@NonNull EmbeddedAuthException e) {
            // wrong password, or MFA required
        }
    });
```
</details>
