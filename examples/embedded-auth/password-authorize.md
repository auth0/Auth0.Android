# Username & Password — first factor

Authenticate with a username and password. The sequence is `authorize` → `identify` (username) →
`verifyPassword`; the server decides what follows by advertising `NextAction` entries (see
[authorize.md](authorize.md) for the next-action pattern).

Each non-terminal step completes by throwing an `EmbeddedAuthException` whose `error` is
`EmbeddedAuthError.InsufficientAuthorization`. `verifyPassword` completes the flow and returns
`Credentials` when no further factor is required; otherwise it throws an `InsufficientAuthorization`
continuation. Always act on that continuation's `nextActions`: after a wrong password they offer
`VerifyPassword` again (possibly alongside other first-factor options), and when the tenant requires
MFA they carry the MFA actions (see
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
} catch (e: EmbeddedAuthException) {
    when (e.error) {
        is EmbeddedAuthError.InsufficientAuthorization -> { /* continuation → VerifyPassword */ }
        EmbeddedAuthError.InvalidRequest -> {
            /* the username was rejected (e.g. "Invalid username format.") — fix the input and identify again */
        }
        EmbeddedAuthError.NoNextSteps -> { /* no step can continue for this user — restart the flow */ }
        else -> { /* other terminal error */ }
    }
}

// 3. Verify the password. Returns Credentials when no further factor is required.
try {
    val credentials = embedded.verifyPassword("the-password").await()
    // credentials.accessToken, credentials.idToken, ...
} catch (e: EmbeddedAuthException) {
    when (val error = e.error) {
        is EmbeddedAuthError.InsufficientAuthorization -> {
            if (error.reason == EmbeddedAuthError.InsufficientAuthorization.Reason.INVALID_IDENTIFIER_OR_PASSWORD) {
                /* wrong username or password — tell the user before re-prompting */
            }
            /* build the next screen from error.nextActions: VerifyPassword to retry, or MFA actions */
        }
        EmbeddedAuthError.PasswordLeaked -> {
            /* breached password detected — send the user to reset their password, then restart */
        }
        EmbeddedAuthError.NoNextSteps -> { /* no step can continue the flow — restart */ }
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
        override fun onFailure(error: EmbeddedAuthException) { /* branch on error.error as in the coroutine sample */ }
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
            // branch on e.getError() as in the coroutine sample
        }
    });
```
</details>
