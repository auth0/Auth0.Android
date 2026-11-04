# Signup with Email or Phone OTP

Create a passwordless account in the same `/e/authorize` flow used for sign-in. The sequence is
`authorize` → `signup` → `identify` → `challengeEmail` (or `challengePhone`) → `verifyOtp` →
`confirmSignup` (see [authorize.md](authorize.md) for the next-action pattern).

Each step before `confirmSignup` completes by throwing an `EmbeddedAuthException` whose `error` is
`EmbeddedAuthError.InsufficientAuthorization`; its `nextActions` tell you what to call next.
`confirmSignup` creates the account and returns `Credentials`.

`SIGNUP` and `CONFIRM_SIGNUP` are in the default capabilities. To keep signup out of your app, pass
a `capabilities` set to `authorize` that leaves them out.

```kotlin
val embedded = EmbeddedAuthClient(Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN"))

// 1. Start the flow. When the connection allows sign-ups, the next actions include NextAction.Signup.
try {
    embedded.authorize("Username-Password-Authentication").await()
} catch (e: EmbeddedAuthException) {
    val nextActions = (e.error as? EmbeddedAuthError.InsufficientAuthorization)?.nextActions ?: throw e
    val signup = nextActions.filterIsInstance<NextAction.Signup>().firstOrNull()
    // signup == null: show sign-in only.
    // signup.identifiers: each SignupIdentifier has the `type` to pass to identify() and whether it is `required`.
}

// 2. Start signup. Continues with the identify step.
try {
    embedded.signup().await()
} catch (e: EmbeddedAuthException) {
    when (e.error) {
        is EmbeddedAuthError.InsufficientAuthorization -> { /* continuation → identify */ }
        EmbeddedAuthError.NoNextSteps -> { /* signup isn't available */ }
        else -> { /* other terminal error */ }
    }
}

// 3. Identify the new user. Continues with a ChallengeEmail action.
try {
    embedded.identify("user@example.com", IdentifierType.EMAIL).await()
} catch (e: EmbeddedAuthException) {
    when (e.error) {
        is EmbeddedAuthError.InsufficientAuthorization -> { /* continuation → challengeEmail */ }
        else -> { /* other terminal error */ }
    }
}

// 4. Send the code, using the index from NextAction.ChallengeEmail. Continues with VerifyOtp.
try {
    embedded.challengeEmail(index = 0).await()
} catch (e: EmbeddedAuthException) { /* continuation → verifyOtp */ }

// 5. Verify the code. Continues with NextAction.ConfirmSignup once the identifier is verified.
try {
    embedded.verifyOtp("123456").await()
} catch (e: EmbeddedAuthException) {
    when (val error = e.error) {
        is EmbeddedAuthError.InsufficientAuthorization -> {
            if (error.reason == EmbeddedAuthError.InsufficientAuthorization.Reason.INVALID_IDENTIFIER_OR_CODE) {
                /* wrong or expired code — re-enter it, resend with challengeEmail, or change the email with identify */
            }
            /* error.nextActions contains NextAction.ConfirmSignup once the email is verified */
        }
        EmbeddedAuthError.TooManyWrongOtpAttempts -> { /* restart with authorize() */ }
        else -> { /* other terminal error */ }
    }
}

// 6. Create the account. Returns Credentials.
try {
    val credentials = embedded.confirmSignup().await()
    // credentials.accessToken, credentials.idToken, ...
} catch (e: EmbeddedAuthException) {
    when (e.error) {
        is EmbeddedAuthError.InsufficientAuthorization -> { /* the tenant requires MFA — continue with error.nextActions */ }
        EmbeddedAuthError.InvalidRequest -> { /* the account couldn't be created — restart with authorize() */ }
        EmbeddedAuthError.NoEligibleFactors -> { /* MFA is required but the new user has no factor */ }
        else -> { /* other terminal error */ }
    }
}
```

For phone, call `identify("+15551234567", IdentifierType.PHONE)`, then
`challengePhone(index, deliveryMethod)` with the values from `NextAction.ChallengePhone`. The other
steps are the same.

<details>
  <summary>Using callbacks</summary>

```kotlin
embedded.signup()
    .start(object : Callback<Void?, EmbeddedAuthException> {
        override fun onSuccess(result: Void?) { }
        override fun onFailure(error: EmbeddedAuthException) { /* continuation → identify */ }
    })

embedded.confirmSignup()
    .start(object : Callback<Credentials, EmbeddedAuthException> {
        override fun onSuccess(result: Credentials) { /* account created and signed in */ }
        override fun onFailure(error: EmbeddedAuthException) { /* branch on error.error as in the coroutine sample */ }
    })
```
</details>

<details>
  <summary>Using Java</summary>

```java
Auth0 auth0 = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN");
EmbeddedAuthClient embedded = new EmbeddedAuthClient(auth0);

embedded.signup()
    .start(new Callback<Void, EmbeddedAuthException>() {
        @Override public void onSuccess(Void result) { }
        @Override public void onFailure(@NonNull EmbeddedAuthException e) {
            // continuation → identify(...)
        }
    });

embedded.confirmSignup()
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
