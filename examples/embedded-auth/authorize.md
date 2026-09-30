### Embedded Authorization (Beta)

> [!IMPORTANT]
> Embedded Authorization is currently in [Beta](https://auth0.com/docs/troubleshoot/product-lifecycle/product-release-stages#beta). Please reach out to Auth0 support to get it enabled for your tenant.

The embedded authorization flow (`/e/authorize`) lets your app authenticate users without leaving the app for a browser. The server drives the flow step-by-step: each call completes through an `EmbeddedAuthException` whose typed `error` property (an `EmbeddedAuthError`) tells you whether the flow can continue — and, when it can, carries the next action to take — until the terminal call succeeds and returns `Credentials`.

`EmbeddedAuthError` is a sealed interface. Branch on it with a `when`. The recoverable case, `EmbeddedAuthError.InsufficientAuthorization`, carries the `nextActions` list; the terminal cases do not. `Network` signals the request never reached the server, so the same step is safe to retry.

The flow is served by `EmbeddedAuthClient`, created from an `Auth0` instance:

```kotlin
val account = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN")
val client = EmbeddedAuthClient(account)
```

#### Start the flow

Call `authorize()` with the connection name. The `scope` defaults to `"openid profile email offline_access"`; pass a custom value if you need a different scope or an `audience`.

```kotlin
try {
    client.authorize("Username-Password-Authentication").await()
} catch (e: EmbeddedAuthException) {
    when (val error = e.error) {
        is EmbeddedAuthError.InsufficientAuthorization -> {
            // Flow is in progress — inspect error.nextActions for the next step.
        }
        else -> {
            // Terminal error — e.g. AccessDenied, SessionExpired, Network.
        }
    }
}
```

With custom scope and audience:

```kotlin
client.authorize(
    connection = "Username-Password-Authentication",
    scope = "openid profile email offline_access",
    audience = "https://api.example.com"
).await()
```

#### Handle next actions

Each non-terminal step throws `EmbeddedAuthException` whose `error` is `EmbeddedAuthError.InsufficientAuthorization`, carrying a list of `NextAction` entries describing what the server will accept next. Iterate them to build your UI:

```kotlin
val error = exception.error
if (error is EmbeddedAuthError.InsufficientAuthorization) {
    for (action in error.nextActions) {
        when (action) {
            is NextAction.IdentifyEmail  -> { /* show email field, call identify() */ }
            is NextAction.ChallengeEmail -> { /* show "send code" button, call challengeEmail(action.index) */ }
            is NextAction.VerifyOtp      -> { /* show OTP field, call verifyOtp() */ }
            is NextAction.Unknown        -> { /* unsupported — skip or show disabled */ }
        }
    }
}
```

#### Identify the user

After `authorize()` returns a continuation with `NextAction.IdentifyEmail`:

```kotlin
try {
    client.identify("jane@example.com", IdentifierType.EMAIL).await()
} catch (e: EmbeddedAuthException) {
    val error = e.error
    if (error is EmbeddedAuthError.InsufficientAuthorization) {
        // Continue with error.nextActions (e.g. ChallengeEmail or VerifyOtp).
    }
}
```

```kotlin
client.identifyPhone("+15550001234").await()
```

#### Request an email challenge

When `NextAction.ChallengeEmail` is present, ask the server to send a one-time code:

```kotlin
// action.index selects which email authenticator to challenge (0 if not specified by the server).
client.challengeEmail(action.index).await()
```

#### Verify the one-time code

`verifyOtp` is a terminal step. On success, it returns `Credentials` directly without throwing:

```kotlin
val credentials = client.verifyOtp(
    code = "123456",
    type = OtpType.OOB   // OOB for emailed codes; TOTP for authenticator-app codes
).await()

// credentials.accessToken, credentials.idToken, etc. are now available.
```

If the server still requires further steps it throws `EmbeddedAuthException` whose `error` is `EmbeddedAuthError.InsufficientAuthorization`, just like the earlier steps. A wrong code comes back as that same continuation — the flow is still recoverable, so re-prompt and retry with the `nextActions` the case carries. 


#### Terminal errors

Some errors end the flow and must not be retried without restarting from `authorize()`:

```kotlin
when (e.error) {
    EmbeddedAuthError.TooManyWrongOtpAttempts -> { /* too many wrong codes — flow denied */ }
    EmbeddedAuthError.ChallengeExpired        -> { /* the code expired — restart the flow */ }
    EmbeddedAuthError.AccessDenied            -> { /* denied for another reason — do not retry */ }
    EmbeddedAuthError.TooManyAttempts         -> { /* rate-limited by attack protection */ }
    EmbeddedAuthError.TooManyLogins           -> { /* too many login attempts */ }
    EmbeddedAuthError.SessionExpired          -> { /* the grant expired — restart via authorize() */ }
    EmbeddedAuthError.Network                 -> { /* transient — safe to retry the same step */ }
    else                                      -> { /* Unknown/unclassified — inspect e.code and e.description */ }
}
```

<details>
  <summary>Using callbacks</summary>

```kotlin
client
    .authorize("Username-Password-Authentication")
    .start(object : Callback<Void?, EmbeddedAuthException> {
        override fun onSuccess(result: Void?) {
            // Unexpected — authorize always continues through onFailure.
        }
        override fun onFailure(exception: EmbeddedAuthException) {
            val error = exception.error
            if (error is EmbeddedAuthError.InsufficientAuthorization) {
                // Handle error.nextActions.
            }
        }
    })
```

Terminal step with callbacks:

```kotlin
client
    .verifyOtp("123456", OtpType.OOB)
    .start(object : Callback<Credentials, EmbeddedAuthException> {
        override fun onSuccess(result: Credentials) {
            // Authenticated.
        }
        override fun onFailure(exception: EmbeddedAuthException) {
            // Handle continuation or terminal error.
        }
    })
```
</details>

<details>
  <summary>Using Java</summary>

```java
Auth0 account = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN");
EmbeddedAuthClient client = new EmbeddedAuthClient(account);

client
    .authorize("Username-Password-Authentication")
    .start(new Callback<Void, EmbeddedAuthException>() {
        @Override
        public void onSuccess(Void result) { }

        @Override
        public void onFailure(@NonNull EmbeddedAuthException e) {
            if (e.getError() instanceof EmbeddedAuthError.InsufficientAuthorization ia) {
                for (NextAction action : ia.getNextActions()) {
                    // Handle each action.
                }
            }
        }
    });

// Terminal step
client
    .verifyOtp("123456", OtpType.OOB)
    .start(new Callback<Credentials, EmbeddedAuthException>() {
        @Override
        public void onSuccess(Credentials credentials) {
            // Authenticated.
        }

        @Override
        public void onFailure(@NonNull EmbeddedAuthException e) { }
    });
```
</details>
