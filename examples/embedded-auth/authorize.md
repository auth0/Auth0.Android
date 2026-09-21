### Embedded Authorization (EA)

> [!IMPORTANT]
> Embedded Authorization is currently in [Early Access](https://auth0.com/docs/troubleshoot/product-lifecycle/product-release-stages#early-access). Please reach out to Auth0 support to get it enabled for your tenant.

The embedded authorization flow (`/e/authorize`) lets your app authenticate users without leaving the app for a browser. The server drives the flow step-by-step: each call completes through an `EmbeddedAuthException` that carries the next action to take, until the terminal  call succeeds and returns `Credentials`.

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
    if (e.isInsufficientAuthorization) {
        // Flow is in progress — inspect e.nextActions for the next step.
    } else {
        // Terminal error — e.g. access_denied, network failure.
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

Each non-terminal step throws `EmbeddedAuthException` with `isInsufficientAuthorization = true` and a list of `NextAction` entries describing what the server will accept next. Iterate them to build your UI:

```kotlin
for (action in exception.nextActions) {
    when (action) {
        is NextAction.IdentifyEmail  -> { /* show email field, call identifyEmail() */ }
        is NextAction.IdentifyPhone  -> { /* show phone field, call identifyPhone() */ }
        is NextAction.ChallengeEmail -> { /* show "send code" button, call challengeEmail(action.index ?: 0) */ }
        is NextAction.VerifyOtp      -> { /* show OTP field, call verifyOtp() */ }
        is NextAction.Unknown        -> { /* unsupported — skip or show disabled */ }
    }
}
```

#### Identify the user

After `authorize()` returns a continuation with `NextAction.IdentifyEmail`:

```kotlin
try {
    client.identifyEmail("jane@example.com").await()
} catch (e: EmbeddedAuthException) {
    if (e.isInsufficientAuthorization) {
        // Continue with e.nextActions (e.g. ChallengeEmail or VerifyOtp).
    }
}
```

Or by phone number when `NextAction.IdentifyPhone` is present:

```kotlin
client.identifyPhone("+15550001234").await()
```

#### Request an email challenge

When `NextAction.ChallengeEmail` is present, ask the server to send a one-time code:

```kotlin
// action.index selects which email authenticator to challenge (defaults to 0).
client.challengeEmail(action.index ?: 0).await()
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

If the server still requires further steps it throws `EmbeddedAuthException` with `isInsufficientAuthorization = true`, just like the earlier steps.

#### Terminal errors

Some errors end the flow and must not be retried without restarting from `authorize()`:

```kotlin
when {
    e.isAccessDenied      -> { /* deny — do not retry */ }
    e.isTooManyAttempts   -> { /* too many failed OTP attempts */ }
    e.isTooManyLogins     -> { /* too many login attempts */ }
    e.isNetworkError      -> { /* transient — safe to retry the same step */ }
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
            if (exception.isInsufficientAuthorization) {
                // Handle exception.nextActions.
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
            if (e.isInsufficientAuthorization()) {
                for (NextAction action : e.getNextActions()) {
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
