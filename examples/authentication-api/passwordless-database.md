### Passwordless Login with a Database Connection (EA)

> [!IMPORTANT]
> Passwordless Login for database connections is currently in [Early Access](https://auth0.com/docs/troubleshoot/product-lifecycle/product-release-stages#early-access). Please reach out to Auth0 support to get it enabled for your tenant.

This flow lets users authenticate with a one-time code sent over email or SMS/voice against a **database connection** that has `email_otp` or `phone_otp` enabled. It is distinct from the [`/passwordless/start` flow](passwordless.md#passwordless-login), which uses dedicated passwordless connections.

Obtain a `PasswordlessClient` from the `AuthenticationAPIClient`:

```kotlin
val passwordless = AuthenticationAPIClient(account).passwordlessClient()
```

The flow has two steps: first issue an OTP challenge, then — after the user enters the code they received — exchange it for credentials. **Save the `PasswordlessChallenge` from step 1**, as you pass that same object into `loginWithOTP` in step 2.

#### Step 1: Issue an OTP challenge

Send a one-time code to the user's email. For privacy, the server **always responds successfully regardless of whether the user exists**. On success, save the returned `PasswordlessChallenge` for step 2.

```kotlin
// keep this reference until the user enters the code
var challenge: PasswordlessChallenge? = null

passwordless
    .challengeWithEmail("info@auth0.com", "my-database-connection")
    .start(object: Callback<PasswordlessChallenge, AuthenticationException> {
        override fun onFailure(exception: AuthenticationException) { }

        override fun onSuccess(result: PasswordlessChallenge) {
            challenge = result
        }
    })
```

To send the code over SMS or voice instead, use `challengeWithPhoneNumber` against a connection with `phone_otp` enabled, choosing the `DeliveryMethod`:

```kotlin
passwordless
    .challengeWithPhoneNumber("+15555550123", "my-database-connection", DeliveryMethod.TEXT)
    .start(object: Callback<PasswordlessChallenge, AuthenticationException> {
        override fun onFailure(exception: AuthenticationException) { }

        override fun onSuccess(result: PasswordlessChallenge) {
            challenge = result
        }
    })
```

Both challenge methods accept an optional `allowSignup` parameter (defaults to `false`) that controls whether a new user is created if one does not yet exist.

#### Step 2: Verify the code and log in

Once the user enters the code, pass the saved `challenge` together with that code to `loginWithOTP` to obtain `Credentials`. If DPoP is enabled on the originating `AuthenticationAPIClient`, a DPoP proof is attached automatically to this token request.

```kotlin
val savedChallenge = requireNotNull(challenge) { "Complete step 1 before verifying the code" }

passwordless
    .loginWithOTP(savedChallenge, "123456")
    .start(object: Callback<Credentials, AuthenticationException> {
        override fun onFailure(exception: AuthenticationException) { }

        override fun onSuccess(credentials: Credentials) { }
    })
```

<details>
  <summary>Using coroutines</summary>

```kotlin
// Step 1: issue the challenge and keep it
val challenge = passwordless
    .challengeWithEmail("info@auth0.com", "my-database-connection")
    .await()

// Step 2: once the user enters the code, pass the saved challenge back to log in
val credentials = passwordless
    .loginWithOTP(challenge, "123456")
    .await()
```
</details>

<details>
  <summary>Using Java</summary>

```java
// Step 1: issue the challenge and keep it
passwordless
    .challengeWithEmail("info@auth0.com", "my-database-connection", false)
    .start(new Callback<PasswordlessChallenge, AuthenticationException>() {
        @Override
        public void onSuccess(PasswordlessChallenge result) {
            challenge = result;
        }

        @Override
        public void onFailure(@NonNull AuthenticationException error) {
            //Error!
        }
    });

// Step 2: once the user enters the code, pass the saved challenge back to log in
passwordless
    .loginWithOTP(challenge, "123456")
    .start(new Callback<Credentials, AuthenticationException>() {
        @Override
        public void onSuccess(@Nullable Credentials payload) {
            //Logged in!
        }

        @Override
        public void onFailure(@NonNull AuthenticationException error) {
            //Error!
        }
    });
```
</details>

> The default scope used is `openid profile email`. Regardless of the scopes set to the request, the `openid` scope is always enforced.
