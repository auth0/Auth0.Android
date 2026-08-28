## Bot Protection
If you are using the [Bot Protection](https://auth0.com/docs/anomaly-detection/bot-protection) feature and performing database login/signup via the Authentication API, you need to handle the `AuthenticationException#isVerificationRequired()` error. It indicates that the request was flagged as suspicious and an additional verification step is necessary to log the user in. That verification step is web-based, so you need to use Universal Login to complete it.

```kotlin
val email = "info@auth0.com"
val password = "a secret password"
val realm = "my-database-connection"

val authentication = AuthenticationAPIClient(account)
authentication.login(email, password, realm).validateClaims()
    .start(object: Callback<Credentials, AuthenticationException> {
        override fun onFailure(exception: AuthenticationException) {
            if (exception.isVerificationRequired()) {
                val params = mapOf("login_hint" to email) // So the user doesn't have to type it again
                WebAuthProvider.login(account)
                    .withConnection(realm)
                    .withParameters(params)
                    .start(LoginActivity.this, object: Callback<Credentials, AuthenticationException> {
                        // You might already have a Callback instance defined

                        override fun onFailure(exception: AuthenticationException) {
                            // Handle error
                        }

                        override fun onSuccess(credentials: Credentials) {
                            // Handle WebAuth success
                        }
                    })
            }
            // Handle other errors
        }

        override fun onSuccess(credentials: Credentials) {
            // Handle API success
        }
    })
```

<details>
  <summary>Using Java</summary>

```java
final String email = "info@auth0.com";
final String password = "a secret password";
final String realm = "my-database-connection";

AuthenticationAPIClient authentication = new AuthenticationAPIClient(account);
authentication.login(email, password, realm).validateClaims()
        .start(new Callback<Credentials, AuthenticationException>() {

            @Override
            public void onSuccess(@Nullable Credentials payload) {
                // Handle API success
            }

            @Override
            public void onFailure(@NonNull AuthenticationException error) {
                if (error.isVerificationRequired()){
                    Map<String, Object> params = new HashMap<>();
                    params.put("login_hint", email); // So the user doesn't have to type it again
                    WebAuthProvider.login(account)
                            .withConnection(realm)
                            .withParameters(params)
                            .start(LoginActivity.this, new AuthCallback() {
                                // You might already have an AuthCallback instance defined

                                @Override
                                public void onFailure(@NonNull Dialog dialog) {
                                    // Error dialog available
                                }

                                @Override
                                public void onFailure(AuthenticationException exception) {
                                    // Error
                                }

                                @Override
                                public void onSuccess(@NonNull Credentials credentials) {
                                    // Handle WebAuth success
                                }
                            });
                }
            }
        });
```
</details>

In the case of signup, you can add [an additional parameter](https://auth0.com/docs/universal-login/new-experience#signup) to make the user land directly on the signup page:

```kotlin
val params = mapOf(
    "login_hint" to email, 
    "screen_hint" to "signup"
)
```

<details>
  <summary>Using Java</summary>

```java
params.put("login_hint", email);
params.put("screen_hint", "signup");
```
</details>
