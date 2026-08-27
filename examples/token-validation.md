## Token Validation
The ID token received as part of the authentication flow is should be verified following the [OpenID Connect specification](https://openid.net/specs/openid-connect-core-1_0.html).

If you are a user of Auth0 Private Cloud with ["Custom Domains"](https://auth0.com/docs/custom-domains) still on the [legacy behavior](https://auth0.com/docs/private-cloud/private-cloud-migrations/migrate-private-cloud-custom-domains#background), you need to override the expected issuer to match your Auth0 domain before starting the authentication.

The validation is done automatically for Web Authentication
```kotlin
val account = Auth0.getInstance("{YOUR_CLIENT_ID}", "{YOUR_CUSTOM_DOMAIN}")

WebAuthProvider.login(account)
    .withIdTokenVerificationIssuer("https://{YOUR_AUTH0_DOMAIN}/")
    .start(this, callback)
```

For Authentication Client, the method `validateClaims()` has to be called to enable it.

```kotlin
val auth0 = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN")
val client = AuthenticationAPIClient(auth0)
client
     .login("{username or email}", "{password}", "{database connection name}")
     .validateClaims()
     .withIdTokenVerificationIssuer("https://{YOUR_AUTH0_DOMAIN}/")
     .start(object : Callback<Credentials, AuthenticationException> {
         override fun onSuccess(result: Credentials) { }
         override fun onFailure(error: AuthenticationException) { }
    })
```

<details>
  <summary>Using coroutines</summary>

```kotlin
val auth0 = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN")
val client = AuthenticationAPIClient(auth0)

try {
    val credentials = client
        .login("{username or email}", "{password}", "{database connection name}")
        .validateClaims()
        .withIdTokenVerificationIssuer("https://{YOUR_AUTH0_DOMAIN}/")
        .await()
    println(credentials)
} catch (e: AuthenticationException) {
    e.printStacktrace()
}
```
</details>

<details>
  <summary>Using Java</summary>

```java
Auth0 auth0 = Auth0.getInstance("client id", "domain");
AuthenticationAPIClient client = new AuthenticationAPIClient(account);
client
   .login("{username or email}", "{password}", "{database connection name}")
   .validateClaims()
   .withIdTokenVerificationIssuer("https://{YOUR_AUTH0_DOMAIN}/")
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
