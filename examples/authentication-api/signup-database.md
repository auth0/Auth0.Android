### Sign Up with a database connection

```kotlin
authentication
    .signUp("info@auth0.com", "a secret password", "my-database-connection")
    .validateClaims() //mandatory
    .start(object: Callback<Credentials, AuthenticationException> {
        override fun onFailure(exception: AuthenticationException) { }

        override fun onSuccess(credentials: Credentials) { }
    })
```

<details>
  <summary>Using coroutines</summary>

```kotlin
try {
    val credentials = authentication
        .signUp("info@auth0.com", "a secret password", "my-database-connection")
        .validateClaims()
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
authentication
    .signUp("info@auth0.com", "a secret password", "my-database-connection")
    .validateClaims() //mandatory
    .start(new Callback<Credentials, AuthenticationException>() {
        @Override
        public void onSuccess(@Nullable Credentials payload) {
            //Signed Up & Logged in!
        }

        @Override
        public void onFailure(@NonNull AuthenticationException error) {
            //Error!
        }
    });
```
</details>

> The default scope used is `openid profile email`. Regardless of the scopes set to the request, the `openid` scope is always enforced.
