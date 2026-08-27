## Native to Web SSO login

This feature allows you to authenticate a user in a web session using the refresh token obtained from the native session without requiring the user to log in again.

Call the API to fetch a webSessionTransferToken in exchange for a refresh token. Use the obtained token to authenticate the user by calling the `/authorize` endpoint, passing the token as a query parameter or a cookie value.

```kotlin
    authentication
    .ssoExchange("refresh_token")
    .start(object : Callback<SSOCredentials, AuthenticationException> {
        override fun onSuccess(result: SSOCredentials) {
            // Use the sessionTransferToken token to authenticate the user in a web session in your app
        }

        override fun onFailure(exception: AuthenticationException) {
            // Handle error
        }

    })
```

<details> 
    <summary>Using coroutines</summary> 

``` kotlin 
try {
    val ssoCredentials = authentication
        .ssoExchange("refresh_token")
        .await()
} catch (e: AuthenticationException) {
    e.printStacktrace()
}
```
</details>

<details>
  <summary>Using Java</summary>

```java
authentication
    .ssoExchange("refresh_token")
    .start(new Callback<SSOCredentials, AuthenticationException>() {
        @Override
        public void onSuccess(@Nullable SSOCredentials result) {
            // Handle success
        }
        @Override
        public void onFailure(@NonNull AuthenticationException error) {
            // Handle error
        }
    });
```
</details>
