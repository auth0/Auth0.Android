## Native to Web SSO login

This feature allows you to authenticate a user in a web session using the refresh token obtained from the native session without requiring the user to log in again.

Call the API to fetch a webSessionTransferToken in exchange for a refresh token. Use the obtained token to authenticate the user by calling the `/authorize` endpoint, passing the token as a query parameter or a cookie value.

> [!CAUTION]
> Passing the token in the query string can leak it through browser history, `Referer` headers, and server or proxy logs. If you use query-string delivery, send it only to a trusted HTTPS target, redeem it immediately, strip it from the URL after use, and redact it from any logs. Prefer cookie delivery when you can.

> [!TIP]
> If you store the user's credentials with a credentials manager, use [SSO credentials](../credentials-manager.md#sso-credentials) instead. It reads the refresh token for you, stores the rotated one, and serializes concurrent requests. The method below does none of that.

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
    e.printStackTrace()
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

> [!IMPORTANT]
> You don't need to store the `SSOCredentials`, as the session transfer token is single-use and short-lived. However, if you use [refresh token rotation](https://auth0.com/docs/secure/tokens/refresh-tokens/refresh-token-rotation), the response contains a new refresh token that you must store in place of the previous one, which is now invalid.
