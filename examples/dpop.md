## DPoP

[DPoP](https://www.rfc-editor.org/rfc/rfc9449.html) (Demonstrating Proof of Possession) is an application-level mechanism for sender-constraining OAuth 2.0 access and refresh tokens by proving that the app is in possession of a certain private key. You can enable it by calling the `useDPoP(context)` method on the login Builder.

```kotlin
WebAuthProvider
    .login(account)
    .useDPoP(requireContext())
    .start(requireContext(), object : Callback<Credentials, AuthenticationException> {
        override fun onSuccess(result: Credentials) {
           println("Credentials $result")
        }
        override fun onFailure(error: AuthenticationException) {
            print("Error $error")
        }
    })
```

> [!IMPORTANT]
> DPoP will only be used for new user sessions created after enabling it. DPoP **will not** be applied to any requests involving existing access and refresh tokens (such as exchanging the refresh token for new credentials).
>
> This means that, after you've enabled it in your app, DPoP will only take effect when users log in again. It's up to you to decide how to roll out this change to your users. For example, you might require users to log in again the next time they open your app. You'll need to implement the logic to handle this transition based on your app's requirements.

When making requests to your own APIs, use the `DPoP.getHeaderData()` method to get the `Authorization` and `DPoP` header values to be used. The `Authorization` header value is generated using the access token and token type, while the `DPoP` header value is the generated DPoP proof.

```kotlin
val url ="https://example.com/api/endpoint"
val httpMethod = "GET"
 val headerData = DPoP.getHeaderData(
                    httpMethod, url,
                    accessToken, tokenType
                )
httpRequest.apply{
    addHeader("Authorization", headerData.authorizationHeader)
    headerData.dpopProof?.let {
        addHeader("DPoP", it)
    }
}
```
If your API is issuing DPoP nonces to prevent replay attacks, you can pass the nonce value to the `getHeaderData()` method to include it in the DPoP proof. Use the `DPoP.isNonceRequiredError(response: Response)` method to check if a particular API response failed because a nonce is required.

```kotlin
if (DPoP.isNonceRequiredError(response)) {
    val nonce = response.headers["DPoP-Nonce"]
    val dpopProof = DPoPProvider.generateProof(
        url, httpMethod, accessToken, nonce
    )
    // Retry the request with the new proof
}
```

When using DPoP with `CredentialsManager` or `SecureCredentialsManager`, the `AuthenticationAPIClient` passed to the credentials manager **must** also have DPoP enabled. Otherwise, token refresh requests will be sent without the DPoP proof and the SDK will throw a `CredentialsManagerException.DPOP_NOT_CONFIGURED` error.

```kotlin

val auth0 = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN")
val apiClient = AuthenticationAPIClient(auth0).useDPoP(context)  // DPoP enabled
val storage = SharedPreferencesStorage(context)
val manager = CredentialsManager(apiClient, storage)

WebAuthProvider
    .useDPoP()
    .login(auth0)
    .start(context, callback)
```

On logout, you should call `DPoP.clearKeyPair()` to delete the user's key pair from the Keychain.

```kotlin
WebAuthProvider.logout(account)
            .start(requireContext(), object : Callback<Void?, AuthenticationException> {
                override fun onSuccess(result: Void?) {
                    DPoPProvider.clearKeyPair()
                }
                override fun onFailure(error: AuthenticationException) {
                }

            })
```
> [!NOTE]
> DPoP is supported only on Android version 6.0 (API level 23) and above. Trying to use DPoP in any older versions will result in an exception.
