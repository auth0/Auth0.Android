## DPoP

[DPoP](https://www.rfc-editor.org/rfc/rfc9449.html) (Demonstrating Proof of Possession) is an application-level mechanism for sender-constraining OAuth 2.0 access and refresh tokens by proving that the app is in possession of a certain private key. You can enable it by calling the `useDPoP(context: Context)` method. This ensures that DPoP proofs are generated for requests made through the AuthenticationAPI client.

```kotlin
val client = AuthenticationAPIClient(account).useDPoP(context)
```

[!IMPORTANT]
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

On logout, you should call `DPoP.clearKeyPair()` to delete the user's key pair from the Keychain.

```kotlin

DPoP.clearKeyPair()

```

To use DPoP with `SecureCredentialsManager` you need to pass an instance of the `AuthenticationAPIClient` with DPoP enabled to the `SecureCredentialsManager` constructor.

```kotlin
val auth0 = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN")
val apiClient = AuthenticationAPIClient(auth0).useDPoP(this)
val storage = SharedPreferencesStorage(this)
val manager = SecureCredentialsManager(apiClient, this, storage)
```

Similarly, for `CredentialsManager`:

```kotlin
val auth0 = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN")
val apiClient = AuthenticationAPIClient(auth0).useDPoP(this)
val storage = SharedPreferencesStorage(this)
val manager = CredentialsManager(apiClient, storage)
```

> [!IMPORTANT]
> When credentials are DPoP-bound, the SDK validates the DPoP key state before each token refresh. If the DPoP key pair is lost, the SDK will throw `CredentialsManagerException.DPOP_KEY_MISSING` and the user must re-authenticate. If the key pair has changed since the credentials were saved, the SDK will throw `CredentialsManagerException.DPOP_KEY_MISMATCH`. If the `AuthenticationAPIClient` was not configured with `useDPoP()`, the SDK will throw `CredentialsManagerException.DPOP_NOT_CONFIGURED`.

> [!NOTE]
> DPoP is supported only on Android version 6.0 (API level 23) and above. Trying to use DPoP in any older versions will result in an exception.
