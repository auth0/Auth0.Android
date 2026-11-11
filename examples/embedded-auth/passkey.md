# Passkey — first factor

Sign the user in with a passkey in the same `/e/authorize` flow used for the other first factors.
The sequence is `authorize` → platform passkey prompt → `verifyPasskey` (see
[authorize.md](authorize.md) for the next-action pattern). There is no identify step: the passkey
identifies the user.

`authorize` completes by throwing an `EmbeddedAuthException` whose `error` is
`EmbeddedAuthError.InsufficientAuthorization`. When passkeys are available, its `nextActions` include a
`NextAction.VerifyPasskey` next to the other first factors. It carries the WebAuthn options as
`requestJson`, which you pass unchanged to the platform. `verifyPasskey` then returns `Credentials`.

## Requirements

- Passkeys are enabled on the connection, and the request is made on a [custom domain](https://auth0.com/docs/customize/custom-domains). Otherwise the server doesn't offer `VerifyPasskey`.
- Android 9 (API 28) or later, which Credential Manager requires. `authorize` asks for passkeys by default, so on earlier versions pass a `capabilities` set that leaves out `EmbeddedCapability.VERIFY_PASSKEY`.
- The user signs in with a **discoverable** passkey, one that stores the user handle. A response without a `userHandle` is rejected with `EmbeddedAuthError.InvalidInput`.
- Your app uses [Credential Manager](https://developer.android.com/identity/sign-in/credential-manager) to run the passkey ceremony. The SDK doesn't depend on it, so add it yourself:

```groovy
dependencies {
    implementation "androidx.credentials:credentials:1.3.0"
    implementation "androidx.credentials:credentials-play-services-auth:1.3.0"
}
```

To keep passkeys out of your app, pass a `capabilities` set to `authorize` that leaves out
`EmbeddedCapability.VERIFY_PASSKEY`.

```kotlin
val embedded = EmbeddedAuthClient(Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN"))

// 1. Start the flow. When passkeys are available, the next actions include NextAction.VerifyPasskey.
val passkey = try {
    embedded.authorize("Username-Password-Authentication").await()
    null
} catch (e: EmbeddedAuthException) {
    val nextActions = (e.error as? EmbeddedAuthError.InsufficientAuthorization)?.nextActions ?: throw e
    nextActions.filterIsInstance<NextAction.VerifyPasskey>().firstOrNull()
}
// passkey == null: passkeys aren't offered; show the other first factors.

// 2. Run the passkey ceremony with the server's options, unchanged.
val assertionJson = try {
    val result = CredentialManager.create(context).getCredential(
        context,
        GetCredentialRequest(listOf(GetPublicKeyCredentialOption(passkey.requestJson)))
    )
    (result.credential as PublicKeyCredential).authenticationResponseJson
} catch (e: GetCredentialCancellationException) {
    /* the user dismissed the sheet — nothing changed, offer it again or another option */
    return
} catch (e: NoCredentialException) {
    /* no passkey for this site on the device — offer the other first factors */
    return
}

// 3. Submit the assertion. Returns Credentials.
try {
    val credentials = embedded.verifyPasskey(assertionJson).await()
    // credentials.accessToken, credentials.idToken, ...
} catch (e: EmbeddedAuthException) {
    when (val error = e.error) {
        is EmbeddedAuthError.InsufficientAuthorization -> {
            if (error.reason == EmbeddedAuthError.InsufficientAuthorization.Reason.INVALID_PASSKEY) {
                /* rejected: error.nextActions has a new NextAction.VerifyPasskey with a fresh challenge — repeat step 2 with it */
            }
            /* otherwise the tenant requires MFA — continue with error.nextActions */
        }
        EmbeddedAuthError.InvalidInput -> { /* the assertion was malformed; nothing was sent and the flow is unchanged */ }
        EmbeddedAuthError.Network -> { /* the request never reached the server — retry verifyPasskey */ }
        else -> { /* other terminal error — restart with authorize() */ }
    }
}
```

## Options

`NextAction.VerifyPasskey` exposes the options the server sent:

| Property | Description |
| --- | --- |
| `requestJson` | The complete options object, ready for `GetPublicKeyCredentialOption`. Use this to run the ceremony. |
| `options.challenge` | The single-use challenge. |
| `options.timeout` | How long, in milliseconds, the ceremony may take. |
| `options.rpId` | The relying party the passkey is scoped to. |
| `options.userVerification` | `REQUIRED`, `PREFERRED` or `DISCOURAGED`. |
| `options.hints` | Preferred authenticator hints. Empty when the server sent none. |
| `options.allowCredentials` | The credentials the server restricts the ceremony to, each as the server sent it. Empty when the server sent none. |

Each challenge works once. After a rejected passkey, use the new `VerifyPasskey` from the error's
`nextActions`; don't reuse the previous `requestJson`.

<details>
  <summary>Using callbacks</summary>

```kotlin
embedded.verifyPasskey(assertionJson)
    .start(object : Callback<Credentials, EmbeddedAuthException> {
        override fun onSuccess(result: Credentials) { /* signed in */ }
        override fun onFailure(error: EmbeddedAuthException) { /* branch on error.error as in the coroutine sample */ }
    })
```
</details>

<details>
  <summary>Using Java</summary>

```java
Auth0 auth0 = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN");
EmbeddedAuthClient embedded = new EmbeddedAuthClient(auth0);

// assertionJson is PublicKeyCredential.getAuthenticationResponseJson() from Credential Manager.
embedded.verifyPasskey(assertionJson)
    .start(new Callback<Credentials, EmbeddedAuthException>() {
        @Override public void onSuccess(Credentials credentials) {
            // credentials.getAccessToken()
        }
        @Override public void onFailure(@NonNull EmbeddedAuthException e) {
            // branch on e.getError() as in the coroutine sample
        }
    });
```
</details>
