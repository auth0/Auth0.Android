# Signup with a Passkey

Create an account in the same `/e/authorize` flow used for [signup with email or phone OTP](signup.md), and secure it
with a passkey instead of a password. The identifiers are collected and verified as in that guide. Only the last step
differs: after `verifyOtp`, the app creates a passkey with the platform and finishes with
`confirmSignup(PasskeyRegistration)`.

## A password or a passkey

The account is secured with **a password or a passkey, never both**. The user picks one of the choices the confirm offer
carries. `NextAction.ConfirmSignup.password` and `ConfirmSignup.passkey` tell you which ones exist:

| `ConfirmSignup.password` | `ConfirmSignup.passkey` | What the user can choose |
| --- | --- | --- |
| set, `required` is `true` | set | the password **or** the passkey (one of them is needed) |
| set, `required` is `false` | set | the password, the passkey, **or** neither |
| `null` | set | the passkey **or** neither |
| set | `null` | the password (or neither when `required` is `false`): see [signup.md](signup.md#signup-with-a-password) |

- **A passkey satisfies a required password.** When the password is required, a user who creates a passkey doesn't have to
  enter one.
- **A passkey replaces the password.** `confirmSignup(PasskeyRegistration)` sends only the passkey, and the server ignores a
  password sent with one, so the SDK has no way to send both.
- **Neither** is `confirmSignup()` with no password. The server accepts it only when no password is required.

`NextAction.Signup.passkeyRequirement` (`OPTIONAL` or `NONE`) announces the passkey earlier, so the first screen can tell the
user it is possible. **Decide from the latest `ConfirmSignup.passkey`**, not from `passkeyRequirement`: each offer carries its
own options, and a later offer can leave the passkey out.

## Requirements

- The same as for [passkey sign-in](passkey.md#requirements): passkeys enabled on the connection, a custom domain, the app
  registered on the Auth0 application (package name and SHA-256 fingerprint), Android 9 (API 28) or later, and
  `androidx.credentials` in your app.
- The `capabilities` you pass to `authorize` don't control this. `EmbeddedCapability.VERIFY_PASSKEY` covers passkey sign-in
  only, so leaving it out doesn't hide the signup passkey. Check the device yourself before offering it.

## Example

```kotlin
val embedded = EmbeddedAuthClient(Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN"))

// 1. Verify the identifiers as in signup.md. The confirm step arrives as NextAction.ConfirmSignup.
val confirm: NextAction.ConfirmSignup = /* from the error's nextActions */

// 2. Show the choices the offer has. Offer the passkey only when confirm.passkey is not null.
val passkey = confirm.passkey ?: return /* no passkey in this offer: use confirmSignup(password) or confirmSignup() */

// 3. The user chose a passkey. Create it with the options the server sent, unchanged.
val registrationJson = try {
    val result = CredentialManager.create(context).createCredential(
        context,
        CreatePublicKeyCredentialRequest(passkey.requestJson)
    )
    (result as? CreatePublicKeyCredentialResponse)?.registrationResponseJson
        ?: return /* the platform returned something else: offer the other choices */
} catch (e: CreateCredentialCancellationException) {
    /* the user dismissed the sheet: nothing changed, offer the choices again */
    return
} catch (e: CreateCredentialException) {
    /* the ceremony failed, for example "RP ID cannot be validated": offer the other choices */
    return
}

// 4. Create the account with the passkey. Returns Credentials.
try {
    val credentials = embedded.confirmSignup(PasskeyRegistration(registrationJson)).await()
    // credentials.accessToken, credentials.idToken, ...
} catch (e: EmbeddedAuthException) {
    val error = e.error as? EmbeddedAuthError.InsufficientAuthorization ?: throw e
    when (error.reason) {
        EmbeddedAuthError.InsufficientAuthorization.Reason.PASSKEY_REGISTRATION_FAILED -> {
            /* error.nextActions has ConfirmSignup again with the same options: create a NEW passkey (step 3) and
               call confirmSignup again, or choose the password with confirmSignup(password), or neither with
               confirmSignup() when no password is required */
        }
        else -> { /* the tenant requires more steps: continue with error.nextActions */ }
    }
}
```

Finishing with a password or with neither is unchanged, and uses the other `confirmSignup`:

```kotlin
embedded.confirmSignup(password).await()   // the password choice
embedded.confirmSignup().await()           // neither, when no password is required
```

- **A rejected passkey keeps the flow open.** `PASSKEY_REGISTRATION_FAILED` comes back with the same passkey options. Don't
  submit the same result again: the server rejects a passkey it already has. Create a new one, or choose another way to
  finish.
- **The SDK sends only the fields the server accepts** from `registrationResponseJson`. A result that doesn't match is
  rejected locally with `EmbeddedAuthError.InvalidInput`, nothing is sent and the flow is unchanged. With no flow in
  progress, the call completes with `EmbeddedAuthError.NoActiveSession`, whatever the JSON holds.
- **A passkey stays on the device if the signup then fails** for another reason, for example the account can't be created
  (`EmbeddedAuthError.InvalidRequest`, which ends the flow). The app can't remove it.
- **In Java, `confirmSignup(null)` is ambiguous**, because `null` fits both the password and the passkey versions. Call
  `confirmSignup()` for neither, or pass a typed value.

<details>
  <summary>Using callbacks</summary>

```kotlin
embedded.confirmSignup(PasskeyRegistration(registrationJson))
    .start(object : Callback<Credentials, EmbeddedAuthException> {
        override fun onSuccess(result: Credentials) { /* account created and signed in */ }
        override fun onFailure(error: EmbeddedAuthException) { /* branch on error.error as in the coroutine sample */ }
    })
```
</details>

<details>
  <summary>Using Java</summary>

```java
Auth0 auth0 = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN");
EmbeddedAuthClient embedded = new EmbeddedAuthClient(auth0);

// registrationJson is CreatePublicKeyCredentialResponse.getRegistrationResponseJson() from Credential Manager.
embedded.confirmSignup(new PasskeyRegistration(registrationJson))
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
