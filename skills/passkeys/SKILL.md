---
name: passkeys
description: >-
  Use when adding passkeys to an Auth0.Android app: signing in with a passkey,
  signing up a new user with a passkey, or enrolling a passkey for an already
  signed-in user through the My Account API. Covers AuthenticationAPIClient
  passkeyChallenge, signupWithPasskey, signinWithPasskey, MyAccountAPIClient, the
  AndroidX Credential Manager ceremony, and identifier verification on signup.
metadata:
  type: sub-skill
  library: Auth0.Android
  library_version: 4.3.1
requires:
  - auth0-android
---

# Auth0.Android - Passkeys

Reference: [`examples/passkeys.md`](https://github.com/auth0/Auth0.Android/blob/main/examples/passkeys.md) and [`examples/my-account-api.md`](https://github.com/auth0/Auth0.Android/blob/main/examples/my-account-api.md).

Requirements: a custom domain, the **Passkeys** grant enabled on the application, Android Device Settings configured for the application, and Android 9 (API 28) or higher for passkey calls. The Digital Asset Links file must be served and verified for the custom domain.

Pattern: Auth0 challenge, then the AndroidX Credential Manager ceremony, then Auth0 sign-in or enroll with the credential. The SDK removed `PasskeyAuthProvider`, `PasskeyProvider` and `PasskeyManager` in v4.

## Gradle

Credential Manager is not a dependency of the SDK, and Gson is not exposed on your compile classpath. Add to the app module:

```groovy
implementation 'androidx.credentials:credentials:1.3.0'
implementation 'androidx.credentials:credentials-play-services-auth:1.3.0'
implementation 'com.google.code.gson:gson:2.11.0'
```

`PublicKeyCredentials` is `com.auth0.android.request.PublicKeyCredentials`.

## Sign in

```kotlin
val authentication = AuthenticationAPIClient(account)

val challenge = authentication.passkeyChallenge(realm = "Username-Password-Authentication").await()

val option = GetPublicKeyCredentialOption(Gson().toJson(challenge.authParamsPublicKey))
val result = credentialManager.getCredential(context, GetCredentialRequest(listOf(option)))
val response = (result.credential as PublicKeyCredential).authenticationResponseJson

val credentials = authentication
    .signinWithPasskey(challenge.authSession, Gson().fromJson(response, PublicKeyCredentials::class.java), "Username-Password-Authentication")
    .validateClaims()
    .setScope("openid profile email offline_access")
    .await()
credentialsManager.saveCredentials(credentials)
```

`passkeyChallenge(realm: String? = null, organization: String? = null)`. `signinWithPasskey(authSession, authResponse, realm?, organization?, verification, verificationRequired)`; `authSession` is first. `authResponse` can be a `PublicKeyCredentials` or the raw JSON `String`.

## Sign up

```kotlin
val challenge = authentication
    .signupWithPasskey(UserData(email = "user@example.com"), realm = "Username-Password-Authentication")
    .await()

val request = CreatePublicKeyCredentialRequest(Gson().toJson(challenge.authParamsPublicKey))
val created = credentialManager.createCredential(context, request) as CreatePublicKeyCredentialResponse
val response = Gson().fromJson(created.registrationResponseJson, PublicKeyCredentials::class.java)

val credentials = authentication
    .signinWithPasskey(challenge.authSession, response, "Username-Password-Authentication")
    .validateClaims()
    .await()
```

`signupWithPasskey(userData: UserData, realm?, organization?, deliveryMethod?)`. `UserData` is `com.auth0.android.request.UserData`, not a Map.

### Identifier verification

If the connection requires verified email or phone, `challenge.verificationRequired` lists `PasskeyVerificationMethod` values. Collect the OTP codes before creating the platform credential, then pass `verification = codes` and `verificationRequired = challenge.verificationRequired.orEmpty()` to `signinWithPasskey`. On `error.isPasskeyVerificationRetryable`, re-collect the codes in `error.passkeyVerificationRequired` and retry with the same credential and `error.passkeyAuthSession`, not the original `challenge.authSession`. Any other error means restarting from `signupWithPasskey`. Optional `deliveryMethod`: `DeliveryMethod.TEXT` or `VOICE`.

## Enroll a passkey for a signed-in user

Uses the same create ceremony, but goes through `MyAccountAPIClient` with a My Account token. It does not create an account and returns no new `Credentials`. `awaitApiCredentials` exchanges the refresh token, so sign-in must request `offline_access`. If that refresh token was issued for another audience, Multi-Resource Refresh Token must be configured for the My Account API on the tenant.

```kotlin
val api = credentialsManager.awaitApiCredentials(
    audience = "https://YOUR_CUSTOM_DOMAIN/me/",
    scope = "create:me:authentication_methods"
)

val myAccount = MyAccountAPIClient(account, api.accessToken)
val challenge = myAccount.passkeyEnrollmentChallenge().await()

val request = CreatePublicKeyCredentialRequest(Gson().toJson(challenge.authParamsPublicKey))
val created = credentialManager.createCredential(context, request) as CreatePublicKeyCredentialResponse
val credential = Gson().fromJson(created.registrationResponseJson, PublicKeyCredentials::class.java)

val method = myAccount.enroll(credential, challenge).await() // PasskeyAuthenticationMethod
```

`passkeyEnrollmentChallenge(userIdentity: String? = null, connection: String? = null)` throws `MyAccountException`. Pass `userIdentity` when the user logged in through a linked account.

## Common mistakes

- Omitting `.validateClaims()` on `signinWithPasskey`.
- Using the login access token for enrollment instead of one for the `/me/` audience with `create:me:authentication_methods`.
- Calling `signupWithPasskey` to add a passkey to an existing user; that creates a new account.
- Crossing `getCredential` (sign-in) and `createCredential` (signup, enroll).
- Passing the ceremony JSON as the credential without parsing it into `PublicKeyCredentials` (or using the `String` overload).
- Missing or unverified Digital Asset Links on the custom domain; Credential Manager refuses the ceremony.
- Expecting a dedicated MFA exception. If the tenant adds a second factor, `AuthenticationException.isMultifactorRequired` is true; continue with the [mfa](../mfa/SKILL.md) skill.
