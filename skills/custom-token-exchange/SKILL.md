---
name: custom-token-exchange
description: >-
  Use when exchanging an external or legacy token (subject token) for Auth0
  tokens in an Auth0.Android app with AuthenticationAPIClient.customTokenExchange:
  migrating from another identity system, signing in with a token from a trusted
  partner, or optionally scoping the exchange to an organization.
metadata:
  type: sub-skill
  library: Auth0.Android
  library_version: 4.3.1
requires:
  - auth0-android
---

# Auth0.Android - Custom Token Exchange

Reference: [`examples/authentication-api/custom-token-exchange.md`](https://github.com/auth0/Auth0.Android/blob/main/examples/authentication-api/custom-token-exchange.md). Tenant setup (a Custom Token Exchange profile and the action that validates the subject token) is configured in Auth0, not in the app.

## Signature

```kotlin
fun customTokenExchange(
    subjectTokenType: String,
    subjectToken: String,
    organization: String? = null,
    actorToken: ActorToken? = null
): AuthenticationRequest
```

The token type comes first, then the token. This is the reverse of `loginWithNativeSocialToken(token, tokenType)`; swapping them compiles and sends the wrong values.

`actorToken` is for delegation and is not covered here.

## Exchange a token

```kotlin
authentication
    .customTokenExchange(
        subjectTokenType = "urn:acme:legacy-token", // a URI you define for your profile
        subjectToken = legacyToken
    )
    .validateClaims()
    .start(object : Callback<Credentials, AuthenticationException> {
        override fun onSuccess(result: Credentials) {
            credentialsManager.saveCredentials(result)
        }

        override fun onFailure(error: AuthenticationException) { }
    })
```

Coroutines: `.await()` returns `Credentials` and throws `AuthenticationException`.

To scope the result to an organization, pass `organization = "org_abc123"`.

## Notes

- The SDK's own example omits `.validateClaims()`. Keep it; direct `AuthenticationAPIClient` calls do not validate the ID token otherwise.
- Public client: no client secret. Do not build the `/oauth/token` request by hand.
- Do not log or persist the subject token. Save the returned `Credentials` with `SecureCredentialsManager`.
- Use a non-reserved URI for `subjectTokenType`; it must match the profile in the tenant.
