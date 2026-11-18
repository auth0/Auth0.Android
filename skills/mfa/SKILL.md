---
name: mfa
description: >-
  Use when handling multi-factor authentication in an Auth0.Android app: detecting
  mfa_required on a password login, listing authenticators, enrolling a phone,
  email, OTP or push factor, challenging and verifying with MfaApiClient, recovery
  codes, and MFA error handling. Covers the Flexible Factors Grant API in v4.
metadata:
  type: sub-skill
  library: Auth0.Android
  library_version: 4.3.1
requires:
  - auth0-android
---

# Auth0.Android - MFA (Flexible Factors Grant)

Early Access. The application needs the **MFA** grant type (Dashboard, Applications, Advanced Settings, Grant Types); contact your Auth0 representative to enable it. Full reference: [`examples/authentication-api/mfa-flexible-factors.md`](https://github.com/auth0/Auth0.Android/blob/main/examples/authentication-api/mfa-flexible-factors.md).

The older MFA methods on `AuthenticationAPIClient` were removed in v4. Everything goes through `authentication.mfaClient(mfaToken)`, which returns an `MfaApiClient`. Each call accepts a `Callback` via `.start(...)` or coroutines via `.await()`.

## Detect mfa_required

```kotlin
authentication.login("user@example.com", "password", "Username-Password-Authentication")
    .setAudience("https://api.example.com")
    .setScope("openid profile email")
    .validateClaims()
    .start(object : Callback<Credentials, AuthenticationException> {
        override fun onSuccess(result: Credentials) { }

        override fun onFailure(error: AuthenticationException) {
            if (error.isMultifactorRequired) {
                val payload = error.mfaRequiredErrorPayload
                val mfaToken = payload?.mfaToken
                val enroll = payload?.mfaRequirements?.enroll       // List<MfaFactor>?, user has no factor yet
                val challenge = payload?.mfaRequirements?.challenge // List<MfaFactor>?, user can be challenged
            }
        }
    })
```

`isMultifactorEnrollRequired` is also available when the user must enroll first. `getCode()` and `getDescription()` are functions in Kotlin.

## MfaApiClient

| Call | Returns |
|------|---------|
| `getAuthenticators(factorsAllowed: List<String>)` | `Request<List<Authenticator>, MfaListAuthenticatorsException>` (`id`, `type`, `authenticatorType`, `active`, `oobChannel`, `name`) |
| `enroll(MfaEnrollmentType)` | `Request<EnrollmentChallenge, MfaEnrollmentException>` |
| `challenge(authenticatorId: String)` | `Request<Challenge, MfaChallengeException>` (`challengeType`, `oobCode`, `bindingMethod`) |
| `verify(MfaVerificationType)` | `Request<Credentials, MfaVerifyException>` |

- `MfaEnrollmentType`: `Phone(phoneNumber)`, `Email(email)`, `Otp`, `Push`.
- `MfaVerificationType`: `Otp(otp)`, `Oob(oobCode, bindingCode = null)`, `RecoveryCode(code)`.
- `factorsAllowed` must be non-empty. Build it from `mfaRequirements.challenge.map { it.type }`. When `challenge` is empty or null, enroll instead.
- `EnrollmentChallenge` is a sealed class. Branch with `when`: `TotpEnrollmentChallenge` (`barcodeUri`, `manualInputCode`, `secret`, `recoveryCodes`), `OobEnrollmentChallenge` (`oobCode`, `bindingMethod`), `RecoveryCodeEnrollmentChallenge`, `MfaEnrollmentChallenge`. Type the callback as `Callback<EnrollmentChallenge, MfaEnrollmentException>`, not a subtype.
- Exceptions are nested in `MfaException`: import `com.auth0.android.authentication.mfa.MfaException.MfaVerifyException` and so on.

## Challenge then verify

`challenge` always requests an out-of-band challenge, which is what sends the SMS, email or push. Call it before verifying an OOB factor. For an authenticator app (`authenticatorType == "otp"`) skip it and verify the code directly.

```kotlin
val mfaClient = authentication.mfaClient(mfaToken)

val authenticator = mfaClient
    .getAuthenticators(factorsAllowed = requirements.challenge.orEmpty().map { it.type })
    .await()
    .first { it.active } // throws NoSuchElementException if none is active

val credentials = if (authenticator.authenticatorType == "otp") {
    mfaClient.verify(MfaVerificationType.Otp(userEnteredCode))
} else {
    val challenge = mfaClient.challenge(authenticator.id).await()
    mfaClient.verify(MfaVerificationType.Oob(challenge.oobCode!!, bindingCode = userEnteredCode))
}.await()

// verify does not validate the ID token; check the claims you rely on before trusting it
credentialsManager.saveCredentials(credentials)
```

For push, the `bindingCode` is optional; omit it once the user approves on their device. Until then the server can answer `verify` with `authorization_pending`, which is Auth0 server behaviour and not defined in this SDK. Check `MfaVerifyException.getCode()`, retry the same `verify` after a short delay, and wait longer on `slow_down`.

## Enroll

```kotlin
when (val enrollment = mfaClient.enroll(MfaEnrollmentType.Otp).await()) {
    is TotpEnrollmentChallenge -> { /* show enrollment.barcodeUri or enrollment.secret (manualInputCode is only set by My Account) */ }
    is OobEnrollmentChallenge -> { /* then verify with MfaVerificationType.Oob(enrollment.oobCode!!, code) */ }
    else -> { }
}
```

After enrolling an OTP factor, verify with `MfaVerificationType.Otp(code)` to receive credentials.

## DPoP

If the `AuthenticationAPIClient` was configured with `useDPoP(context)`, the MFA client inherits it. The DPoP proof is attached to the final `verify` call.

## Errors

All four exception types expose `getCode()`, `getDescription()`, `statusCode`, `getValue(key)`, `isNetworkError` and `cause`. Branch on the code, not the description:

| Code | Meaning |
|------|---------|
| `invalid_token` | MFA token expired or invalid; restart login |
| `invalid_grant`, `invalid_oob_code`, `invalid_binding_code`, `expired_token` | Wrong or expired code |
| `enrollment_conflict` | Authenticator already enrolled |
| `unsupported_challenge_type` | Factor not enabled for the tenant |
| `authenticator_not_found` | Unknown authenticator id |

## Common mistakes

- Verifying an OOB factor (SMS, email, push) without calling `challenge` first.
- Calling `getAuthenticators` with an empty list.
- Forgetting `.setAudience` / `.setScope` on the original `login` request, then getting credentials for the wrong API.
- Using removed `AuthenticationAPIClient` MFA methods from v3.
- Typing the enroll callback as a concrete challenge class.
