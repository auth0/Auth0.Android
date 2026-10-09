# Phone OTP (SMS/Voice) — first-factor & MFA second-factor

Authenticate with a phone number and an SMS or voice one-time code. The same
`identify` → `challengePhone` → `verifyOtp` sequence works whether phone is the first
factor or an MFA step-up — the server decides which by advertising the matching
`NextAction` entries (see [authorize.md](authorize.md) for the next-action pattern).

Each non-terminal step completes by throwing an `EmbeddedAuthException` whose `error` is
`EmbeddedAuthError.InsufficientAuthorization`; the terminal `verifyOtp` returns `Credentials`.

```kotlin
val embedded = EmbeddedAuthClient(Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN"))

// 1. Start the flow — always continues with the next actions (e.g. IdentifyPhone).
try {
    embedded.authorize("Username-Password-Authentication").await()
} catch (e: EmbeddedAuthException) { /* inspect (e.error as InsufficientAuthorization).nextActions */ }

// 2. Identify by phone. The server continues with a ChallengePhone action.
try {
    embedded.identify("+15550123456", IdentifierType.PHONE).await()
} catch (e: EmbeddedAuthException) { /* continuation → ChallengePhone */ }

// 3. Send the code by SMS (TEXT) or voice (VOICE). index defaults to the first authenticator (0),
//    which is correct for phone as a first factor; as an MFA step-up, pass the
//    NextAction.ChallengePhone.index the server offered. Continues with VerifyOtp(channel = SMS).
try {
    embedded.challengePhone(deliveryMethod = PhoneDeliveryMethod.TEXT).await()
} catch (e: EmbeddedAuthException) { /* continuation → VerifyOtp */ }

// 4. Verify the code the user received. Terminal — returns Credentials on success.
try {
    val credentials = embedded.verifyOtp(code = "123456", type = OtpType.OOB).await()
    // credentials.accessToken, credentials.idToken, ...
} catch (e: EmbeddedAuthException) {
    when (e.error) {
        is EmbeddedAuthError.InsufficientAuthorization -> { /* wrong code or more MFA — re-prompt */ }
        EmbeddedAuthError.TooManyWrongOtpAttempts -> { /* too many wrong codes */ }
        else -> { /* other terminal error */ }
    }
}
```

`challengePhone` offers the delivery methods the server advertised in
`NextAction.ChallengePhone.deliveryMethods` — pass `PhoneDeliveryMethod.VOICE` for a voice
call. SMS and voice codes are both verified with `OtpType.OOB`.

<details>
  <summary>Using Java</summary>

```java
Auth0 auth0 = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN");
EmbeddedAuthClient embedded = new EmbeddedAuthClient(auth0);

embedded.identify("+15550123456", IdentifierType.PHONE)
    .start(new Callback<Void, EmbeddedAuthException>() {
        @Override public void onSuccess(Void result) { }
        @Override public void onFailure(@NonNull EmbeddedAuthException e) {
            // continuation → challengePhone(...)
        }
    });

embedded.verifyOtp("123456", OtpType.OOB)
    .start(new Callback<Credentials, EmbeddedAuthException>() {
        @Override public void onSuccess(Credentials credentials) {
            // credentials.getAccessToken()
        }
        @Override public void onFailure(@NonNull EmbeddedAuthException e) { }
    });
```
</details>
