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

// 2. Identify by phone. The server continues with a ChallengePhone action carrying the
//    authenticator index and the delivery methods it will accept.
val challenge = try {
    embedded.identify("+15550123456", IdentifierType.PHONE).await()
    return
} catch (e: EmbeddedAuthException) {
    (e.error as? EmbeddedAuthError.InsufficientAuthorization)
        ?.nextActions?.filterIsInstance<NextAction.ChallengePhone>()?.firstOrNull()
        ?: throw e
}

// 3. Send the code using the index and a delivery method the server offered. Pick VOICE for a
//    voice call; the first offered method is used here. Continues with VerifyOtp.
try {
    val method = challenge.deliveryMethods.firstOrNull() ?: PhoneDeliveryMethod.TEXT
    embedded.challengePhone(index = challenge.index, deliveryMethod = method).await()
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
            // continuation → read NextAction.ChallengePhone for its index and deliveryMethods
        }
    });

// Send the code using the index and a delivery method the server offered.
embedded.challengePhone(0, PhoneDeliveryMethod.TEXT)
    .start(new Callback<Void, EmbeddedAuthException>() {
        @Override public void onSuccess(Void result) { }
        @Override public void onFailure(@NonNull EmbeddedAuthException e) {
            // continuation → verifyOtp(...)
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
