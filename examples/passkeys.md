## Passkeys
User should have a custom domain configured and passkey grant-type enabled in the Auth0 dashboard to use passkeys.

To sign up a user with passkey

```kotlin
// Using Coroutines 
try {
    val userData = UserData(
        email = "user@example.com",
        phoneNumber = "+11234567890",
        name = "John Doe",
        givenName = "John",
        familyName = "Doe",
        nickName = "johnny",
        picture = "https://example.com/photo.png",
        userMetadata = mapOf("signup_source" to "android_app")
    )

    val challenge = authenticationApiClient.signupWithPasskey(
        userData,
        "{realm}",
        "{organization-id}"
    ).await()
    
    //Use CredentialManager to create public key credentials
    val request = CreatePublicKeyCredentialRequest(
        Gson().toJson(challenge.authParamsPublicKey)
    )

    val result = credentialManager.createCredential(requireContext(), request)

    val authRequest = Gson().fromJson(
        (result as CreatePublicKeyCredentialResponse).registrationResponseJson,
        PublicKeyCredentials::class.java
    )

    val userCredential = authenticationApiClient.signinWithPasskey(
        challenge.authSession, authRequest, "{realm}" , "{organization-id}"
    )
        .validateClaims()
        .await()
} catch (e: CreateCredentialException) {
} catch (exception: AuthenticationException) {
}
```
<details>
  <summary>Using Java</summary>

```java
 UserData userData = new UserData(
    "user@example.com",    // email
    "+11234567890",        // phoneNumber
    null,                  // userName
    "John Doe",            // name
    "John",                // givenName
    "Doe",                 // familyName
    "johnny",              // nickName
    "https://example.com/photo.png", // picture
    Map.of("signup_source", "android_app") // userMetadata
 );

 authenticationAPIClient.signupWithPasskey(userData, "{realm}","{organization-id}")
        .start(new Callback<PasskeyRegistrationChallenge, AuthenticationException>() {
    @Override
    public void onSuccess(PasskeyRegistrationChallenge result) {
        CreateCredentialRequest request =
                new CreatePublicKeyCredentialRequest(new Gson().toJson(result.getAuthParamsPublicKey()));
        credentialManager.createCredentialAsync(getContext(),
                request,
                cancellationSignal,
                <executor>,
                new CredentialManagerCallback<CreateCredentialResponse, CreateCredentialException>() {
                    @Override
                    public void onResult(CreateCredentialResponse createCredentialResponse) {
                        PublicKeyCredentials credentials = new Gson().fromJson(
                                ((CreatePublicKeyCredentialResponse) createCredentialResponse).getRegistrationResponseJson(),
                                PublicKeyCredentials.class);

                        authenticationAPIClient.signinWithPasskey(result.getAuthSession(),
                                        credentials, "{realm}","{organization-id}")
                                .start(new Callback<Credentials, AuthenticationException>() {
                                    @Override
                                    public void onSuccess(Credentials result) {}

                                    @Override
                                    public void onFailure(@NonNull AuthenticationException error) {}
                                });
                    }
                    @Override
                    public void onError(@NonNull CreateCredentialException e) {}
                });
    }

    @Override
    public void onFailure(@NonNull AuthenticationException error) {}
});
```
</details>

### Passkey signup with identifier verification

When the database connection has verification enabled for email and phone, the `signupWithPasskey`
response includes a `verificationRequired` list naming the identifiers
(`PasskeyVerificationMethod.EMAIL`, `PasskeyVerificationMethod.PHONE`) that must be verified before tokens
can be issued. It is `null` when no verification is required. You must:

1. Collect the OTP code for every identifier in `verificationRequired` **before** creating the
   platform credential with `CredentialManager.createCredential(...)`. Creating the credential first
   and then failing verification leaves an orphaned local passkey and shows a second biometric prompt
   on retry.
2. Pass the collected codes to `signinWithPasskey` via the `verification` map (identifier -> code). A blank
   code fails the request with an `AuthenticationException` before any network call is made.
3. On a retryable error (`AuthenticationException.isPasskeyVerificationRetryable == true`), re-collect
   the codes and call `signinWithPasskey` again **reusing the same `PublicKeyCredentials`** — the
   biometric prompt will not reappear.

An error is retryable (`isPasskeyVerificationRetryable`) when it is an `invalid_grant` or `invalid_request` error
that carries an `auth_session`, meaning the session is still alive (for example a code was wrong or missing and
attempts remain). The identifiers to re-collect are in `passkeyVerificationRequired` and the session in
`passkeyAuthSession`. Any other error is terminal and the registration must be restarted from `signupWithPasskey`.

Optionally pass `deliveryMethod` (`DeliveryMethod.TEXT` or `DeliveryMethod.VOICE`) to
`signupWithPasskey` to choose the phone OTP channel.

`signupWithPasskey` is rate-limited. When the limit is hit, the request fails with an `AuthenticationException`
whose `statusCode` is `429`.

```kotlin
// Using Coroutines
try {
    val userData = UserData(email = "user@example.com")

    val challenge = authenticationApiClient.signupWithPasskey(
        userData,
        "{realm}",
        "{organization-id}",
        deliveryMethod = DeliveryMethod.TEXT // optional, phone OTP channel
    ).await()

    // Collect OTP codes BEFORE creating the credential.
    var codes: Map<PasskeyVerificationMethod, String> = challenge.verificationRequired.orEmpty()
        .associateWith { identifier -> promptUserForOtp(identifier) } // app-defined

    // Now create the platform credential.
    val request = CreatePublicKeyCredentialRequest(
        Gson().toJson(challenge.authParamsPublicKey)
    )
    val result = credentialManager.createCredential(requireContext(), request)
    val authRequest = Gson().fromJson(
        (result as CreatePublicKeyCredentialResponse).registrationResponseJson,
        PublicKeyCredentials::class.java
    )

    var authSession = challenge.authSession
    val maxAttempts = 3 // retry limit; adjust it to suit your app
    var attempts = 0
    while (true) {
        try {
            val userCredential = authenticationApiClient.signinWithPasskey(
                authSession,
                authRequest,
                "{realm}",
                "{organization-id}",
                verification = codes
            ).validateClaims().await()
            break // success
        } catch (exception: AuthenticationException) {
            if (!exception.isPasskeyVerificationRetryable || ++attempts >= maxAttempts) {
                throw exception // terminal (or too many attempts) - restart registration
            }
            // Re-collect the failed identifiers and retry with the SAME credential. If the error does not
            // list them, fall back to the identifiers of the original challenge.
            authSession = exception.passkeyAuthSession ?: authSession
            val failed = exception.passkeyVerificationRequired ?: challenge.verificationRequired.orEmpty()
            codes = codes + failed.associateWith { identifier -> promptUserForOtp(identifier) }
        }
    }
} catch (e: CreateCredentialException) {
    // The passkey could not be created or the user cancelled: show an error and let the user try again.
} catch (exception: AuthenticationException) {
    // Verification failed for good or the retries ran out: show the error and restart the registration.
}
```
<details>
  <summary>Using Java</summary>

```java
UserData userData = new UserData("user@example.com", null, null, null, null, null, null, null, null);

authenticationAPIClient.signupWithPasskey(userData, "{realm}", "{organization-id}", DeliveryMethod.TEXT)
        .start(new Callback<PasskeyRegistrationChallenge, AuthenticationException>() {
    @Override
    public void onSuccess(PasskeyRegistrationChallenge result) {
        // Collect OTP codes for result.getVerificationRequired() BEFORE creating the credential.
        Map<PasskeyVerificationMethod, String> verification = collectOtpCodes(result.getVerificationRequired()); // app-defined

        CreateCredentialRequest request =
                new CreatePublicKeyCredentialRequest(new Gson().toJson(result.getAuthParamsPublicKey()));
        credentialManager.createCredentialAsync(getContext(), request, cancellationSignal, <executor>,
                new CredentialManagerCallback<CreateCredentialResponse, CreateCredentialException>() {
                    @Override
                    public void onResult(CreateCredentialResponse createCredentialResponse) {
                        PublicKeyCredentials credentials = new Gson().fromJson(
                                ((CreatePublicKeyCredentialResponse) createCredentialResponse).getRegistrationResponseJson(),
                                PublicKeyCredentials.class);

                        authenticationAPIClient.signinWithPasskey(result.getAuthSession(),
                                        credentials, "{realm}", "{organization-id}", verification)
                                .start(new Callback<Credentials, AuthenticationException>() {
                                    @Override
                                    public void onSuccess(Credentials result) {}

                                    @Override
                                    public void onFailure(@NonNull AuthenticationException error) {
                                        if (error.isPasskeyVerificationRetryable()) {
                                            // Re-collect the codes for error.getPasskeyVerificationRequired(), or for
                                            // result.getVerificationRequired() when it is null, and retry
                                            // signinWithPasskey with the SAME credentials. Use
                                            // error.getPasskeyAuthSession() when present, else result.getAuthSession().
                                        } else {
                                            // Terminal — restart registration.
                                        }
                                    }
                                });
                    }
                    @Override
                    public void onError(@NonNull CreateCredentialException e) {}
                });
    }

    @Override
    public void onFailure(@NonNull AuthenticationException error) {}
});
```
</details>

To sign in a user with passkey
```kotlin
//Using coroutines
try {

    val challenge =
        authenticationApiClient.passkeyChallenge("{realm}","{organization-id}")
            .await()

    //Use CredentialManager to create public key credentials
    val request = GetPublicKeyCredentialOption(Gson().toJson(challenge.authParamsPublicKey))
    val getCredRequest = GetCredentialRequest(
        listOf(request)
    )
    val result = credentialManager.getCredential(requireContext(), getCredRequest)
    when (val credential = result.credential) {
        is PublicKeyCredential -> {
            val authRequest = Gson().fromJson(
                credential.authenticationResponseJson,
                PublicKeyCredentials::class.java
            )
            val userCredential = authenticationApiClient.signinWithPasskey(
                challenge.authSession,
                authRequest,
                "{realm}",
                "{organization-id}"
            )
                .validateClaims()
                .await()
        }

        else -> {}
    }
} catch (e: GetCredentialException) {
} catch (exception: AuthenticationException) {
}
```
<details>
  <summary>Using Java</summary>

```java
authenticationAPIClient.passkeyChallenge("realm","{organization-id}")
                .start(new Callback<PasskeyChallenge, AuthenticationException>() {
    @Override
    public void onSuccess(PasskeyChallenge result) {
        GetPublicKeyCredentialOption option = new GetPublicKeyCredentialOption(new Gson().toJson(result.getAuthParamsPublicKey()));
        GetCredentialRequest request = new GetCredentialRequest(List.of(option));
        credentialManager.getCredentialAsync(getContext(),
                request,
                cancellationSignal,
                <executor>,
                new CredentialManagerCallback<GetCredentialResponse, GetCredentialException>() {
                    @Override
                    public void onResult(GetCredentialResponse getCredentialResponse) {
                        Credential credential = getCredentialResponse.getCredential();
                        if (credential instanceof PublicKeyCredential) {
                            String responseJson = ((PublicKeyCredential) credential).getAuthenticationResponseJson();
                            PublicKeyCredentials publicKeyCredentials = new Gson().fromJson(
                                    responseJson,
                                    PublicKeyCredentials.class
                            );
                            authenticationAPIClient.signinWithPasskey(result.getAuthSession(), publicKeyCredentials,"{realm}","{organization-id}")
                                    .start(new Callback<Credentials, AuthenticationException>() {
                                        @Override
                                        public void onSuccess(Credentials result) {}

                                        @Override
                                        public void onFailure(@NonNull AuthenticationException error) {}
                                    });
                        }
                    }

                    @Override
                    public void onError(@NonNull GetCredentialException e) {}
                });
    }

    @Override
    public void onFailure(@NonNull AuthenticationException error) {}
});
```
</details>

**Points to be Noted**:

Passkeys are supported only on devices that run Android 9 (API level 28) or higher.
To use passkeys ,user needs to add support for Digital Asset Links.
