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
2. Pass the signup challenge and the collected codes to `signinWithPasskey(challenge, ...)` via the
   `verification` map (identifier -> code). The SDK checks that every identifier in `verificationRequired`
   has a non-empty code before sending the request.
3. On a retryable error (`AuthenticationException.isPasskeyVerificationRetryable == true`), re-collect
   the codes and call `signinWithPasskey` again **reusing the same challenge and `PublicKeyCredentials`** —
   the biometric prompt will not reappear.

A failed `signinWithPasskey` can be retried with the same credential when `isPasskeyVerificationRetryable` is
`true`. This is the case when a code is wrong: the error is `invalid_grant` with an `auth_session`, and
`passkeyVerificationRequired` lists the identifiers whose code was wrong. Collect new codes for those identifiers
and retry.

If the code for an identifier in `verificationRequired` is missing or empty, the SDK fails the request before
sending it, with an `invalid_request` error and a `statusCode` of `0`. This error is not retryable.

Any other error is terminal, so restart the registration from `signupWithPasskey`.

Optionally pass `deliveryMethod` (`DeliveryMethod.TEXT` or `DeliveryMethod.VOICE`) to
`signupWithPasskey` to choose the phone OTP channel.

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

    val maxAttempts = 3 // retry limit; adjust it to suit your app
    var attempts = 0
    while (true) {
        try {
            val userCredential = authenticationApiClient.signinWithPasskey(
                challenge,
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
            // Re-collect the failed identifiers and retry with the SAME challenge and credential.
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

                        authenticationAPIClient.signinWithPasskey(result,
                                        credentials, "{realm}", "{organization-id}", verification)
                                .start(new Callback<Credentials, AuthenticationException>() {
                                    @Override
                                    public void onSuccess(Credentials result) {}

                                    @Override
                                    public void onFailure(@NonNull AuthenticationException error) {
                                        if (error.isPasskeyVerificationRetryable()) {
                                            // Re-collect the codes for error.getPasskeyVerificationRequired() and retry
                                            // signinWithPasskey with the SAME challenge (result) and credentials.
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
