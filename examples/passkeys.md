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
