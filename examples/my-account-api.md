## My Account API

Use the Auth0 My Account API to manage the current user's account.

To call the My Account API, you need an access token issued specifically for this API, including any required scopes for the operations you want to perform. See [API credentials](credentials-manager.md#api-credentials) to learn how to obtain one.

```kotlin
val client = MyAccountAPIClient(auth0, accessToken)
```

#### Using DPoP

If your application uses [DPoP (Demonstrating Proof of Possession)](https://auth0.com/docs/get-started/authentication-and-authorization-flow/call-your-api-using-the-authorization-code-flow-with-dpop), you can enable it on the My Account API client:

```kotlin
val client = MyAccountAPIClient(auth0, accessToken).useDPoP(context)
```

When DPoP is enabled, the client will automatically:
- Use the `DPoP` authorization scheme instead of `Bearer`
- Include a DPoP proof header on every request

<details>
    <summary>Using Java</summary>

```java
MyAccountAPIClient client = new MyAccountAPIClient(auth0, accessToken).useDPoP(context);
```
</details>

### Enroll a new passkey

**Scopes required:** `create:me:authentication_methods`

Enrolling a new passkey is a three-step process. First, you request an enrollment challenge from Auth0. Then you need to pass that challenge to Google's [Credential Manager](https://developer.android.com/identity/sign-in/credential-manager)
APIs to create a new passkey credential. Finally, you use the created passkey credential and the original challenge to enroll the passkey with Auth0.

#### Prerequisites

- A custom domain configured for your Auth0 tenant.
- The **Passkeys** grant to be enabled for your Auth0 application.
- The Android **Device Settings** configured for your Auth0 application.
- Passkeys are supported only on devices that run Android 9 (API level 28) or higher.

Check [our documentation](https://auth0.com/docs/native-passkeys-for-mobile-applications#before-you-begin) for more information.

#### 1. Request an enrollment challenge

You can specify an optional user identity identifier and/or a database connection name to help Auth0 find the user. The user identity identifier will be needed if the user logged in with a [linked account](https://auth0.com/docs/manage-users/user-accounts/user-account-linking).

```kotlin

val client = MyAccountAPIClient(account, accessToken)
 
client.passkeyEnrollmentChallenge()
    .start(object: Callback<PasskeyEnrollmentChallenge, MyAccountException> {
        override fun onSuccess(result: PasskeyEnrollmentChallenge) {
            print("Challenge: ${result.challenge}")
        }
        override fun onFailure(error: MyAccountException) {
            print("Error: ${error.message}")
        }
    })
```
<details>
    <summary>Using coroutines</summary>
    
```kotlin

    val client = MyAccountAPIClient(account, "accessToken")
     
    try {
        val challenge = client.passkeyEnrollmentChallenge()
            .await()
        println("Challenge: $challenge")
    } catch (exception: MyAccountException) {
        print("Error: ${exception.message}")
    }
```
</details>

<details>
    <summary>Using Java</summary>

```java

MyAccountAPIClient client = new MyAccountAPIClient(account, "accessToken");

client.passkeyEnrollmentChallenge()
        .start(new Callback<PasskeyEnrollmentChallenge, MyAccountException>() {
            @Override
            public void onSuccess(PasskeyEnrollmentChallenge result) {
                System.out.println(result);
            }
        
            @Override
            public void onFailure(@NonNull MyAccountException error) {
                System.out.println(error);
            }
});

```
</details>

#### 2. Create a new passkey credential

Use the enrollment challenge with the Google's [CredentialManager](https://developer.android.com/identity/sign-in/credential-manager) APIs to create a new passkey credential.

```kotlin
// Using coroutines
val request = CreatePublicKeyCredentialRequest(
    Gson().toJson(enrollmentChallenge.authParamsPublicKey)
)

val result = credentialManager.createCredential(requireContext(), request)

val passkeyCredentials = Gson().fromJson(
    (result as CreatePublicKeyCredentialResponse).registrationResponseJson,
    PublicKeyCredentials::class.java
)
```
<details>
    <summary>Using Java</summary>

```java

 CreateCredentialRequest request =
                new CreatePublicKeyCredentialRequest(new Gson().toJson(enrollmentChallenge.authParamsPublicKey()));
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
                    }
                    @Override
                    public void onError(@NonNull CreateCredentialException e) {}
                });

```
</details>


#### 3. Enroll the passkey

Use the created passkey credential and the enrollment challenge to enroll the passkey with Auth0.

```Kotlin

client.enroll(passkeyCredential,challenge)
    .start(object: Callback<PasskeyAuthenticationMethod, MyAccountException> {
        override fun onSuccess(result: PasskeyAuthenticationMethod) {
            println("Passkey enrolled successfully: ${result.id}")
        }
        
        override fun onFailure(error: MyAccountException) {
            println("Error enrolling passkey: ${error.message}")
        }
    })
```
<details>
    <summary>Using coroutines</summary>
    
```kotlin

try {
   val result = client.enroll(passkeyCredential, challenge)
       .await()
    println("Passkey enrolled successfully: ${result.id}")
} catch(error: MyAccountException) {
    println("Error enrolling passkey: ${error.message}")
}
```
</details>

<details>
    <summary>Using Java</summary>

```java

client.enroll(passkeyCredential, challenge)
        .start(new Callback<PasskeyAuthenticationMethod, MyAccountException>() {
            @Override
            public void onSuccess(@NonNull PasskeyAuthenticationMethod result) {
                System.out.println("Passkey enrolled successfully: " + result.getId());
            }

            @Override
            public void onFailure(@NonNull MyAccountException error) {
                System.out.println("Error enrolling passkey: " + error.getMessage());
            }
        });

```
</details>

### Get Available Factors
**Scopes required:** `read:me:factors`

Retrieves the list of multi-factor authentication (MFA) factors that are enabled for the tenant and available for the user to enroll.

**Prerequisites:**

Enable the desired MFA factors you want to be listed. Go to Auth0 Dashboard > Security > Multi-factor Auth.

```kotlin
myAccountClient.getFactors()
    .start(object : Callback<List<Factor>, MyAccountException> {
        override fun onSuccess(result: Factors) {
            // List of available factors in result.factors
        }
        override fun onFailure(error: MyAccountException) { }
    })
```
<details>
    <summary>Using Java</summary>

```java
myAccountClient.getFactors()
    .start(new Callback<List<Factor>, MyAccountException>() {
        @Override
        public void onSuccess(Factors result) {
            // List of available factors in result.getFactors()
        }
        @Override
        public void onFailure(@NonNull MyAccountException error) { }
    });
```
</details>

### Get All Enrolled Authentication Methods
**Scopes required:** `read:me:authentication_methods`

Retrieves a detailed list of all the authentication methods that the current user has already enrolled in. You can optionally filter the results by type using `AuthenticationMethodType`.


**Prerequisites:**

The user must have one or more authentication methods already enrolled.

```kotlin
// Get all authentication methods
myAccountClient.getAuthenticationMethods()
    .start(object : Callback<List<AuthenticationMethod>, MyAccountException> {
        override fun onSuccess(result: List<AuthenticationMethod>) {
            // List of enrolled methods
        }
        override fun onFailure(error: MyAccountException) { }
    })

// Get authentication methods filtered by type
myAccountClient.getAuthenticationMethods(AuthenticationMethodType.PASSKEY)
    .start(object : Callback<List<AuthenticationMethod>, MyAccountException> {
        override fun onSuccess(result: List<AuthenticationMethod>) {
            // List of enrolled passkey methods only
        }
        override fun onFailure(error: MyAccountException) { }
    })
```
<details>
    <summary>Using Java</summary>

```java
// Get all authentication methods
myAccountClient.getAuthenticationMethods()
    .start(new Callback<List<AuthenticationMethod>, MyAccountException>() {
        @Override
        public void onSuccess(List<AuthenticationMethod> result) {
            // List of enrolled methods
        }
        @Override
        public void onFailure(@NonNull MyAccountException error) { }
    });

// Get authentication methods filtered by type
myAccountClient.getAuthenticationMethods(AuthenticationMethodType.PASSKEY)
    .start(new Callback<List<AuthenticationMethod>, MyAccountException>() {
        @Override
        public void onSuccess(List<AuthenticationMethod> result) {
            // List of enrolled passkey methods only
        }
        @Override
        public void onFailure(@NonNull MyAccountException error) { }
    });
```
</details>

### Get a Single Authentication Method by ID
**Scopes required:** `read:me:authentication_methods`

Retrieves a single authentication method by its unique ID.

**Prerequisites:**

The user must have the specific authentication method (identified by its ID) already enrolled.

```kotlin
myAccountClient.getAuthenticationMethodById("phone|dev_...")
    .start(object : Callback<AuthenticationMethod, MyAccountException> {
        override fun onSuccess(result: AuthenticationMethod) {
            // The requested authentication method
        }
        override fun onFailure(error: MyAccountException) { }
    })
```
<details>
    <summary>Using Java</summary>

```java
myAccountClient.getAuthenticationMethodById("phone|dev_...")
    .start(new Callback<AuthenticationMethod, MyAccountException>() {
        @Override
        public void onSuccess(AuthenticationMethod result) {
            // The requested authentication method
        }
        @Override
        public void onFailure(@NonNull MyAccountException error) { }
    });
```
</details>

### Enroll a Phone Method
**Scopes required:** `create:me:authentication_methods`

Enrolling a new phone authentication method is a two-step process. First, you request an enrollment challenge which sends an OTP to the user. Then, you must verify the enrollment with the received OTP.

**Prerequisites:**

Enable the MFA grant type for your application. Go to Auth0 Dashboard > Applications > Your App > Advanced Settings > Grant Types and select MFA.

Enable the Phone Message factor. Go to Auth0 Dashboard > Security > Multi-factor Auth > Phone Message.

```kotlin
myAccountClient.enrollPhone("+11234567890", PhoneAuthenticationMethodType.SMS)
    .start(object : Callback<EnrollmentChallenge, MyAccountException> {
        override fun onSuccess(result: EnrollmentChallenge) {
            // OTP sent. Use result.id and result.authSession to verify.
        }
        override fun onFailure(error: MyAccountException) { }
    })
```
<details>
    <summary>Using Java</summary>

```java
myAccountClient.enrollPhone("+11234567890", PhoneAuthenticationMethodType.SMS)
    .start(new Callback<EnrollmentChallenge, MyAccountException>() {
        @Override
        public void onSuccess(EnrollmentChallenge result) {
            // OTP sent. Use result.getId() and result.getAuthSession() to verify.
        }
        @Override
        public void onFailure(@NonNull MyAccountException error) { }
    });
```

</details>

### Enroll an Email Method
**Scopes required:** `create:me:authentication_methods`

Enrolling a new email authentication method is a two-step process. First, you request an enrollment challenge which sends an OTP to the user. Then, you must verify the enrollment with the received OTP.

**Prerequisites:**

Enable the MFA grant type for your application. Go to Auth0 Dashboard > Applications > Your App > Advanced Settings > Grant Types and select MFA.

Enable the Email factor. Go to Auth0 Dashboard > Security > Multi-factor Auth > Email.

```kotlin
myAccountClient.enrollEmail("user@example.com")
    .start(object : Callback<EnrollmentChallenge, MyAccountException> {
        override fun onSuccess(result: EnrollmentChallenge) {
            // OTP sent. Use result.id and result.authSession to verify.
        }
        override fun onFailure(error: MyAccountException) { }
    })
```
<details>
    <summary>Using Java</summary>

```java
myAccountClient.enrollEmail("user@example.com")
    .start(new Callback<EnrollmentChallenge, MyAccountException>() {
        @Override
        public void onSuccess(EnrollmentChallenge result) {
            // OTP sent. Use result.getId() and result.getAuthSession() to verify.
        }
        @Override
        public void onFailure(@NonNull MyAccountException error) { }
    });
```
</details>

### Enroll a TOTP (Authenticator App) Method

**Scopes required:** `create:me:authentication_methods`

Enrolling a new TOTP (Authenticator App) authentication method is a two-step process. First, you request an enrollment challenge which provides a QR code or manual entry key. Then, you must verify the enrollment with an OTP from the authenticator app.

**Prerequisites:**

Enable the MFA grant type for your application. Go to Auth0 Dashboard > Applications > Your App > Advanced Settings > Grant Types and select MFA.

Enable the One-time Password factor. Go to Auth0 Dashboard > Security > Multi-factor Auth > One-time Password.

```kotlin
myAccountClient.enrollTotp()
    .start(object : Callback<TotpEnrollmentChallenge, MyAccountException> {
        override fun onSuccess(result: TotpEnrollmentChallenge) {
            // The result is already a TotpEnrollmentChallenge, no cast is needed.
            // Show QR code from result.barcodeUri or manual code from result.manualInputCode
            // Then use result.id and result.authSession to verify.
        }
        override fun onFailure(error: MyAccountException) { }
    })
```

<details>
    <summary>Using Java</summary>

```java
myAccountClient.enrollTotp()
    .start(new Callback<TotpEnrollmentChallenge, MyAccountException>() {
        @Override
        public void onSuccess(TotpEnrollmentChallenge result) {
            // The result is already a TotpEnrollmentChallenge, no cast is needed.
            // Show QR code from result.getBarcodeUri() or manual code from result.getManualInputCode()
            // Then use result.getId() and result.getAuthSession() to verify.
        }
        @Override
        public void onFailure(@NonNull MyAccountException error) { }
    });
```
</details>

### Enroll a Push Notification Method
**Scopes required:** `create:me:authentication_methods`

Enrolling a new Push Notification authentication method is a two-step process. First, you request an enrollment challenge which provides a QR code. Then, after the user scans the QR code and approves, you must confirm the enrollment.

**Prerequisites:**

Enable the MFA grant type for your application. Go to Auth0 Dashboard > Applications > Your App > Advanced Settings > Grant Types and select MFA.

Enable the Push Notification factor. Go to Auth0 Dashboard > Security > Multi-factor Auth > Push Notification using Auth0 Guardian.

```kotlin
myAccountClient.enrollPushNotification()
    .start(object : Callback<TotpEnrollmentChallenge, MyAccountException> {
        override fun onSuccess(result: TotpEnrollmentChallenge) {
            // The result is already a TotpEnrollmentChallenge, no cast is needed.
            // Show QR code from result.barcodeUri to be scanned by Auth0 Guardian/Verify
            // Then use result.id and result.authSession to verify.
        }
        override fun onFailure(error: MyAccountException) { }
    })
```
<details>
    <summary>Using Java</summary>

```java
myAccountClient.enrollPushNotification()
    .start(new Callback<TotpEnrollmentChallenge, MyAccountException>() {
    @Override
    public void onSuccess(TotpEnrollmentChallenge result) {
        // The result is already a TotpEnrollmentChallenge, no cast is needed.
        // Show QR code from result.getBarcodeUri() to be scanned by Auth0 Guardian/Verify
        // Then use result.getId() and result.getAuthSession() to verify.
    }
    @Override
    public void onFailure(@NonNull MyAccountException error) { }
});
```
</details>

### Enroll a Recovery Code
**Scopes required:** `create:me:authentication_methods`

Enrolls a new recovery code for the user. This is a single-step process that immediately returns the recovery code. The user must save this code securely as it will not be shown again.

**Prerequisites:**

Enable the MFA grant type for your application. Go to Auth0 Dashboard > Applications > Your App > Advanced Settings > Grant Types and select MFA.

Enable the Recovery Code factor. Go to Auth0 Dashboard > Security > Multi-factor Auth > Recovery Code.

```kotlin
myAccountClient.enrollRecoveryCode()
    .start(object : Callback<RecoveryCodeEnrollmentChallenge, MyAccountException> {
        override fun onSuccess(result: RecoveryCodeEnrollmentChallenge) {
            // The result is already a RecoveryCodeEnrollmentChallenge, no cast is needed.
            // Display and require the user to save result.recoveryCode
            // This method is already verified.
        }
        override fun onFailure(error: MyAccountException) { }
    })

```
<details>
    <summary>Using Java</summary>

```java
myAccountClient.enrollRecoveryCode()
    .start(new Callback<RecoveryCodeEnrollmentChallenge, MyAccountException>() {
    @Override
    public void onSuccess(RecoveryCodeEnrollmentChallenge result) {
        // The result is already a RecoveryCodeEnrollmentChallenge, no cast is needed.
        // Display and require the user to save result.getRecoveryCode()
        // This method is already verified.
    }
    @Override
    public void onFailure(@NonNull MyAccountException error) { }
});
```
</details>

### Enroll a Password Method
**Scopes required:** `create:me:authentication_methods`

Enrolling a password authentication method is a two-step process. First, you request an enrollment challenge, which returns the connection's password [policy](https://auth0.com/docs/authenticate/database-connections/password-options) so you can guide the user to choose a compliant password. Then, you confirm the enrollment with the new password.

#### 1. Request an enrollment challenge

```kotlin
myAccountClient.enrollPassword()
    .start(object : Callback<PasswordEnrollmentChallenge, MyAccountException> {
        override fun onSuccess(result: PasswordEnrollmentChallenge) {
            // Use result.policy to validate the user's new password before confirming.
            // Then use result.id and result.authSession to verify.
        }
        override fun onFailure(error: MyAccountException) { }
    })
```

<details>
    <summary>Using Java</summary>

```java
myAccountClient.enrollPassword()
    .start(new Callback<PasswordEnrollmentChallenge, MyAccountException>() {
        @Override
        public void onSuccess(PasswordEnrollmentChallenge result) {
            // Use result.getPolicy() to validate the user's new password before confirming.
            // Then use result.getId() and result.getAuthSession() to verify.
        }
        @Override
        public void onFailure(@NonNull MyAccountException error) { }
    });
```
</details>

#### 2. Confirm the enrollment

```kotlin
myAccountClient.verifyPassword("challenge_id_from_enroll", "auth_session_from_enroll", "new_password")
    .start(object : Callback<PasswordAuthenticationMethod, MyAccountException> {
        override fun onSuccess(result: PasswordAuthenticationMethod) {
            // Enrollment successful
        }
        override fun onFailure(error: MyAccountException) { }
    })
```

<details>
    <summary>Using Java</summary>

```java
myAccountClient.verifyPassword("challenge_id_from_enroll", "auth_session_from_enroll", "new_password")
    .start(new Callback<PasswordAuthenticationMethod, MyAccountException>() {
        @Override
        public void onSuccess(PasswordAuthenticationMethod result) {
            // Enrollment successful
        }
        @Override
        public void onFailure(@NonNull MyAccountException error) { }
    });
```
</details>

### Verify an Enrollment
**Scopes required:** `create:me:authentication_methods`

Confirms the enrollment of an authentication method after the user has completed the initial challenge (e.g., entered an OTP, scanned a QR code).

Prerequisites:

An enrollment must have been successfully started to obtain the challenge_id and auth_session.

```kotlin
// For OTP-based factors (TOTP, Email, Phone)
myAccountClient.verifyOtp("challenge_id_from_enroll", "123456", "auth_session_from_enroll")
    .start(object : Callback<AuthenticationMethod, MyAccountException> {
        override fun onSuccess(result: AuthenticationMethod) {
            // Enrollment successful
        }
        override fun onFailure(error: MyAccountException) { }
    })

// For Push Notification factor
myAccountClient.verify("challenge_id_from_enroll", "auth_session_from_enroll")
    .start(object : Callback<AuthenticationMethod, MyAccountException> {
        override fun onSuccess(result: AuthenticationMethod) {
            // Enrollment successful
        }
        override fun onFailure(error: MyAccountException) { }
    })
```
<details>
    <summary>Using Java</summary>

```java
// For OTP-based factors (TOTP, Email, Phone)
myAccountClient.verifyOtp("challenge_id_from_enroll", "123456", "auth_session_from_enroll")
    .start(new Callback<AuthenticationMethod, MyAccountException>() {
        @Override
        public void onSuccess(AuthenticationMethod result) {
            // Enrollment successful
        }
        @Override
        public void onFailure(@NonNull MyAccountException error) { }
    });

// For Push Notification factor
myAccountClient.verify("challenge_id_from_enroll", "auth_session_from_enroll")
    .start(new Callback<AuthenticationMethod, MyAccountException>() {
        @Override
        public void onSuccess(AuthenticationMethod result) {
            // Enrollment successful
        }
        @Override
        public void onFailure(@NonNull MyAccountException error) { }
    });
```
</details>

### Delete an Authentication Method
**Scopes required:** `delete:me:authentication_methods`

Deletes an existing authentication method belonging to the current user.

**Prerequisites:**

The user must have the specific authentication method (identified by its ID) already enrolled.

```kotlin
myAccountClient.deleteAuthenticationMethod("phone|dev_...")
    .start(object : Callback<Unit, MyAccountException> {
        override fun onSuccess(result: Unit) {
            // Deletion successful
        }
        override fun onFailure(error: MyAccountException) { }
    })
```
<details>
    <summary>Using Java</summary>

```java
myAccountClient.deleteAuthenticationMethod("phone|dev_...")
    .start(new Callback<Void, MyAccountException>() {
        @Override
        public void onSuccess(Void result) {
            // Deletion successful
        }
        @Override
        public void onFailure(@NonNull MyAccountException error) { }
    });
```
</details>



### Update an Authentication Method
**Scopes required:** `update:me:authentication_methods`

Updates a single authentication method.

**Prerequisites:**

The user must have the specific authentication method (identified by its ID) already enrolled.

```kotlin
myAccountClient.updateAuthenticationMethodById("{Authentication_Id}", "{Name}")
    .start(object : Callback<Unit, MyAccountException> {
        override fun onSuccess(result: Unit) {
            // Deletion successful
        }
        override fun onFailure(error: MyAccountException) { }
    })
```
<details>
    <summary>Using Java</summary>

```java
myAccountClient.updateAuthenticationMethodById("{Authentication_Id}", "{Name}")
    .start(new Callback<Void, MyAccountException>() {
        @Override
        public void onSuccess(Void result) {
            // Deletion successful
        }
        @Override
        public void onFailure(@NonNull MyAccountException error) { }
    });
```
</details>
