### MFA Flexible Factors Grant

> [!IMPORTANT]
> Multi Factor Authentication support via SDKs is currently in Early Access. To request access to this feature, contact your Auth0 representative.

The MFA Flexible Factors Grant allows you to handle MFA challenges during the authentication flow when users sign in to MFA-enabled connections. This feature requires your Application to have the *MFA* grant type enabled. Check [this article](https://auth0.com/docs/clients/client-grant-types) to learn how to enable it.

#### Understanding the mfa_required Error Payload

When MFA is required during authentication, the error response contains a structured payload with the following properties:

| Property | Type | Description |
|----------|------|-------------|
| `mfaToken` | `String` | A token that must be used for all subsequent MFA operations. This token is short-lived. |
| `mfaRequirements` | `MfaRequirements?` | Contains the available MFA actions. |
| `mfaRequirements.enroll` | `List<MfaFactor>?` | Factor types available for enrollment. Present when the user **has not enrolled** any MFA factors yet. |
| `mfaRequirements.challenge` | `List<MfaFactor>?` | Factor types available for challenge. Present when the user **has already enrolled** MFA factors. |

**Enroll vs Challenge Flows:**
- **Enroll flow**: When `mfaRequirements.enroll` is present and not empty, the user needs to enroll a new MFA factor before they can authenticate. Use `mfaClient.enroll()` to register a new authenticator.
- **Challenge flow**: When `mfaRequirements.challenge` is present and not empty, the user has already enrolled MFA factors. Use `mfaClient.getAuthenticators()` to list their enrolled authenticators, then `mfaClient.challenge()` to initiate verification.

> **Note**: Check both `enroll` and `challenge` independently. While typically only one will be present, your code should handle both scenarios defensively.

#### Handling MFA Required Errors

When a user signs in to an MFA-enabled connection, the authentication request will fail with an `AuthenticationException` that contains the MFA requirements. You can extract the MFA token and requirements from the error to proceed with the MFA flow.

```kotlin
authentication
    .login("user@example.com", "password", "Username-Password-Authentication")
    .validateClaims()
    .start(object: Callback<Credentials, AuthenticationException> {
        override fun onFailure(exception: AuthenticationException) {
            if (exception.isMultifactorRequired) {
                // MFA is required - extract the MFA payload
                val mfaPayload = exception.mfaRequiredErrorPayload
                val mfaToken = mfaPayload?.mfaToken
                val requirements = mfaPayload?.mfaRequirements
                
                // Check if enrollment is required (user has not enrolled MFA yet)
                requirements?.enroll?.let { enrollTypes ->
                    println("User needs to enroll MFA")
                    println("Available enrollment types: ${enrollTypes.map { it.type }}")
                    // Example output: ["otp", "phone", "push-notification"]
                    // Proceed with MFA enrollment using one of these types
                }
                
                // Check if challenge is available (user already enrolled)
                requirements?.challenge?.let { challengeTypes ->
                    println("User has enrolled MFA factors")
                    println("Available challenge types: ${challengeTypes.map { it.type }}")
                    // Example output: ["otp", "phone"]
                    // Get authenticators and challenge one of them
                }
                
                // Proceed with MFA flow using mfaToken
            }
        }

        override fun onSuccess(credentials: Credentials) {
            // Login successful without MFA
        }
    })
```

<details>
  <summary>Using Java</summary>

```java
authentication
    .login("user@example.com", "password", "Username-Password-Authentication")
    .validateClaims()
    .start(new Callback<Credentials, AuthenticationException>() {
        @Override
        public void onFailure(@NonNull AuthenticationException exception) {
            if (exception.isMultifactorRequired()) {
                // MFA is required - extract the MFA payload
                MfaRequiredErrorPayload mfaPayload = exception.getMfaRequiredErrorPayload();
                if (mfaPayload != null) {
                    String mfaToken = mfaPayload.getMfaToken();
                    MfaRequirements requirements = mfaPayload.getMfaRequirements();
                    
                    // Check if enrollment is required (user has not enrolled MFA yet)
                    if (requirements != null && requirements.getEnroll() != null) {
                        List<MfaFactor> enrollTypes = requirements.getEnroll();
                        Log.d(TAG, "User needs to enroll MFA");
                        for (MfaFactor factor : enrollTypes) {
                            Log.d(TAG, "Available enrollment type: " + factor.getType());
                        }
                    }
                    
                    // Check if challenge is available (user already enrolled)
                    if (requirements != null && requirements.getChallenge() != null) {
                        List<MfaFactor> challengeTypes = requirements.getChallenge();
                        Log.d(TAG, "User has enrolled MFA factors");
                        for (MfaFactor factor : challengeTypes) {
                            Log.d(TAG, "Available challenge type: " + factor.getType());
                        }
                    }
                    
                    // Proceed with MFA flow using mfaToken
                }
            }
        }

        @Override
        public void onSuccess(Credentials credentials) {
            // Login successful without MFA
        }
    });
```
</details>

<details>
  <summary>Using coroutines</summary>

```kotlin
try {
    val credentials = authentication
        .login("user@example.com", "password", "Username-Password-Authentication")
        .validateClaims()
        .await()
    println(credentials)
} catch (e: AuthenticationException) {
    if (e.isMultifactorRequired) {
        val mfaPayload = e.mfaRequiredErrorPayload
        val mfaToken = mfaPayload?.mfaToken
        val requirements = mfaPayload?.mfaRequirements
        
        // Check if enrollment is required
        requirements?.enroll?.let { enrollTypes ->
            println("User needs to enroll MFA")
            println("Available enrollment types: ${enrollTypes.map { it.type }}")
            // Example output: ["otp", "phone", "push-notification"]
        }
        
        // Check if challenge is available
        requirements?.challenge?.let { challengeTypes ->
            println("User has enrolled MFA factors")
            println("Available challenge types: ${challengeTypes.map { it.type }}")
            // Example output: ["otp", "phone"]
        }
        
        // Proceed with MFA flow using mfaToken
    }
}
```
</details>

#### Creating the MFA API Client

Once you have the MFA token, create an MFA API client to perform MFA operations:

```kotlin
val mfaClient = authentication.mfaClient(mfaToken)
```

<details>
  <summary>Using Java</summary>

```java
MfaApiClient mfaClient = authentication.mfaClient(mfaToken);
```
</details>

##### Using DPoP with MFA

If the originating `AuthenticationAPIClient` has [DPoP](dpop.md#dpop) enabled, the resulting `mfaClient` inherits it automatically, and the final `verify()` call exchanging credentials at `/oauth/token` will carry a DPoP proof:

```kotlin
val authentication = AuthenticationAPIClient(account).useDPoP(context)
val mfaClient = authentication.mfaClient(mfaToken) // DPoP inherited
```

Alternatively, if you are using the `MfaApiClient` on its own, enable DPoP directly on it:

```kotlin
val mfaClient = MfaApiClient(account, mfaToken).useDPoP(context)
```

<details>
  <summary>Using Java</summary>

```java
MfaApiClient mfaClient = new MfaApiClient(account, mfaToken).useDPoP(context);
```
</details>

> [!NOTE]
> The proof is only attached to the token exchange performed by `verify()`. The `getAuthenticators()`, `enroll()`, and `challenge()` calls authenticate with the MFA token as a bearer credential and do not carry a DPoP proof.

#### Getting Available Authenticators

Retrieve the list of authenticators that the user has enrolled and are allowed for this authentication flow. The `factorsAllowed` parameter filters the authenticators based on the allowed factor types from the MFA requirements.

```kotlin
// Convert List<MfaFactor> to List<String> for the factorsAllowed parameter
val factorTypes = requirements?.challenge?.map { it.type } ?: emptyList()

// getAuthenticators() requires at least one factor type. An empty list means the
// requirements carried `enroll` rather than `challenge`, so enroll a factor instead
// (see "Enrolling New Authenticators" below).
if (factorTypes.isEmpty()) {
    // start enrollment
} else {
    mfaClient
        .getAuthenticators(factorsAllowed = factorTypes)
        .start(object: Callback<List<Authenticator>, MfaListAuthenticatorsException> {
            override fun onFailure(exception: MfaListAuthenticatorsException) {
                // Handle error
            }

            override fun onSuccess(authenticators: List<Authenticator>) {
                // Display authenticators for user to choose
                authenticators.forEach { auth ->
                    println("Type: ${auth.authenticatorType}, ID: ${auth.id}")
                }
            }
        })
}
```

<details>
  <summary>Using coroutines</summary>

```kotlin
try {
    val factorTypes = requirements?.challenge?.map { it.type } ?: emptyList()
    // An empty list means enrollment is required — enroll a factor instead of listing authenticators.
    require(factorTypes.isNotEmpty()) { "No challenge factors; start enrollment instead" }
    val authenticators = mfaClient
        .getAuthenticators(factorsAllowed = factorTypes)
        .await()
    println(authenticators)
} catch (e: MfaListAuthenticatorsException) {
    e.printStackTrace()
}
```
</details>

<details>
  <summary>Using Java</summary>

```java
// Convert List<MfaFactor> to List<String> for the factorsAllowed parameter
List<String> factorTypes = new ArrayList<>();
if (requirements != null && requirements.getChallenge() != null) {
    for (MfaFactor factor : requirements.getChallenge()) {
        factorTypes.add(factor.getType());
    }
}

// getAuthenticators() requires at least one factor type. An empty list means the
// requirements carried `enroll` rather than `challenge`, so enroll a factor instead
// (see "Enrolling New Authenticators" below).
if (factorTypes.isEmpty()) {
    // start enrollment
} else {
    mfaClient
        .getAuthenticators(factorTypes)
        .start(new Callback<List<Authenticator>, MfaListAuthenticatorsException>() {
            @Override
            public void onFailure(@NonNull MfaListAuthenticatorsException exception) {
                // Handle error
            }

            @Override
            public void onSuccess(List<Authenticator> authenticators) {
                // Display authenticators for user to choose
                for (Authenticator auth : authenticators) {
                    Log.d(TAG, "Type: " + auth.getAuthenticatorType() + ", ID: " + auth.getId());
                }
            }
        });
}
```
</details>

#### Enrolling New Authenticators

If the user doesn't have an authenticator enrolled, or needs to enroll a new one, you can use the enrollment methods. The available enrollment types depend on your tenant configuration.

##### Enroll Phone (SMS)

```kotlin
mfaClient
    .enroll(MfaEnrollmentType.Phone("+11234567890"))
    .start(object: Callback<EnrollmentChallenge, MfaEnrollmentException> {
        override fun onFailure(exception: MfaEnrollmentException) { }

        override fun onSuccess(enrollment: EnrollmentChallenge) {
            // Phone enrolled - need to verify with OOB code
            val oobCode = enrollment.oobCode
            // For OOB challenges, cast to OobEnrollmentChallenge to access bindingMethod
            if (enrollment is OobEnrollmentChallenge) {
                val bindingMethod = enrollment.bindingMethod
            }
        }
    })
```

<details>
  <summary>Using Java</summary>

```java
mfaClient
    .enroll(MfaEnrollmentType.Phone.INSTANCE.invoke("+11234567890"))
    .start(new Callback<EnrollmentChallenge, MfaEnrollmentException>() {
        @Override
        public void onFailure(@NonNull MfaEnrollmentException exception) { }

        @Override
        public void onSuccess(EnrollmentChallenge enrollment) {
            // Phone enrolled - need to verify with OOB code
            String oobCode = enrollment.getOobCode();
            // For OOB challenges, cast to OobEnrollmentChallenge to access bindingMethod
            if (enrollment instanceof OobEnrollmentChallenge) {
                String bindingMethod = ((OobEnrollmentChallenge) enrollment).getBindingMethod();
            }
        }
    });
```
</details>

##### Enroll Email

```kotlin
mfaClient
    .enroll(MfaEnrollmentType.Email("user@example.com"))
    .start(object: Callback<EnrollmentChallenge, MfaEnrollmentException> {
        override fun onFailure(exception: MfaEnrollmentException) { }

        override fun onSuccess(enrollment: EnrollmentChallenge) {
            // Email enrolled - need to verify with OOB code
            val oobCode = enrollment.oobCode
        }
    })
```

<details>
  <summary>Using Java</summary>

```java
mfaClient
    .enroll(MfaEnrollmentType.Email.INSTANCE.invoke("user@example.com"))
    .start(new Callback<EnrollmentChallenge, MfaEnrollmentException>() {
        @Override
        public void onFailure(@NonNull MfaEnrollmentException exception) { }

        @Override
        public void onSuccess(EnrollmentChallenge enrollment) {
            // Email enrolled - need to verify with OOB code
            String oobCode = enrollment.getOobCode();
        }
    });
```
</details>

##### Enroll OTP (Authenticator App)

```kotlin
mfaClient
    .enroll(MfaEnrollmentType.Otp)
    .start(object: Callback<EnrollmentChallenge, MfaEnrollmentException> {
        override fun onFailure(exception: MfaEnrollmentException) { }

        override fun onSuccess(enrollment: EnrollmentChallenge) {
            // Display QR code or secret for user to scan/enter in authenticator app.
            // The `/mfa/associate` endpoint returns the manual-entry key as `secret`
            // (not `manualInputCode`, which is only populated by the My Account API).
            if (enrollment is TotpEnrollmentChallenge) {
                val secret = enrollment.secret
                val barcodeUri = enrollment.barcodeUri
                val recoveryCodes = enrollment.recoveryCodes
            }
        }
    })
```

<details>
  <summary>Using Java</summary>

```java
mfaClient
    .enroll(MfaEnrollmentType.Otp.INSTANCE)
    .start(new Callback<EnrollmentChallenge, MfaEnrollmentException>() {
        @Override
        public void onFailure(@NonNull MfaEnrollmentException exception) { }

        @Override
        public void onSuccess(EnrollmentChallenge enrollment) {
            // Display QR code or secret for user to scan/enter in authenticator app.
            // The `/mfa/associate` endpoint returns the manual-entry key as `secret`
            // (not `manualInputCode`, which is only populated by the My Account API).
            if (enrollment instanceof TotpEnrollmentChallenge) {
                TotpEnrollmentChallenge totpEnrollment = (TotpEnrollmentChallenge) enrollment;
                String secret = totpEnrollment.getSecret();
                String barcodeUri = totpEnrollment.getBarcodeUri();
                List<String> recoveryCodes = totpEnrollment.getRecoveryCodes();
            }
        }
    });
```
</details>

##### Enroll Push Notification

```kotlin
mfaClient
    .enroll(MfaEnrollmentType.Push)
    .start(object: Callback<EnrollmentChallenge, MfaEnrollmentException> {
        override fun onFailure(exception: MfaEnrollmentException) { }

        override fun onSuccess(enrollment: EnrollmentChallenge) {
            // Display QR code for user to scan with Guardian app
            if (enrollment is TotpEnrollmentChallenge) {
                val barcodeUri = enrollment.barcodeUri
            }
        }
    })
```

<details>
  <summary>Using Java</summary>

```java
mfaClient
    .enroll(MfaEnrollmentType.Push.INSTANCE)
    .start(new Callback<EnrollmentChallenge, MfaEnrollmentException>() {
        @Override
        public void onFailure(@NonNull MfaEnrollmentException exception) { }

        @Override
        public void onSuccess(EnrollmentChallenge enrollment) {
            // Display QR code for user to scan with Guardian app
            if (enrollment instanceof TotpEnrollmentChallenge) {
                String barcodeUri = ((TotpEnrollmentChallenge) enrollment).getBarcodeUri();
            }
        }
    });
```
</details>

#### Challenging an Authenticator

After selecting an authenticator, initiate a challenge. This will send an OTP code (for email/SMS) or push notification to the user.

```kotlin
mfaClient
    .challenge(authenticatorId = "phone|dev_xxxx")
    .start(object: Callback<Challenge, MfaChallengeException> {
        override fun onFailure(exception: MfaChallengeException) { }

        override fun onSuccess(challenge: Challenge) {
            // Challenge initiated
            val challengeType = challenge.challengeType
            val oobCode = challenge.oobCode
            val bindingMethod = challenge.bindingMethod
        }
    })
```

<details>
  <summary>Using Java</summary>

```java
mfaClient
    .challenge("phone|dev_xxxx")
    .start(new Callback<Challenge, MfaChallengeException>() {
        @Override
        public void onFailure(@NonNull MfaChallengeException exception) { }

        @Override
        public void onSuccess(Challenge challenge) {
            // Challenge initiated
            String challengeType = challenge.getChallengeType();
            String oobCode = challenge.getOobCode();
            String bindingMethod = challenge.getBindingMethod();
        }
    });
```
</details>

<details>
  <summary>Using coroutines</summary>

```kotlin
try {
    val challenge = mfaClient
        .challenge(authenticatorId = "phone|dev_xxxx")
        .await()
    println("Challenge type: ${challenge.challengeType}")
} catch (e: MfaChallengeException) {
    e.printStackTrace()
}
```
</details>

##### Verify with OTP (Authenticator App)

```kotlin
mfaClient
    .verify(MfaVerificationType.Otp(otp = "123456"))
    .start(object: Callback<Credentials, MfaVerifyException> {
        override fun onFailure(exception: MfaVerifyException) { }

        override fun onSuccess(credentials: Credentials) {
            // MFA verification successful - user is now logged in
        }
    })
```

<details>
  <summary>Using coroutines</summary>

```kotlin
try {
    val credentials = mfaClient
        .verify(MfaVerificationType.Otp(otp = "123456"))
        .await()
    println(credentials)
} catch (e: MfaVerifyException) {
    e.printStackTrace()
}
```
</details>

<details>
  <summary>Using Java</summary>

```java
mfaClient
    .verify(MfaVerificationType.Otp.INSTANCE.invoke("123456"))
    .start(new Callback<Credentials, MfaVerifyException>() {
        @Override
        public void onFailure(@NonNull MfaVerifyException exception) { }

        @Override
        public void onSuccess(Credentials credentials) {
            // MFA verification successful - user is now logged in
        }
    });
```
</details>

##### Verify with OOB (Email/SMS/Push)

For email, SMS, or push notification verification, use the OOB code from the challenge response along with the binding code (OTP) received by the user:

```kotlin
mfaClient
    .verify(MfaVerificationType.Oob(oobCode = oobCode, bindingCode = "123456")) // bindingCode is optional for push
    .start(object: Callback<Credentials, MfaVerifyException> {
        override fun onFailure(exception: MfaVerifyException) { }

        override fun onSuccess(credentials: Credentials) {
            // MFA verification successful
        }
    })
```

<details>
  <summary>Using Java</summary>

```java
mfaClient
    .verify(MfaVerificationType.Oob.INSTANCE.invoke(oobCode, "123456")) // bindingCode is optional for push
    .start(new Callback<Credentials, MfaVerifyException>() {
        @Override
        public void onFailure(@NonNull MfaVerifyException exception) { }

        @Override
        public void onSuccess(Credentials credentials) {
            // MFA verification successful
        }
    });
```
</details>

##### Verify with Recovery Code

If the user has lost access to their MFA device, they can use a recovery code:

```kotlin
mfaClient
    .verify(MfaVerificationType.RecoveryCode(code = "ABCD1234EFGH5678"))
    .start(object: Callback<Credentials, MfaVerifyException> {
        override fun onFailure(exception: MfaVerifyException) { }

        override fun onSuccess(credentials: Credentials) {
            // MFA verification successful
            // Note: A new recovery code may be returned in credentials
        }
    })
```

<details>
  <summary>Using Java</summary>

```java
mfaClient
    .verify(MfaVerificationType.RecoveryCode.INSTANCE.invoke("ABCD1234EFGH5678"))
    .start(new Callback<Credentials, MfaVerifyException>() {
        @Override
        public void onFailure(@NonNull MfaVerifyException exception) { }

        @Override
        public void onSuccess(Credentials credentials) {
            // MFA verification successful
            // Note: A new recovery code may be returned in credentials
        }
    });
```
</details>

#### Complete MFA Flow Example

Here's a complete example showing the typical MFA flow:

```kotlin
// Step 1: Attempt login
authentication
    .login(email, password, connection)
    .validateClaims()
    .start(object: Callback<Credentials, AuthenticationException> {
        override fun onFailure(exception: AuthenticationException) {
            if (exception.isMultifactorRequired) {
                val mfaPayload = exception.mfaRequiredErrorPayload ?: return
                val mfaToken = mfaPayload.mfaToken ?: return
                val requirements = mfaPayload.mfaRequirements
                
                // Step 2: Create MFA client
                val mfaClient = authentication.mfaClient(mfaToken)
                
                // Step 3: Get available authenticators
                // Convert List<MfaFactor> to List<String> for the factorsAllowed parameter
                val factorTypes = requirements?.challenge?.map { it.type } ?: emptyList()
                mfaClient
                    .getAuthenticators(factorsAllowed = factorTypes)
                    .start(object: Callback<List<Authenticator>, MfaListAuthenticatorsException> {
                        override fun onSuccess(authenticators: List<Authenticator>) {
                            if (authenticators.isNotEmpty()) {
                                // Step 4: Challenge the first authenticator
                                val authenticator = authenticators.first()
                                mfaClient
                                    .challenge(authenticatorId = authenticator.id)
                                    .start(object: Callback<Challenge, MfaChallengeException> {
                                        override fun onSuccess(challenge: Challenge) {
                                            // Step 5: Prompt user for OTP and verify
                                            // ... show OTP input UI, then call verify()
                                        }
                                        override fun onFailure(e: MfaChallengeException) { }
                                    })
                            } else {
                                // No authenticators enrolled - need to enroll one
                                // ... show enrollment UI
                            }
                        }
                        override fun onFailure(e: MfaListAuthenticatorsException) { }
                    })
            }
        }

        override fun onSuccess(credentials: Credentials) {
            // Login successful without MFA
        }
    })
```

<details>
  <summary>Using Java</summary>

```java
// Step 1: Attempt login
authentication
    .login(email, password, connection)
    .validateClaims()
    .start(new Callback<Credentials, AuthenticationException>() {
        @Override
        public void onFailure(@NonNull AuthenticationException exception) {
            if (exception.isMultifactorRequired()) {
                MfaRequiredErrorPayload mfaPayload = exception.getMfaRequiredErrorPayload();
                if (mfaPayload == null) return;
                String mfaToken = mfaPayload.getMfaToken();
                if (mfaToken == null) return;
                MfaRequirements requirements = mfaPayload.getMfaRequirements();
                
                // Step 2: Create MFA client
                MfaApiClient mfaClient = authentication.mfaClient(mfaToken);
                
                // Step 3: Get available authenticators
                List<String> factorTypes = new ArrayList<>();
                if (requirements != null && requirements.getChallenge() != null) {
                    for (MfaFactor factor : requirements.getChallenge()) {
                        factorTypes.add(factor.getType());
                    }
                }
                
                mfaClient
                    .getAuthenticators(factorTypes)
                    .start(new Callback<List<Authenticator>, MfaListAuthenticatorsException>() {
                        @Override
                        public void onSuccess(List<Authenticator> authenticators) {
                            if (!authenticators.isEmpty()) {
                                // Step 4: Challenge the first authenticator
                                Authenticator authenticator = authenticators.get(0);
                                mfaClient
                                    .challenge(authenticator.getId())
                                    .start(new Callback<Challenge, MfaChallengeException>() {
                                        @Override
                                        public void onSuccess(Challenge challenge) {
                                            // Step 5: Prompt user for OTP and verify
                                            // ... show OTP input UI, then call verify()
                                        }
                                        @Override
                                        public void onFailure(@NonNull MfaChallengeException e) { }
                                    });
                            } else {
                                // No authenticators enrolled - need to enroll one
                                // ... show enrollment UI
                            }
                        }
                        @Override
                        public void onFailure(@NonNull MfaListAuthenticatorsException e) { }
                    });
            }
        }

        @Override
        public void onSuccess(Credentials credentials) {
            // Login successful without MFA
        }
    });
```
</details>

#### MFA Client Errors

The MFA client produces specific exception types for different operations:

- **`MfaListAuthenticatorsException`**: Returned by `getAuthenticators()` when listing authenticators fails
- **`MfaEnrollmentException`**: Returned by `enroll()` methods when enrollment fails
- **`MfaChallengeException`**: Returned by `challenge()` when initiating a challenge fails
- **`MfaVerifyException`**: Returned by `verify()` methods when verification fails

All MFA exception types provide:
- `code`: The error code from the API response
- `description`: A human-readable error description
- `statusCode`: The HTTP status code
- `getValue(key)`: Access to additional error properties from the response
- `cause`: The underlying `Throwable`, if any (useful for network errors)
- `isNetworkError`: Whether the request failed due to network issues

##### Example error handling

```kotlin
mfaClient
    .verify(MfaVerificationType.Otp(otp = "123456"))
    .start(object: Callback<Credentials, MfaVerifyException> {
        override fun onFailure(exception: MfaVerifyException) {
            println("Failed with code: ${exception.code}")
            println("Description: ${exception.description}")
            println("Status code: ${exception.statusCode}")
        }

        override fun onSuccess(credentials: Credentials) {
            // MFA verification successful
        }
    })
```

<details>
  <summary>Using coroutines</summary>

```kotlin
try {
    val credentials = mfaClient
        .verify(MfaVerificationType.Otp(otp = "123456"))
        .await()
    println(credentials)
} catch (e: MfaVerifyException) {
    println("Failed with code: ${e.code}")
    println("Description: ${e.description}")
    println("Status code: ${e.statusCode}")
}
```
</details>

<details>
  <summary>Using Java</summary>

```java
mfaClient
    .verify(MfaVerificationType.Otp.INSTANCE.invoke("123456"))
    .start(new Callback<Credentials, MfaVerifyException>() {
        @Override
        public void onFailure(@NonNull MfaVerifyException exception) {
            Log.e(TAG, "Failed with code: " + exception.getCode());
            Log.e(TAG, "Description: " + exception.getDescription());
            Log.e(TAG, "Status code: " + exception.getStatusCode());
        }

        @Override
        public void onSuccess(Credentials credentials) {
            // MFA verification successful
        }
    });
```
</details>

##### Common error codes

Each MFA exception type includes specific error codes to help you handle different scenarios:

**MfaListAuthenticatorsException** (from `getAuthenticators()`):
- `invalid_request`: Request parameters are invalid (e.g., missing or empty factorsAllowed)
- `invalid_token`: MFA token is invalid or expired
- `access_denied`: User lacks permission to access this resource

**MfaEnrollmentException** (from `enroll()` methods):
- `invalid_request`: Enrollment parameters are invalid
- `invalid_token`: MFA token is invalid or expired
- `enrollment_conflict`: Authenticator is already enrolled
- `unsupported_challenge_type`: Requested factor type is not enabled

**MfaChallengeException** (from `challenge()`):
- `invalid_request`: Challenge parameters are invalid
- `invalid_token`: MFA token is invalid or expired
- `authenticator_not_found`: Specified authenticator doesn't exist
- `unsupported_challenge_type`: Authenticator type doesn't support challenges

**MfaVerifyException** (from `verify()` methods):
- `invalid_grant`: Verification code is incorrect or expired
- `invalid_token`: MFA token is invalid or expired
- `invalid_oob_code`: Out-of-band code is invalid
- `invalid_binding_code`: Binding code (SMS/email code) is incorrect
- `expired_token`: Verification code has expired

##### Handling specific error cases

You can check the `code` property to handle specific error scenarios:

```kotlin
mfaClient
    .enroll(MfaEnrollmentType.Phone("+12025550135"))
    .start(object: Callback<EnrollmentChallenge, MfaEnrollmentException> {
        override fun onFailure(exception: MfaEnrollmentException) {
            when (exception.code) {
                "invalid_token" -> println("MFA token is invalid or expired")
                "invalid_phone_number" -> println("Phone number format is invalid")
                "unsupported_challenge_type" -> println("This MFA factor is not supported")
                else -> println("Enrollment failed: ${exception.description}")
            }
        }

        override fun onSuccess(enrollment: EnrollmentChallenge) {
            // Enrollment successful
        }
    })
```

##### Network errors

MFA exceptions include an `isNetworkError` property to help handle transient network failures:

```kotlin
mfaClient
    .verify(MfaVerificationType.Otp(otp = "123456"))
    .start(object: Callback<Credentials, MfaVerifyException> {
        override fun onFailure(exception: MfaVerifyException) {
            if (exception.isNetworkError) {
                println("Network connectivity issue - check your connection")
            } else {
                println("Verification failed: ${exception.description}")
            }
        }

        override fun onSuccess(credentials: Credentials) {
            // MFA verification successful
        }
    })
```

The `isNetworkError` property returns `true` for network-related failures such as:
- No internet connection
- DNS lookup failures
- Connection timeouts

##### Authentication flow errors

When handling MFA-required errors from the authentication flow (not the MFA client), you'll receive `AuthenticationException` values. Use these properties to identify MFA-related scenarios:

- `isMultifactorRequired`: MFA is required to authenticate
- `mfaRequiredErrorPayload`: Contains the MFA token and requirements when MFA is required

```kotlin
authentication
    .login(email, password, connection)
    .start(object: Callback<Credentials, AuthenticationException> {
        override fun onFailure(exception: AuthenticationException) {
            if (exception.isMultifactorRequired) {
                val mfaPayload = exception.mfaRequiredErrorPayload
                val mfaToken = mfaPayload?.mfaToken
                // Proceed with MFA flow
            }
        }

        override fun onSuccess(credentials: Credentials) {
            // Login successful
        }
    })
```

> [!WARNING]
> Do not parse or otherwise rely on the error messages to handle the errors. The error messages are not part of the API and can change. Use the error `code` property and exception types instead, which are part of the API.
