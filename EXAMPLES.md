# Examples using Auth0.Android

- [Examples using Auth0.Android](#examples-using-auth0android)
  - [Authenticate with any Auth0 connection](#authenticate-with-any-auth0-connection)
  - [Specify audience](#specify-audience)
  - [Specify scope](#specify-scope)
  - [Specify Connection scope](#specify-connection-scope)
  - [Specify Parameter](#specify-parameter)
  - [Specify a Custom Authorize URL](#specify-a-custom-authorize-url)
  - [Customize the Custom Tabs UI](#customize-the-custom-tabs-ui)
  - [Changing the Return To URL scheme](#changing-the-return-to-url-scheme)
  - [Specify a Custom Logout URL](#specify-a-custom-logout-url)
  - [Trusted Web Activity](#trusted-web-activity)
  - [DPoP [EA]](#dpop-ea)
  - [Authentication API](#authentication-api)
    - [Login with database connection](#login-with-database-connection)
    - [Login using MFA with One Time Password code](#login-using-mfa-with-one-time-password-code)
    - [Passwordless Login](#passwordless-login)
      - [Step 1: Request the code](#step-1-request-the-code)
      - [Step 2: Input the code](#step-2-input-the-code)
    - [Sign Up with a database connection](#sign-up-with-a-database-connection)
    - [Get user information](#get-user-information)
    - [Custom Token Exchange](#custom-token-exchange)
    - [Native to Web SSO login [EA]](#native-to-web-sso-login-ea)
    - [DPoP [EA]](#dpop-ea-1)
  - [My Account API](#my-account-api)
    - [Enroll a new passkey](#enroll-a-new-passkey)
    - [Get Available Factors](#get-available-factors)
    - [Get All Enrolled Authentication Methods](#get-all-enrolled-authentication-methods)
    - [Get a Single Authentication Method by ID](#get-a-single-authentication-method-by-id)
    - [Enroll a Phone Method](#enroll-a-phone-method)
    - [Enroll an Email Method](#enroll-an-email-method)
    - [Enroll a TOTP (Authenticator App) Method](#enroll-a-totp-authenticator-app-method)
    - [Enroll a Push Notification Method](#enroll-a-push-notification-method)
    - [Enroll a Recovery Code](#enroll-a-recovery-code)
    - [Verify an Enrollment](#verify-an-enrollment)
    - [Delete an Authentication Method](#delete-an-authentication-method)
  - [Credentials Manager](#credentials-manager)
    - [Secure Credentials Manager](#secure-credentials-manager)
      - [Usage](#usage)
      - [Requiring Authentication](#requiring-authentication)
    - [Other Credentials](#other-credentials)
    - [Handling Credentials Manager exceptions](#handling-credentials-manager-exceptions)
  - [Passkeys](#passkeys)
  - [Bot Protection](#bot-protection)
  - [Management API](#management-api)
    - [Link users](#link-users)
    - [Unlink users](#unlink-users)
    - [Get User Profile](#get-user-profile)
    - [Update User Metadata](#update-user-metadata)
  - [Token Validation](#token-validation)
  - [Organizations](#organizations)
    - [Log in to an organization](#log-in-to-an-organization)
    - [Accept user invitations](#accept-user-invitations)
  - [Networking client customization](#networking-client-customization)
    - [Timeout configuration](#timeout-configuration)
    - [Logging configuration](#logging-configuration)
    - [Set additional headers for all requests](#set-additional-headers-for-all-requests)
    - [Advanced configuration](#advanced-configuration)
  - [Unit testing with JUnit 4 or JUnit 5](#unit-testing-with-junit-4-or-junit-5)
    - [Handling `Method getMainLooper in android.os.Looper not mocked` errors](#handling-method-getmainlooper-in-androidoslooper-not-mocked-errors)
    - [Handling SSL errors](#handling-ssl-errors)
  - [Proguard](#proguard)

## Authenticate with any Auth0 connection

The connection must first be enabled in the Auth0 dashboard for this Auth0 application.

```kotlin
WebAuthProvider.login(account)
    .withConnection("twitter")
    .start(this, callback)
```

## Specify audience

```kotlin
WebAuthProvider.login(account)
    .withAudience("https://{YOUR_AUTH0_DOMAIN}/api/v2/")
    .start(this, callback)
```

The sample above requests tokens with the audience required to call the [Management API](https://auth0.com/docs/api/management/v2) endpoints.

> Replace `{YOUR_AUTH0_DOMAIN}` with your actual Auth0 domain (i.e. `mytenant.auth0.com`). If you've set up the tenant to use "Custom Domains", use that value here.

## Specify scope

```kotlin
WebAuthProvider.login(account)
    .withScope("openid profile email read:users")
    .start(this, callback)
```

> The default scope used is `openid profile email`. Regardless of the scopes passed here, the `openid` scope is always enforced.

## Specify Connection scope

```kotlin
WebAuthProvider.login(account)
    .withConnectionScope("email", "profile", "calendar:read")
    .start(this, callback)
```

## Specify Parameter

To [prompt](https://auth0.com/docs/customize/universal-login-pages/customize-login-text-prompts#prompt-values) the user to login or to send custom parameters in the request, `.withParameters` method can be used.

```kotlin
WebAuthProvider.login(account)
    .withParameters(mapOf("prompt" to "login", "custom" to "value"))
    .start(this, callback)
```

## Specify a Custom Authorize URL

In scenarios where you need to use a specific authorize endpoint different from the one derived from your Auth0 domain (e.g., for custom domains, specific tenant configurations), you can provide a full custom URL to the `/authorize` endpoint.

```kotlin
WebAuthProvider
.login(account)
.withAuthorizeUrl("https://YOUR_CUSTOM_TENANT_OR_AUTH_DOMAIN/authorize")
.start(this, callback)
```

<details>
  <summary>Using Java</summary>

```java
WebAuthProvider
.login(account)
.withAuthorizeUrl("https://YOUR_CUSTOM_TENANT_OR_AUTH_DOMAIN/authorize")
.start(this, callback);
```
</details>

The URL provided to `.withAuthorizeUrl()` must be a complete and valid HTTPS URL for an OAuth 2.0 authorize endpoint. The SDK will append standard OAuth parameters to this custom base URL.

## Customize the Custom Tabs UI

If the device where the app is running has a Custom Tabs compatible Browser, a Custom Tab will be preferred for the logout flow. You can customize the Page Title visibility, the Toolbar color, and the supported Browser applications by using the `CustomTabsOptions` class.

```kotlin
val ctOptions = CustomTabsOptions.newBuilder()
    .withToolbarColor(R.color.ct_toolbar_color)
    .showTitle(true)
    .build()
 
WebAuthProvider.login(account)
    .withCustomTabsOptions(ctOptions)
    .start(this, callback)
```

<details>
  <summary>Using Java</summary>

```java
CustomTabsOptions options = CustomTabsOptions.newBuilder()
   .withToolbarColor(R.color.ct_toolbar_color)
   .showTitle(true)
   .build();

WebAuthProvider.login(account)
   .withCustomTabsOptions(options)
   .start(MainActivity.this, callback);
```
</details>

## Changing the Return To URL scheme
This configuration will probably match what you've done for the [authentication setup](#a-note-about-app-deep-linking).

```kotlin
WebAuthProvider.logout(account)
    .withScheme("myapp")
    .start(this, logoutCallback)
```

## Specify a Custom Logout URL

Similar to the authorize URL, you can specify a custom logout endpoint if your setup requires it (e.g., using custom domains or for specific logout behaviors configured in your Auth0 tenant).

```kotlin
WebAuthProvider
.logout(account)
.withLogoutUrl("https://YOUR_CUSTOM_TENANT_OR_AUTH_DOMAIN/v2/logout")
.start(this, logoutCallback)
```
<details>
  <summary>Using Java</summary>

```java
WebAuthProvider
.logout(account)
.withLogoutUrl("https://YOUR_CUSTOM_TENANT_OR_AUTH_DOMAIN/v2/logout")
.start(this, logoutCallback);
```
</details>

The URL provided to `.withLogoutUrl()` must be a complete and valid HTTPS URL for logout endpoint. The SDK will append standard logout parameters to this custom base URL.

## Trusted Web Activity

Trusted Web Activity is a feature provided by some browsers to provide a native look and feel to the custom tabs.

To use this feature, there are some additional steps you must take:

- We need the SHA256 fingerprints of the app’s signing certificate. To get this, you can run the following command on your APK
```shell
keytool -printcert -jarfile sample-debug.apk
```
- The fingerprint has to be updated in the [Auth0 Dashboard](https://manage.auth0.com/dashboard/eu/poovamraj/applications) under
Applications > *Specific Application* > Settings > Advanced Settings > Device Settings > Key Hashes
- App's package name has to be entered in the field above

Once the above prerequisites are met, you can call your login method as below to open your web authentication in Trusted Web Activity.

```kotlin
WebAuthProvider.login(account)
    .withTrustedWebActivity()
    .await(this)
```

## DPoP [EA]

> [!NOTE]  
> This feature is currently available in [Early Access](https://auth0.com/docs/troubleshoot/product-lifecycle/product-release-stages#early-access). Please reach out to Auth0 support to get it enabled for your tenant.

[DPoP](https://www.rfc-editor.org/rfc/rfc9449.html) (Demonstrating Proof of Possession) is an application-level mechanism for sender-constraining OAuth 2.0 access and refresh tokens by proving that the app is in possession of a certain private key. You can enable it by calling the `useDPoP()` method.

```kotlin
WebAuthProvider
    .useDPoP()
    .login(account)
    .start(requireContext(), object : Callback<Credentials, AuthenticationException> {
        override fun onSuccess(result: Credentials) {
           println("Credentials $result")
        }
        override fun onFailure(error: AuthenticationException) {
            print("Error $error")
        }
    })
```

> [!IMPORTANT]
> DPoP will only be used for new user sessions created after enabling it. DPoP **will not** be applied to any requests involving existing access and refresh tokens (such as exchanging the refresh token for new credentials).
>
> This means that, after you've enabled it in your app, DPoP will only take effect when users log in again. It's up to you to decide how to roll out this change to your users. For example, you might require users to log in again the next time they open your app. You'll need to implement the logic to handle this transition based on your app's requirements.

When making requests to your own APIs, use the `DPoP.getHeaderData()` method to get the `Authorization` and `DPoP` header values to be used. The `Authorization` header value is generated using the access token and token type, while the `DPoP` header value is the generated DPoP proof.

```kotlin
val url ="https://example.com/api/endpoint"
val httpMethod = "GET"
 val headerData = DPoP.getHeaderData(
                    httpMethod, url,
                    accessToken, tokenType
                )
httpRequest.apply{
    addHeader("Authorization", headerData.authorizationHeader)
    headerData.dpopProof?.let {
        addHeader("DPoP", it)
    }
}
```
If your API is issuing DPoP nonces to prevent replay attacks, you can pass the nonce value to the `getHeaderData()` method to include it in the DPoP proof. Use the `DPoP.isNonceRequiredError(response: Response)` method to check if a particular API response failed because a nonce is required.

```kotlin
if (DPoP.isNonceRequiredError(response)) {
    val nonce = response.headers["DPoP-Nonce"]
    val dpopProof = DPoPProvider.generateProof(
        url, httpMethod, accessToken, nonce
    )
    // Retry the request with the new proof
}
```

On logout, you should call `DPoP.clearKeyPair()` to delete the user's key pair from the Keychain.

```kotlin
WebAuthProvider.logout(account)
            .start(requireContext(), object : Callback<Void?, AuthenticationException> {
                override fun onSuccess(result: Void?) {
                    DPoPProvider.clearKeyPair()
                }
                override fun onFailure(error: AuthenticationException) {
                }

            })
```
> [!NOTE]  
> DPoP is supported only on Android version 6.0 (API level 23) and above. Trying to use DPoP in any older versions will result in an exception.

## Authentication API

The client provides methods to authenticate the user against the Auth0 server.

Create a new instance by passing the account:

```kotlin
val authentication = AuthenticationAPIClient(account)
```

<details>
  <summary>Using Java</summary>

```java
AuthenticationAPIClient authentication = new AuthenticationAPIClient(account);
```
</details>

**Note:** If your Auth0 account has the ["Bot Protection"](https://auth0.com/docs/anomaly-detection/bot-protection) feature enabled, your requests might be flagged for verification. Read how to handle this scenario on the [Bot Protection](#bot-protection) section.

### Login with database connection

```kotlin
authentication
    .login("info@auth0.com", "a secret password", "my-database-connection")
    .validateClaims() //mandatory
    .start(object: Callback<Credentials, AuthenticationException> {
        override fun onFailure(exception: AuthenticationException) { }

        override fun onSuccess(credentials: Credentials) { }
    })
```

<details>
  <summary>Using coroutines</summary>

```kotlin
try {
    val credentials = authentication
        .login("info@auth0.com", "a secret password", "my-database-connection")
        .validateClaims()
        .await()
    println(credentials)
} catch (e: AuthenticationException) {
    e.printStacktrace()
}
```
</details>

<details>
  <summary>Using Java</summary>

```java
authentication
    .login("info@auth0.com", "a secret password", "my-database-connection")
    .validateClaims() //mandatory
    .start(new Callback<Credentials, AuthenticationException>() {
        @Override
        public void onSuccess(@Nullable Credentials payload) {
            //Logged in!
        }

        @Override
        public void onFailure(@NonNull AuthenticationException error) {
            //Error!
        }
    });
```
</details>

> The default scope used is `openid profile email`. Regardless of the scopes set to the request, the `openid` scope is always enforced.

### Login using MFA with One Time Password code

This call requires the client to have the *MFA* Client Grant Type enabled. Check [this article](https://auth0.com/docs/clients/client-grant-types) to learn how to enable it.

When you sign in to a multifactor authentication enabled connection using the `login` method, you receive an error standing that MFA is required for that user along with an `mfa_token` value. Use this value to call `loginWithOTP` and complete the MFA flow passing the One Time Password from the enrolled MFA code generator app.

```kotlin
authentication
    .loginWithOTP("the mfa token", "123456")
    .validateClaims() //mandatory
    .start(object: Callback<Credentials, AuthenticationException> {
        override fun onFailure(exception: AuthenticationException) { }

        override fun onSuccess(credentials: Credentials) { }
    })
```

<details>
  <summary>Using coroutines</summary>

```kotlin
try {
    val credentials = authentication
        .loginWithOTP("the mfa token", "123456")
        .validateClaims()
        .await()
    println(credentials)
} catch (e: AuthenticationException) {
    e.printStacktrace()
}
```
</details>

<details>
  <summary>Using Java</summary>

```java
authentication
    .loginWithOTP("the mfa token", "123456")
    .validateClaims() //mandatory
    .start(new Callback<Credentials, AuthenticationException>() {
        @Override
        public void onSuccess(@Nullable Credentials payload) {
            //Logged in!
        }

        @Override
        public void onFailure(@NonNull AuthenticationException error) {
            //Error!
        }
    });
```
</details>

> The default scope used is `openid profile email`. Regardless of the scopes set to the request, the `openid` scope is always enforced.

### Passwordless Login

This feature requires your Application to have the *Passwordless OTP* enabled. See [this article](https://auth0.com/docs/clients/client-grant-types) to learn how to enable it.

Passwordless is a 2 step flow:

#### Step 1: Request the code

```kotlin
authentication
    .passwordlessWithEmail("info@auth0.com", PasswordlessType.CODE, "my-passwordless-connection")
    .start(object: Callback<Void, AuthenticationException> {
        override fun onFailure(exception: AuthenticationException) { }

        override fun onSuccess(result: Void?) { }
    })
```

<details>
  <summary>Using coroutines</summary>

```kotlin
try {
    val result = authentication
        .passwordlessWithEmail("info@auth0.com", PasswordlessType.CODE, "my-passwordless-connection")
        .await()
    println(result)
} catch (e: AuthenticationException) {
    e.printStacktrace()
}
```
</details>

<details>
  <summary>Using Java</summary>

```java
authentication
    .passwordlessWithEmail("info@auth0.com", PasswordlessType.CODE, "my-passwordless-connection")
    .start(new Callback<Void, AuthenticationException>() {
        @Override
        public void onSuccess(Void payload) {
            //Code sent!
        }

        @Override
        public void onFailure(@NonNull AuthenticationException error) {
            //Error!
        }
    });
```
</details>

#### Step 2: Input the code

```kotlin
authentication
    .loginWithEmail("info@auth0.com", "123456", "my-passwordless-connection")
    .validateClaims() //mandatory
    .start(object: Callback<Credentials, AuthenticationException> {
       override fun onFailure(exception: AuthenticationException) { }

       override fun onSuccess(credentials: Credentials) { }
   })
```

<details>
  <summary>Using coroutines</summary>

```kotlin
try {
    val credentials = authentication
        .loginWithEmail("info@auth0.com", "123456", "my-passwordless-connection")
        .validateClaims()
        .await()
    println(credentials)
} catch (e: AuthenticationException) {
    e.printStacktrace()
}
```
</details>


<details>
  <summary>Using Java</summary>

```java
authentication
    .loginWithEmail("info@auth0.com", "123456", "my-passwordless-connection")
    .validateClaims() //mandatory
    .start(new Callback<Credentials, AuthenticationException>() {
        @Override
        public void onSuccess(@Nullable Credentials payload) {
            //Logged in!
        }

        @Override
        public void onFailure(@NonNull AuthenticationException error) {
            //Error!
        }
    });
```
</details>

> The default scope used is `openid profile email`. Regardless of the scopes set to the request, the `openid` scope is always enforced.

### Sign Up with a database connection

```kotlin
authentication
    .signUp("info@auth0.com", "a secret password", "my-database-connection")
    .validateClaims() //mandatory
    .start(object: Callback<Credentials, AuthenticationException> {
        override fun onFailure(exception: AuthenticationException) { }

        override fun onSuccess(credentials: Credentials) { }
    })
```

<details>
  <summary>Using coroutines</summary>

```kotlin
try {
    val credentials = authentication
        .signUp("info@auth0.com", "a secret password", "my-database-connection")
        .validateClaims()
        .await()
    println(credentials)
} catch (e: AuthenticationException) {
    e.printStacktrace()
}
```
</details>

<details>
  <summary>Using Java</summary>

```java
authentication
    .signUp("info@auth0.com", "a secret password", "my-database-connection")
    .validateClaims() //mandatory
    .start(new Callback<Credentials, AuthenticationException>() {
        @Override
        public void onSuccess(@Nullable Credentials payload) {
            //Signed Up & Logged in!
        }

        @Override
        public void onFailure(@NonNull AuthenticationException error) {
            //Error!
        }
    });
```
</details>

> The default scope used is `openid profile email`. Regardless of the scopes set to the request, the `openid` scope is always enforced.

### Get user information

```kotlin
authentication
   .userInfo("user access_token")
   .start(object: Callback<UserProfile, AuthenticationException> {
       override fun onFailure(exception: AuthenticationException) { }

       override fun onSuccess(profile: UserProfile) { }
   })
```

<details>
  <summary>Using coroutines</summary>

```kotlin
try {
    val user = authentication
        .userInfo("user access_token")
        .await()
    println(user)
} catch (e: AuthenticationException) {
    e.printStacktrace()
}
```
</details>

<details>
  <summary>Using Java</summary>

```java
authentication
   .userInfo("user access_token")
   .start(new Callback<UserProfile, AuthenticationException>() {
       @Override
       public void onSuccess(@Nullable UserProfile payload) {
           //Got the profile!
       }

       @Override
       public void onFailure(@NonNull AuthenticationException error) {
           //Error!
       }
   });
```
</details>

### Custom Token Exchange

```kotlin
authentication
    .customTokenExchange("subject_token_type", "subject_token")
    .start(object : Callback<Credentials, AuthenticationException> {
        override fun onSuccess(result: Credentials) {
            // Handle success
        }

        override fun onFailure(exception: AuthenticationException) {
            // Handle error
        }

    })
```
<details> 
    <summary>Using coroutines</summary> 

``` kotlin 
try {
    val credentials = authentication
        .tokenExchange("subject_token_type", "subject_token")
        .await()
} catch (e: AuthenticationException) {
    e.printStacktrace()
}
```
</details>

<details>
  <summary>Using Java</summary>

```java
authentication
    .customTokenExchange("subject_token_type", "subject_token")
    .start(new Callback<Credentials, AuthenticationException>() {
        @Override
        public void onSuccess(@Nullable Credentials payload) {
            // Handle success
        }
        @Override
        public void onFailure(@NonNull AuthenticationException error) {
            // Handle error
        }
    });
```


</details>


## Native to Web SSO login [EA]

> [!NOTE]  
> This feature is currently available in [Early Access](https://auth0.com/docs/troubleshoot/product-lifecycle/product-release-stages#early-access). Please reach out to Auth0 support to get it 
> enabled for your tenant.

This feature allows you to authenticate a user in a web session using the refresh token obtained from the native session without requiring the user to log in again.

Call the API to fetch a webSessionTransferToken in exchange for a refresh token. Use the obtained token to authenticate the user by calling the `/authorize` endpoint, passing the token as a query parameter or a cookie value.

```kotlin
    authentication
    .ssoExchange("refresh_token")
    .start(object : Callback<SSOCredentials, AuthenticationException> {
        override fun onSuccess(result: SSOCredentials) {
            // Use the sessionTransferToken token to authenticate the user in a web session in your app
        }

        override fun onFailure(exception: AuthenticationException) {
            // Handle error
        }

    })
```

<details> 
    <summary>Using coroutines</summary> 

``` kotlin 
try {
    val ssoCredentials = authentication
        .ssoExchange("refresh_token")
        .await()
} catch (e: AuthenticationException) {
    e.printStacktrace()
}
```
</details>

<details>
  <summary>Using Java</summary>

```java
authentication
    .ssoExchange("refresh_token")
    .start(new Callback<SSOCredentials, AuthenticationException>() {
        @Override
        public void onSuccess(@Nullable SSOCredentials result) {
            // Handle success
        }
        @Override
        public void onFailure(@NonNull AuthenticationException error) {
            // Handle error
        }
    });
```
</details>

## DPoP [EA]

> [!NOTE]  
> This feature is currently available in [Early Access](https://auth0.com/docs/troubleshoot/product-lifecycle/product-release-stages#early-access). Please reach out to Auth0 support to get it enabled for your tenant.

[DPoP](https://www.rfc-editor.org/rfc/rfc9449.html) (Demonstrating Proof of Posession) is an application-level mechanism for sender-constraining OAuth 2.0 access and refresh tokens by proving that the app is in possession of a certain private key. You can enable it by calling the `useDPoP()` method. This ensures that DPoP proofs are generated for requests made through the AuthenticationAPI client.

```kotlin
val client = AuthenticationAPIClient(account).useDPoP()
```

[!IMPORTANT]
> DPoP will only be used for new user sessions created after enabling it. DPoP **will not** be applied to any requests involving existing access and refresh tokens (such as exchanging the refresh token for new credentials).
>
> This means that, after you've enabled it in your app, DPoP will only take effect when users log in again. It's up to you to decide how to roll out this change to your users. For example, you might require users to log in again the next time they open your app. You'll need to implement the logic to handle this transition based on your app's requirements.

When making requests to your own APIs, use the `DPoP.getHeaderData()` method to get the `Authorization` and `DPoP` header values to be used. The `Authorization` header value is generated using the access token and token type, while the `DPoP` header value is the generated DPoP proof.

```kotlin
val url ="https://example.com/api/endpoint"
val httpMethod = "GET"
 val headerData = DPoP.getHeaderData(
                    httpMethod, url,
                    accessToken, tokenType
                )
httpRequest.apply{
    addHeader("Authorization", headerData.authorizationHeader)
    headerData.dpopProof?.let {
        addHeader("DPoP", it)
    }
}
```
If your API is issuing DPoP nonces to prevent replay attacks, you can pass the nonce value to the `getHeaderData()` method to include it in the DPoP proof. Use the `DPoP.isNonceRequiredError(response: Response)` method to check if a particular API response failed because a nonce is required.

```kotlin
if (DPoP.isNonceRequiredError(response)) {
    val nonce = response.headers["DPoP-Nonce"]
    val dpopProof = DPoPProvider.generateProof(
        url, httpMethod, accessToken, nonce
    )
    // Retry the request with the new proof
}
```

On logout, you should call `DPoP.clearKeyPair()` to delete the user's key pair from the Keychain.

```kotlin

DPoP.clearKeyPair()

```

> [!NOTE]  
> DPoP is supported only on Android version 6.0 (API level 23) and above. Trying to use DPoP in any older versions will result in an exception.



## My Account API

> [!NOTE]
> The My Account API is currently available in [Early Access](https://auth0.com/docs/troubleshoot/product-lifecycle/product-release-stages#early-access). Please reach out to Auth0 support to get it enabled for your tenant.

Use the Auth0 My Account API to manage the current user's account.

To call the My Account API, you need an access token issued specifically for this API, including any required scopes for the operations you want to perform. See [API credentials [EA]](#api-credentials-ea) to learn how to obtain one.

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

Retrieves a detailed list of all the authentication methods that the current user has already enrolled in.


**Prerequisites:**

The user must have one or more authentication methods already enrolled.

```kotlin
myAccountClient.getAuthenticationMethods()
    .start(object : Callback<List<AuthenticationMethod>, MyAccountException> {
        override fun onSuccess(result: AuthenticationMethods) {
            // List of enrolled methods in result.authenticationMethods
        }
        override fun onFailure(error: MyAccountException) { }
    })
```
<details>
    <summary>Using Java</summary>

```java
myAccountClient.getAuthenticationMethods()
    .start(new Callback<List<AuthenticationMethod>, MyAccountException>() {
        @Override
        public void onSuccess(AuthenticationMethods result) {
            // List of enrolled methods in result.getAuthenticationMethods()
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


## Credentials Manager

### Secure Credentials Manager

This version adds encryption to the data storage. Additionally, in those devices where a Secure Lock Screen has been configured it can require the user to authenticate before letting them obtain the stored credentials. The class is called `SecureCredentialsManager`.

#### Usage
The usage is similar to the previous version, with the slight difference that the manager now requires a valid android `Context` as shown below:

```kotlin
val storage = SharedPreferencesStorage(this)
val manager = SecureCredentialsManager(this, account, storage)
```

<details>
  <summary>Using Java</summary>

```java
Storage storage = new SharedPreferencesStorage(this);
SecureCredentialsManager manager = new SecureCredentialsManager(this, account, storage);
```
</details>

#### Requiring Authentication

You can require the user authentication to obtain credentials. This will make the manager prompt the user with the device's configured Lock Screen, which they must pass correctly in order to obtain the credentials. **This feature is only available on devices where the user has setup a secured Lock Screen** (PIN, Pattern, Password or Fingerprint).

To enable authentication you must supply an instance of `FragmentActivity` on which the authentication prompt to be shown, and an instance of `LocalAuthenticationOptions` to configure the authentication prompt with details like title and authentication level when creating an instance of `SecureCredentialsManager` as shown in the snippet below.

```kotlin
val localAuthenticationOptions =
    LocalAuthenticationOptions.Builder().setTitle("Authenticate").setDescription("Accessing Credentials")
        .setAuthenticationLevel(AuthenticationLevel.STRONG).setNegativeButtonText("Cancel")
        .setDeviceCredentialFallback(true)
        .build()
val storage = SharedPreferencesStorage(this)
val manager = SecureCredentialsManager(
    this, account, storage, fragmentActivity,
    localAuthenticationOptions
)
```

<details>
  <summary>Using Java</summary>

```java
LocalAuthenticationOptions localAuthenticationOptions =
        new LocalAuthenticationOptions.Builder().setTitle("Authenticate").setDescription("Accessing Credentials")
                .setAuthenticationLevel(AuthenticationLevel.STRONG).setNegativeButtonText("Cancel")
                .setDeviceCredentialFallback(true)
                .build();
Storage storage = new SharedPreferencesStorage(context);
SecureCredentialsManager secureCredentialsManager = new SecureCredentialsManager(
        context, auth0, storage, fragmentActivity,
        localAuthenticationOptions);
```
</details>

**Points to be Noted**:

On Android API 29 and below, specifying **DEVICE_CREDENTIAL** alone as the authentication level is not supported.
On Android API 28 and 29, specifying **STRONG** as the authentication level along with enabling device credential fallback is not supported.


#### Creating LocalAuthenticationOptions object for requiring Authentication while using SecureCredentialsManager

`LocalAuthenticationOptions` class exposes a Builder class to create an instance of it. Details about the methods are explained below:

- **setTitle(title: String): Builder** - Sets the title to be displayed in the Authentication Prompt.
- **setSubTitle(subtitle: String?): Builder** - Sets the subtitle of the Authentication Prompt.
- **setDescription(description: String?): Builder** - Sets the description for the Authentication Prompt.
- **setAuthenticationLevel(authenticationLevel: AuthenticationLevel): Builder** - Sets the authentication level, more on this can be found [here](#authenticationlevel-enum-values)
- **setDeviceCredentialFallback(enableDeviceCredentialFallback: Boolean): Builder** - Enables/disables device credential fallback.
- **setNegativeButtonText(negativeButtonText: String): Builder** - Sets the negative button text, used only when the device credential fallback is disabled (or) the authentication level is not set to `AuthenticationLevel.DEVICE_CREDENTIAL`.
- **build(): LocalAuthenticationOptions** - Constructs the LocalAuthenticationOptions instance.


#### AuthenticationLevel Enum Values

AuthenticationLevel is an enum that defines the different levels of authentication strength required for local authentication mechanisms.

**Enum Values**:
- **STRONG**: Any biometric (e.g., fingerprint, iris, or face) on the device that meets or exceeds the requirements for Class 3 (formerly Strong).
- **WEAK**: Any biometric (e.g., fingerprint, iris, or face) on the device that meets or exceeds the requirements for Class 2 (formerly Weak), as defined by the Android CDD.
- **DEVICE_CREDENTIAL**: The non-biometric credential used to secure the device (i.e., PIN, pattern, or password).


### Other Credentials

#### API credentials [EA]

> [!NOTE]
> This feature is currently available in [Early Access](https://auth0.com/docs/troubleshoot/product-lifecycle/product-release-stages#early-access). Please reach out to Auth0 support to get it enabled for your tenant.

When the user logs in, you can request an access token for a specific API by passing its API identifier as the [audience](#specify-audience) value. The access token in the resulting credentials can then be used to make authenticated requests to that API.

However, if you need an access token for a different API, you can exchange the [refresh token](https://auth0.com/docs/secure/tokens/refresh-tokens) for credentials containing an access token specific to this other API.

> [!IMPORTANT]
> Currently, only the Auth0 My Account API is supported. Support for other APIs will be added in the future.

```kotlin

credentialsManager.getApiCredentials(
    audience = "https://example.com/me", scope = " create:me:authentication_methods",
    callback = object : Callback<APICredentials, CredentialsManagerException> {
        override fun onSuccess(result: APICredentials) {
            print("Obtained API credentials: $result")
        }

        override fun onFailure(error: CredentialsManagerException) {
            print("Failed with: $error")
        }
    })

```

<details>
  <summary>Using Coroutines</summary>

```kotlin

  try {
          val result =   credentialsManager.awaitApiCredentials(
                audience = "https://example.com/me",
                scope = "create:me:authentication_methods"
            )
            print("Obtained API credentials: $result")
        } catch (error: CredentialsManagerException) {
            print("Failed with: $error")
        }

```

</details>

<details>
    <summary>Using Java</summary>

```java

credentialsManager.getApiCredentials("audience",
                "scope",
                0,
                new HashMap<>(),
                new HashMap<>(),
                new Callback<APICredentials, CredentialsManagerException>() {
                    @Override
                    public void onSuccess(APICredentials result) {
                        System.out.println(result);
                    }

                    @Override
                    public void onFailure(@NonNull CredentialsManagerException error) {
                        System.out.println(error);
                    }
                });

```
</details>

### Handling Credentials Manager exceptions

In the event that something happened while trying to save or retrieve the credentials, a `CredentialsManagerException` will be thrown. These are some of the expected failure scenarios:

- Invalid Credentials format or values. e.g. when it's missing the `access_token`, the `id_token` or the `expires_at` values.
- Tokens have expired but no `refresh_token` is available to perform a refresh credentials request.
- Device's Lock Screen security settings have changed (e.g. the PIN code was changed). Even when `hasCredentials` returns true, the encryption keys will be deemed invalid and until `saveCredentials` is called again it won't be possible to decrypt any previously existing content, since they keys used back then are not the same as the new ones.
- Device is not compatible with some of the algorithms required by the `SecureCredentialsManager` class. This is considered a catastrophic event and might happen when the OEM has modified the Android ROM removing some of the officially included algorithms. Nevertheless, it can be checked in the exception instance itself by calling `isDeviceIncompatible`. By doing so you can decide the fallback for storing the credentials, such as using the regular `CredentialsManager`.

You can access the `code` property of the `CredentialsManagerException` to understand why the operation with `CredentialsManager` has failed and the `message` property of the `CredentialsManagerException` would give you a description of the exception. 

Starting from version `3.0.0` you can even pass the exception to a `when` expression and handle the exception accordingly in your app's logic as shown in the below code snippet: 

```kotlin
when(credentialsManagerException) {
    CredentialsManagerException.NO_CREDENTIALS - > {
        // handle no credentials scenario
    }

    CredentialsManagerException.NO_REFRESH_TOKEN - > {
        // handle no refresh token scenario
    }

    CredentialsManagerException.STORE_FAILED - > {
        // handle store failed scenario
    }
    // ... similarly for other error codes
}
```

## Passkeys
User should have a custom domain configured and passkey grant-type enabled in the Auth0 dashboard to use passkeys.

To sign up a user with passkey

```kotlin
// Using Coroutines 
try {
    val challenge = authenticationApiClient.signupWithPasskey(
        "{user-data}",
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
 authenticationAPIClient.signupWithPasskey("{user-data}", "{realm}","{organization-id}")
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


## Bot Protection
If you are using the [Bot Protection](https://auth0.com/docs/anomaly-detection/bot-protection) feature and performing database login/signup via the Authentication API, you need to handle the `AuthenticationException#isVerificationRequired()` error. It indicates that the request was flagged as suspicious and an additional verification step is necessary to log the user in. That verification step is web-based, so you need to use Universal Login to complete it.

```kotlin
val email = "info@auth0.com"
val password = "a secret password"
val realm = "my-database-connection"

val authentication = AuthenticationAPIClient(account)
authentication.login(email, password, realm).validateClaims()
    .start(object: Callback<Credentials, AuthenticationException> {
        override fun onFailure(exception: AuthenticationException) {
            if (exception.isVerificationRequired()) {
                val params = mapOf("login_hint" to email) // So the user doesn't have to type it again
                WebAuthProvider.login(account)
                    .withConnection(realm)
                    .withParameters(params)
                    .start(LoginActivity.this, object: Callback<Credentials, AuthenticationException> {
                        // You might already have a Callback instance defined

                        override fun onFailure(exception: AuthenticationException) {
                            // Handle error
                        }

                        override fun onSuccess(credentials: Credentials) {
                            // Handle WebAuth success
                        }
                    })
            }
            // Handle other errors
        }

        override fun onSuccess(credentials: Credentials) {
            // Handle API success
        }
    })
```

<details>
  <summary>Using Java</summary>

```java
final String email = "info@auth0.com";
final String password = "a secret password";
final String realm = "my-database-connection";

AuthenticationAPIClient authentication = new AuthenticationAPIClient(account);
authentication.login(email, password, realm).validateClaims()
        .start(new Callback<Credentials, AuthenticationException>() {

            @Override
            public void onSuccess(@Nullable Credentials payload) {
                // Handle API success
            }

            @Override
            public void onFailure(@NonNull AuthenticationException error) {
                if (error.isVerificationRequired()){
                    Map<String, Object> params = new HashMap<>();
                    params.put("login_hint", email); // So the user doesn't have to type it again
                    WebAuthProvider.login(account)
                            .withConnection(realm)
                            .withParameters(params)
                            .start(LoginActivity.this, new AuthCallback() {
                                // You might already have an AuthCallback instance defined

                                @Override
                                public void onFailure(@NonNull Dialog dialog) {
                                    // Error dialog available
                                }

                                @Override
                                public void onFailure(AuthenticationException exception) {
                                    // Error
                                }

                                @Override
                                public void onSuccess(@NonNull Credentials credentials) {
                                    // Handle WebAuth success
                                }
                            });
                }
            }
        });
```
</details>

In the case of signup, you can add [an additional parameter](https://auth0.com/docs/universal-login/new-experience#signup) to make the user land directly on the signup page:

```kotlin
val params = mapOf(
    "login_hint" to email, 
    "screen_hint" to "signup"
)
```

<details>
  <summary>Using Java</summary>

```java
params.put("login_hint", email);
params.put("screen_hint", "signup");
```
</details>

## Management API

The client provides a few methods to interact with the [Users Management API](https://auth0.com/docs/api/management/v2/#!/Users).

Create a new instance passing the account and an access token with the Management API audience and the right scope:

```kotlin
val users = UsersAPIClient(account, "api access token")
```

<details>
  <summary>Using Java</summary>

```java
Auth0 account = Auth0.getInstance("client id", "domain");
UsersAPIClient users = new UsersAPIClient(account, "api token");
```
</details>

### Link users

```kotlin
users
    .link("primary user id", "secondary user token")
    .start(object: Callback<List<UserIdentity>, ManagementException> {
    
        override fun onFailure(exception: ManagementException) { }
    
        override fun onSuccess(identities: List<UserIdentity>) { }
    })
```

<details>
  <summary>Using coroutines</summary>

```kotlin
try {
    val identities = users
        .link("primary user id", "secondary user token")
        .await()
    println(identities)
} catch (e: ManagementException) {
    e.printStacktrace()
}
```
</details>

<details>
  <summary>Using Java</summary>

```java
users
    .link("primary user id", "secondary user token")
    .start(new Callback<List<UserIdentity>, ManagementException>() {
        @Override
        public void onSuccess(List<UserIdentity> payload) {
            //Got the updated identities! Accounts linked.
        }

        @Override
        public void onFailure(@NonNull ManagementException error) {
            //Error!
        }
    });
```
</details>

### Unlink users

```kotlin
users
    .unlink("primary user id", "secondary user id", "secondary provider")
    .start(object: Callback<List<UserIdentity>, ManagementException> {
    
        override fun onFailure(exception: ManagementException) { }
    
        override fun onSuccess(identities: List<UserIdentity>) { }
    })
```

<details>
  <summary>Using coroutines</summary>

```kotlin
try {
    val identities = users
        .unlink("primary user id", "secondary user id", "secondary provider")
        .await()
    println(identities)
} catch (e: ManagementException) {
    e.printStacktrace()
}
```
</details>

<details>
  <summary>Using Java</summary>

```java
users
    .unlink("primary user id", "secondary user id", "secondary provider")
    .start(new Callback<List<UserIdentity>, ManagementException>() {
        @Override
        public void onSuccess(List<UserIdentity> payload) {
            //Got the updated identities! Accounts linked.
        }

        @Override
        public void onFailure(@NonNull ManagementException error) {
            //Error!
        }
    });
```
</details>

### Get User Profile

```kotlin
users
    .getProfile("user id")
    .start(object: Callback<UserProfile, ManagementException> {
    
        override fun onFailure(exception: ManagementException) { }
    
        override fun onSuccess(identities: UserProfile) { }
    })
```

<details>
  <summary>Using coroutines</summary>

```kotlin
try {
    val user = users
        .getProfile("user id")
        .await()
    println(user)
} catch (e: ManagementException) {
    e.printStacktrace()
}
```
</details>

<details>
  <summary>Using Java</summary>

```java
users
    .getProfile("user id")
    .start(new Callback<UserProfile, ManagementException>() {
        @Override
        public void onSuccess(@Nullable UserProfile payload) {
            //Profile received
        }

        @Override
        public void onFailure(@NonNull ManagementException error) {
            //Error!
        }
    });
```
</details>

### Update User Metadata

```kotlin
val metadata = mapOf(
    "name" to listOf("My", "Name", "Is"),
    "phoneNumber" to "1234567890"
)

users
    .updateMetadata("user id", metadata)
    .start(object: Callback<UserProfile, ManagementException> {
    
        override fun onFailure(exception: ManagementException) { }
    
        override fun onSuccess(identities: UserProfile) { }
    })
```

<details>
  <summary>Using coroutines</summary>

```kotlin
val metadata = mapOf(
    "name" to listOf("My", "Name", "Is"),
    "phoneNumber" to "1234567890"
)

try {
    val user = users
        .updateMetadata("user id", metadata)
        .await()
    println(user)
} catch (e: ManagementException) {
    e.printStacktrace()
}
```
</details>

<details>
  <summary>Using Java</summary>

```java
Map<String, Object> metadata = new HashMap<>();
metadata.put("name", Arrays.asList("My", "Name", "Is"));
metadata.put("phoneNumber", "1234567890");

users
    .updateMetadata("user id", metadata)
    .start(new Callback<UserProfile, ManagementException>() {
        @Override
        public void onSuccess(@Nullable UserProfile payload) {
            //User Metadata updated
        }

        @Override
        public void onFailure(@NonNull ManagementException error) {
            //Error!
        }
    });
```
</details>

> In all the cases, the `user ID` parameter is the unique identifier of the auth0 account instance. i.e. in `google-oauth2|123456789` it would be the part after the '|' pipe: `123456789`.

## Token Validation
The ID token received as part of the authentication flow is should be verified following the [OpenID Connect specification](https://openid.net/specs/openid-connect-core-1_0.html).

If you are a user of Auth0 Private Cloud with ["Custom Domains"](https://auth0.com/docs/custom-domains) still on the [legacy behavior](https://auth0.com/docs/private-cloud/private-cloud-migrations/migrate-private-cloud-custom-domains#background), you need to override the expected issuer to match your Auth0 domain before starting the authentication.

The validation is done automatically for Web Authentication
```kotlin
val account = Auth0.getInstance("{YOUR_CLIENT_ID}", "{YOUR_CUSTOM_DOMAIN}")

WebAuthProvider.login(account)
    .withIdTokenVerificationIssuer("https://{YOUR_AUTH0_DOMAIN}/")
    .start(this, callback)
```

For Authentication Client, the method `validateClaims()` has to be called to enable it.

```kotlin
val auth0 = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN")
val client = AuthenticationAPIClient(auth0)
client
     .login("{username or email}", "{password}", "{database connection name}")
     .validateClaims()
     .withIdTokenVerificationIssuer("https://{YOUR_AUTH0_DOMAIN}/")
     .start(object : Callback<Credentials, AuthenticationException> {
         override fun onSuccess(result: Credentials) { }
         override fun onFailure(error: AuthenticationException) { }
    })
```

<details>
  <summary>Using coroutines</summary>

```kotlin
val auth0 = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN")
val client = AuthenticationAPIClient(auth0)

try {
    val credentials = client
        .login("{username or email}", "{password}", "{database connection name}")
        .validateClaims()
        .withIdTokenVerificationIssuer("https://{YOUR_AUTH0_DOMAIN}/")
        .await()
    println(credentials)
} catch (e: AuthenticationException) {
    e.printStacktrace()
}
```
</details>

<details>
  <summary>Using Java</summary>

```java
Auth0 auth0 = Auth0.getInstance("client id", "domain");
AuthenticationAPIClient client = new AuthenticationAPIClient(account);
client
   .login("{username or email}", "{password}", "{database connection name}")
   .validateClaims()
   .withIdTokenVerificationIssuer("https://{YOUR_AUTH0_DOMAIN}/")
   .start(new Callback<Credentials, AuthenticationException>() {
       @Override
       public void onSuccess(@Nullable Credentials payload) {
           //Logged in!
       }

       @Override
       public void onFailure(@NonNull AuthenticationException error) {
           //Error!
       }
   });
```
</details>

## Organizations

[Organizations](https://auth0.com/docs/organizations) is a set of features that provide better support for developers who build and maintain SaaS and Business-to-Business (B2B) applications.
Note that Organizations is currently only available to customers on our Enterprise and Startup subscription plans.

### Log in to an organization

```kotlin
WebAuthProvider.login(account)
    .withOrganization(organizationIdOrName)
    .start(this, callback)
```

### Accept user invitations

Users can be invited to your organization via a link. Tapping on the invitation link should open your app. Since invitations links are `https` only, is recommended that your app supports [Android App Links](https://developer.android.com/training/app-links). In [Enable Android App Links Support](https://auth0.com/docs/applications/enable-android-app-links-support), you will find how to make the Auth0 server publish the Digital Asset Links file required by your application.

When your app gets opened by an invitation link, grab the invitation URL from the received Intent (e.g. in `onCreate` or `onNewIntent`) and pass it to `.withInvitationUrl()`:

```kotlin
getIntent()?.data?.let {
    WebAuthProvider.login(account)
        .withInvitationUrl(invitationUrl)
        .start(this, callback)
}
```

<details>
  <summary>Using Java</summary>

```java
if (getIntent() != null && getIntent().getData() != null) {
    WebAuthProvider.login(account)
        .withInvitationUrl(getIntent().getData())
        .start(this, callback);
}
```
</details>

If the URL doesn't contain the expected values, an error will be raised through the provided callback.

## Networking client customization

This library provides the ability to customize the behavior of the networking client for common configurations, as well the ability to define and use your own networking client implementation.

The Auth0 class can be configured with a `NetworkingClient`, which will be used when making requests. You can configure the default client with custom timeout values, any headers that should be sent on all requests, and whether to log request/response info (for non-production debugging purposes only). For more advanced configuration, you can provide your own implementation of `NetworkingClient`.

### Timeout configuration

```kotlin
val netClient = DefaultClient(
    connectTimeout = 30,
    readTimeout = 30
)

val account = Auth0.getInstance("{YOUR_CLIENT_ID}", "{YOUR_DOMAIN}")
account.networkingClient = netClient
```

<details>
  <summary>Using Java</summary>

```java
DefaultClient netClient = new DefaultClient(30, 30);
Auth0 account = Auth0.getInstance("client id", "domain");
account.setNetworkingClient(netClient);
```
</details>

### Logging configuration

```kotlin
val netClient = DefaultClient(
    enableLogging = true
)

val account = Auth0.getInstance("{YOUR_CLIENT_ID}", "{YOUR_DOMAIN}")
account.networkingClient = netClient
```

<details>
  <summary>Using Java</summary>

```java
import java.util.HashMap;

DefaultClient netClient = new DefaultClient(
        10, 10, new HashMap<>() ,true
);
Auth0 account = Auth0.getInstance("client id", "domain");
account.setNetworkingClient(netClient);
```
</details>

### Set additional headers for all requests

```kotlin
val netClient = DefaultClient(
    defaultHeaders = mapOf("{HEADER-NAME}" to "{HEADER-VALUE}")
)

val account = Auth0.getInstance("{YOUR_CLIENT_ID}", "{YOUR_DOMAIN}")
account.networkingClient = netClient
```

<details>
  <summary>Using Java</summary>

```java
Map<String, String> defaultHeaders = new HashMap<>();
defaultHeaders.put("{HEADER-NAME}", "{HEADER-VALUE}");

DefaultClient netClient = new DefaultClient(
        10,10 , defaultHeaders
);
Auth0 account = Auth0.getInstance("client id", "domain");
account.setNetworkingClient(netClient);
```
</details>

### Advanced configuration

For more advanced configuration of the networking client, you can provide a custom implementation of `NetworkingClient`. This may be useful when you wish to reuse your own networking client, configure a proxy, etc.

```kotlin
class CustomNetClient : NetworkingClient {
    override fun load(url: String, options: RequestOptions): ServerResponse {
         // Create and execute the request to the specified URL with the given options
         val response = // ...

         // Return a ServerResponse from the received response data
         return ServerResponse(responseCode, responseBody, responseHeaders)
    }
}

val account = Auth0.getInstance("{YOUR_CLIENT_ID}", "{YOUR_DOMAIN}")
account.networkingClient = CustomNetClient()
```

<details>
  <summary>Using Java</summary>

```java
class CustomNetClient extends NetworkingClient {
   @Override
   public ServerResponse load(String url) {
      // Create and execute the request to the specified URL with the given options
      ServerResponse response = // ...

      // Return a ServerResponse from the received response data
      return new ServerResponse(responseCode, responseBody, responseHeaders);
   }  
};

Auth0 account = Auth0.getInstance("client id", "domain");
account.networkingClient = new CustomNetClient();
```
</details>

## Unit testing with JUnit 4 or JUnit 5

### Handling `Method getMainLooper in android.os.Looper not mocked` errors
Your unit tests might break with `Caused by: java.lang.RuntimeException: Method getMainLooper in android.os.Looper not mocked` due to the Looper being used internally by this library. There are two options to handle this:
1. Use Robolectric Shadows - see this [test](https://github.com/auth0/Auth0.Android/blob/main/auth0/src/test/java/com/auth0/android/authentication/AuthenticationAPIClientTest.kt#L44-L45) for an example
2. If your project does not use Robolectric and uses JUnit 4, you can create a `Rule` that you can add to your unit test:
```kotlin
import com.auth0.android.request.internal.CommonThreadSwitcher
import com.auth0.android.request.internal.ThreadSwitcher
import org.junit.rules.TestWatcher
import org.junit.runner.Description

public class CommonThreadSwitcherRule : TestWatcher() {
    override fun starting(description: Description) {
        super.starting(description)
        CommonThreadSwitcher.getInstance().setDelegate(object : ThreadSwitcher {
            override fun mainThread(runnable: Runnable) {
                runnable.run()
            }

            override fun backgroundThread(runnable: Runnable) {
                runnable.run()
            }
        })
    }

    override fun finished(description: Description) {
        super.finished(description)
        CommonThreadSwitcher.getInstance().setDelegate(null)
    }
}
```
See this [test](https://github.com/auth0/Auth0.Android/blob/main/auth0/src/test/java/com/auth0/android/request/internal/CommonThreadSwitcherDelegateTest.kt) for an example of it being used.

3. If you use JUnit 5 then you can create an `Extension` similar to the previous `Rule` for JUnit 4:
```kotlin
import com.auth0.android.request.internal.CommonThreadSwitcher
import com.auth0.android.request.internal.ThreadSwitcher
import org.junit.jupiter.api.extension.AfterEachCallback
import org.junit.jupiter.api.extension.BeforeEachCallback
import org.junit.jupiter.api.extension.ExtensionContext

class CommonThreadSwitcherExtension : BeforeEachCallback, AfterEachCallback {

    override fun beforeEach(context: ExtensionContext?) {
        CommonThreadSwitcher.getInstance().setDelegate(object : ThreadSwitcher {
            override fun mainThread(runnable: Runnable) {
                runnable.run()
            }

            override fun backgroundThread(runnable: Runnable) {
                runnable.run()
            }
        })
    }

    override fun afterEach(context: ExtensionContext?) {
        CommonThreadSwitcher.getInstance().setDelegate(null)
    }

}
```

### Handling SSL errors
You might encounter errors similar to `PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target`, which means that you need to set up your unit tests in a way that ignores or trusts all SSL certificates. In that case, you may have to implement your own `NetworkingClient` so that you can supply your own `SSLSocketFactory` and `X509TrustManager`, and use that in creating your `Auth0` object. See the [`DefaultClient`](https://github.com/auth0/Auth0.Android/blob/main/auth0/src/main/java/com/auth0/android/request/DefaultClient.kt) class for an idea on how to extend `NetworkingClient`.

## Proguard
The rules should be applied automatically if your application is using `minifyEnabled = true`. If you want to include them manually check the [proguard directory](proguard).
By default you should at least use the following files:
* `proguard-okio.pro`
* `proguard-gson.pro`
* `proguard-jetpack.pro`
