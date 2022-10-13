# Examples using Auth0.Android

- [Authenticate with any Auth0 connection](#authenticate-with-any-auth0-connection)
- [Specify audience](#specify-audience)
- [Specify scope](#specify-scope)
- [Specify Connection scope](#specify-connection-scope)
- [Customize the Custom Tabs UI](#customize-the-custom-tabs-ui)
- [Changing the Return To URL scheme](#changing-the-return-to-url-scheme)
- [Authentication API](#authentication-api)
  - [Login with database connection](#login-with-database-connection)
  - [Login using MFA with One Time Password code](#login-using-mfa-with-one-time-password-code)
  - [Passwordless Login](#passwordless-login)
  - [Sign Up with a database connection](#sign-up-with-a-database-connection)
  - [Get user information](#get-user-information)
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
Auth0 account = new Auth0("client id", "domain");
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
val account = Auth0("{YOUR_CLIENT_ID}", "{YOUR_CUSTOM_DOMAIN}")

WebAuthProvider.login(account)
    .withIdTokenVerificationIssuer("https://{YOUR_AUTH0_DOMAIN}/")
    .start(this, callback)
```

For Authentication Client, the method `validateClaims()` has to be called to enable it.

```kotlin
val auth0 = Auth0("YOUR_CLIENT_ID", "YOUR_DOMAIN")
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
val auth0 = Auth0("YOUR_CLIENT_ID", "YOUR_DOMAIN")
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
Auth0 auth0 = new Auth0("client id", "domain");
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
    .withOrganization(organizationId)
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

val account = Auth0("{YOUR_CLIENT_ID}", "{YOUR_DOMAIN}")
account.networkingClient = netClient
```

<details>
  <summary>Using Java</summary>

```java
DefaultClient netClient = new DefaultClient(
   connectTimeout = 30,
   readTimeout = 30
);
Auth0 account = new Auth0("client id", "domain");
account.networkingClient = netClient;
```
</details>

### Logging configuration

```kotlin
val netClient = DefaultClient(
    enableLogging = true
)

val account = Auth0("{YOUR_CLIENT_ID}", "{YOUR_DOMAIN}")
account.networkingClient = netClient
```

<details>
  <summary>Using Java</summary>

```java
DefaultClient netClient = new DefaultClient(
    enableLogging = true
);
Auth0 account = new Auth0("client id", "domain");
account.networkingClient = netClient;
```
</details>

### Set additional headers for all requests

```kotlin
val netClient = DefaultClient(
    defaultHeaders = mapOf("{HEADER-NAME}" to "{HEADER-VALUE}")
)

val account = Auth0("{YOUR_CLIENT_ID}", "{YOUR_DOMAIN}")
account.networkingClient = netClient
```

<details>
  <summary>Using Java</summary>

```java
Map<String, String> defaultHeaders = new HashMap<>();
defaultHeaders.put("{HEADER-NAME}", "{HEADER-VALUE}");

DefaultClient netClient = new DefaultClient(
    defaultHeaders = defaultHeaders
);
Auth0 account = new Auth0("client id", "domain");
account.networkingClient = netClient;
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

val account = Auth0("{YOUR_CLIENT_ID}", "{YOUR_DOMAIN}")
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
      return ServerResponse(responseCode, responseBody, responseHeaders)
   }  
};

Auth0 account = new Auth0("client id", "domain");
account.networkingClient = new CustomNetClient();
```
</details>