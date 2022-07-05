# Auth0.Android

[![CircleCI](https://img.shields.io/circleci/project/github/auth0/Auth0.Android.svg?style=flat-square)](https://circleci.com/gh/auth0/Auth0.Android/tree/master)
[![Coverage Status](https://img.shields.io/codecov/c/github/auth0/Auth0.Android/master.svg?style=flat-square)](https://codecov.io/github/auth0/Auth0.Android)
[![License](https://img.shields.io/:license-mit-blue.svg?style=flat-square)](https://doge.mit-license.org/)
[![Maven Central](https://img.shields.io/maven-central/v/com.auth0.android/auth0.svg?style=flat-square)](https://search.maven.org/artifact/com.auth0.android/auth0)
[![javadoc](https://javadoc.io/badge2/com.auth0.android/auth0/javadoc.svg)](https://javadoc.io/doc/com.auth0.android/auth0)

Easily integrate Auth0 into Android apps. Add **login** and **logout**, store **credentials** securely, and access **user information**.

## Table of contents

- [Requirements](#requirements)
- [Installation](#installation)
   + [Permissions](#permissions)
- [Getting Started](#getting-started)
   * [Authentication with Universal Login](#authentication-with-universal-login)
   * [Clearing the session](#clearing-the-session)
- [Next steps](#next-steps)
   * [Authentication API](#authentication-api)
   * [Management API](#management-api)
   * [Token Validation](#token-validation)
   * [Organizations](#organizations)
- [Credentials Manager](#credentials-manager)
   * [Basic](#basic)
   * [Encryption enforced](#encryption-enforced)
- [Networking client customization](#networking-client-customization)
- [FAQ](#faq)
- [Proguard](#proguard)
- [What is Auth0?](#what-is-auth0)
- [Issue Reporting](#issue-reporting)
- [License](#license)

## Requirements

Android API version 21 or later and Java 8+.

Here’s what you need in `build.gradle` to target Java 8 byte code for Android and Kotlin plugins respectively.

```groovy
android {
    compileOptions {
        sourceCompatibility JavaVersion.VERSION_1_8
        targetCompatibility JavaVersion.VERSION_1_8
    }

    kotlinOptions {
        jvmTarget = '1.8'
    }
}
```

## Installation

To install Auth0.Android with [Gradle](https://gradle.org/), simply add the following line to your `build.gradle` file:

```gradle
dependencies {
    implementation 'com.auth0.android:auth0:2.8.0'
}
```

#### Permissions

Open your app's `AndroidManifest.xml` file and add the following permission.

```xml
<uses-permission android:name="android.permission.INTERNET" />
```

## Getting Started

First, create an instance of `Auth0` with your Application information

```kotlin
val account = Auth0("{YOUR_CLIENT_ID}", "{YOUR_DOMAIN}")
```

<details>
  <summary>Using Java</summary>

```java
Auth0 account = new Auth0("{YOUR_CLIENT_ID}", "{YOUR_DOMAIN}");
```
</details>

<details>
  <summary>Configure using Android Context</summary>

Alternatively, you can save your Application information in the `strings.xml` file using the following names:

```xml
<resources>
    <string name="com_auth0_client_id">YOUR_CLIENT_ID</string>
    <string name="com_auth0_domain">YOUR_DOMAIN</string>
</resources>
```

You can then create a new Auth0 instance by passing an Android Context:

```kotlin
val account = Auth0(context)
```
</details>

### Authentication with Universal Login

First go to the [Auth0 Dashboard](https://manage.auth0.com/#/applications) and go to your application's settings. Make sure you have in **Allowed Callback URLs** a URL with the following format:

```
https://{YOUR_AUTH0_DOMAIN}/android/{YOUR_APP_PACKAGE_NAME}/callback
```

> ⚠️ Make sure that the [application type](https://auth0.com/docs/configure/applications) of the Auth0 application is **Native**.

Replace `{YOUR_APP_PACKAGE_NAME}` with your actual application's package name, available in your `app/build.gradle` file as the `applicationId` value.

Next, define the Manifest Placeholders for the Auth0 Domain and Scheme which are going to be used internally by the library to register an **intent-filter**. Go to your application's `build.gradle` file and add the `manifestPlaceholders` line as shown below:

```groovy
apply plugin: 'com.android.application'

android {
    compileSdkVersion 30
    defaultConfig {
        applicationId "com.auth0.samples"
        minSdkVersion 21
        targetSdkVersion 30
        //...

        //---> Add the next line
        manifestPlaceholders = [auth0Domain: "@string/com_auth0_domain", auth0Scheme: "https"]
        //<---
    }
    //...
}
```

It's a good practice to define reusable resources like `@string/com_auth0_domain`, but you can also hard-code the value.

> The scheme value can be either `https` or a custom one. Read [this section](#a-note-about-app-deep-linking) to learn more.

Declare the callback instance that will receive the authentication result and authenticate by showing the **Auth0 Universal Login**:

```kotlin
val callback = object : Callback<Credentials, AuthenticationException> {
    override fun onFailure(exception: AuthenticationException) {
        // Failure! Check the exception for details
    }

    override fun onSuccess(credentials: Credentials) {
        // Success! Access token and ID token are presents
    }
}

WebAuthProvider.login(account)
    .start(this, callback)
```

<details>
  <summary>Using coroutines</summary>

```kotlin
try {
    val credentials = WebAuthProvider.login(account)
        .await(requireContext())
    println(credentials)    
} catch(e: AuthenticationException) {
    e.printStacktrace()
}
```
</details>

<details>
  <summary>Using Java</summary>

```java
Callback<Credentials, AuthenticationException> callback = new Callback<Credentials, AuthenticationException>() {
    @Override
    public void onFailure(@NonNull AuthenticationException exception) {
        //failed with an exception
    }

    @Override
    public void onSuccess(@Nullable Credentials credentials) {
        //succeeded!
    }
};

WebAuthProvider.login(account)
    .start(this, callback);
```
</details>

The callback will get invoked when the user returns to your application. There are a few scenarios where this may fail:

* When the device cannot open the URL because it doesn't have any compatible browser application installed. You can check this scenario with `error.isBrowserAppNotAvailable`.
* When the user manually closed the browser (e.g. pressing the back key). You can check this scenario with `error.isAuthenticationCanceled`.
* When there was a server error. Check the received exception for details.

> If the `redirect` URL is not found in the **Allowed Callback URLs** of your Auth0 Application, the server will not make the redirection and the browser will remain open.

##### A note about App Deep Linking:

If you followed the configuration steps documented here, you may have noticed the default scheme used for the Callback URI is `https`. This works best for Android API 23 or newer if you're using [Android App Links](https://auth0.com/docs/applications/enable-android-app-links), but in previous Android versions this _may_ show the intent chooser dialog prompting the user to choose either your application or the browser. You can change this behaviour by using a custom unique scheme so that the OS opens directly the link with your app.

1. Update the `auth0Scheme` Manifest Placeholder on the `app/build.gradle` file or update the intent-filter declaration in the `AndroidManifest.xml` to use the new scheme.
2. Update the **Allowed Callback URLs** in your [Auth0 Dashboard](https://manage.auth0.com/#/applications) application's settings.
3. Call `withScheme()` in the `WebAuthProvider` builder passing the custom scheme you want to use.

```kotlin
WebAuthProvider.login(account)
    .withScheme("myapp")
    .start(this, callback)
```

> Note that the schemes [can only have lowercase letters](https://developer.android.com/guide/topics/manifest/data-element).

#### Authenticate with any Auth0 connection

The connection must first be enabled in the Auth0 dashboard for this Auth0 application.

```kotlin
WebAuthProvider.login(account)
    .withConnection("twitter")
    .start(this, callback)
```

#### Specify audience

```kotlin
WebAuthProvider.login(account)
    .withAudience("https://{YOUR_AUTH0_DOMAIN}/api/v2/")
    .start(this, callback)
```

The sample above requests tokens with the audience required to call the [Management API](https://auth0.com/docs/api/management/v2) endpoints.

> Replace `{YOUR_AUTH0_DOMAIN}` with your actual Auth0 domain (i.e. `mytenant.auth0.com`). If you've set up the tenant to use "Custom Domains", use that value here.

#### Specify scope

```kotlin
WebAuthProvider.login(account)
    .withScope("openid profile email read:users")
    .start(this, callback)
```

> The default scope used is `openid profile email`. Regardless of the scopes passed here, the `openid` scope is always enforced.

#### Specify Connection scope

```kotlin
WebAuthProvider.login(account)
    .withConnectionScope("email", "profile", "calendar:read")
    .start(this, callback)
```

#### Customize the Custom Tabs UI

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


### Clearing the session

To log the user out and clear the SSO cookies that the Auth0 Server keeps attached to your browser app, you need to call the [logout endpoint](https://auth0.com/docs/api/authentication?#logout). This can be done in a similar fashion to how you authenticated before: using the `WebAuthProvider` class.

Make sure to [revisit this section](#authentication-with-universal-login) to configure the Manifest Placeholders if you still cannot authenticate successfully. The values set there are used to generate the URL that the server will redirect the user back to after a successful log out.

In order for this redirection to happen, you must copy the **Allowed Callback URLs** value you added for authentication into the **Allowed Logout URLs** field in your [application settings](https://manage.auth0.com/#/applications). Both fields should have an URL with the following format:

```
https://{YOUR_AUTH0_DOMAIN}/android/{YOUR_APP_PACKAGE_NAME}/callback
```

Remember to replace `{YOUR_APP_PACKAGE_NAME}` with your actual application's package name, available in your `app/build.gradle` file as the `applicationId` value.

Initialize the provider, this time calling the static method `logout`.

```kotlin
//Declare the callback that will receive the result
val logoutCallback = object: Callback<Void?, AuthenticationException> {
    override fun onFailure(exception: AuthenticationException) {
        // Failure! Check the exception for details
    }

    override fun onSuccess(result: Void?) {
        // Success! The browser session was cleared
    }
}

//Configure and launch the log out
WebAuthProvider.logout(account)
        .start(this, logoutCallback)
```

<details>
  <summary>Using coroutines</summary>

```kotlin
try {
    WebAuthProvider.logout(account)
        .await(requireContext())
    println("Logged out")
} catch(e: AuthenticationException) {
    e.printStacktrace()
}
```
</details>

<details>
  <summary>Using Java</summary>

```java
//Declare the callback that will receive the result
Callback<Void, AuthenticationException> logoutCallback = new Callback<Void, AuthenticationException>() {
    @Override
    public void onFailure(@NonNull Auth0Exception exception) {
        //failed with an exception
    }

    @Override
    public void onSuccess(@Nullable Void payload) {
        //succeeded!
    }
};

//Configure and launch the log out
WebAuthProvider.logout(account)
    .start(MainActivity.this, logoutCallback);
```
</details>

The callback will get invoked when the user returns to your application. There are a few scenarios where this may fail:

* When the device cannot open the URL because it doesn't have any compatible browser application installed. You can check this scenario with `error.isBrowserAppNotAvailable`.
* When the user manually closed the browser (e.g. pressing the back key). You can check this scenario with `error.isAuthenticationCanceled`.

If the `returnTo` URL is not found in the **Allowed Logout URLs** of your Auth0 Application, the server will not make the redirection and the browser will remain open.

#### Changing the Return To URL scheme
This configuration will probably match what you've done for the [authentication setup](#a-note-about-app-deep-linking).

```kotlin
WebAuthProvider.logout(account)
    .withScheme("myapp")
    .start(this, logoutCallback)
```

#### Customize the Custom Tabs UI

If the device where the app is running has a Custom Tabs compatible Browser, a Custom Tab will be preferred for the logout flow. You can customize the Page Title visibility, the Toolbar color, and the supported Browser applications by using the `CustomTabsOptions` class.

```kotlin
val ctOptions = CustomTabsOptions.newBuilder()
    .withToolbarColor(R.color.ct_toolbar_color)
    .showTitle(true)
    .build()
 
WebAuthProvider.logout(account)
    .withCustomTabsOptions(ctOptions)
    .start(this, logoutCallback)
```

<details>
  <summary>Using Java</summary>

```java
CustomTabsOptions options = CustomTabsOptions.newBuilder()
    .withToolbarColor(R.color.ct_toolbar_color)
    .showTitle(true)
    .build();

WebAuthProvider.logout(account)
    .withCustomTabsOptions(options)
    .start(MainActivity.this, logoutCallback);
```
</details>

#### Learning resources

Check out the [Android QuickStart Guide](https://auth0.com/docs/quickstart/native/android) to find out more about the Auth0.Android toolkit and explore our tutorials and sample projects.

## Next steps

### Authentication API

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

#### Login with database connection

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

#### Login using MFA with One Time Password code

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

#### Passwordless Login

This feature requires your Application to have the *Passwordless OTP* enabled. See [this article](https://auth0.com/docs/clients/client-grant-types) to learn how to enable it.

Passwordless is a 2 step flow:

##### Step 1: Request the code

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

##### Step 2: Input the code

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

#### Sign Up with a database connection

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

#### Get user information

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


#### Bot Protection
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

Check out how to set up Universal Login in the [Authentication with Universal Login](#authentication-with-universal-login) section.

### Management API

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

#### Link users

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

#### Unlink users

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

#### Get User Profile

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

#### Update User Metadata

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

### Token Validation
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

### Organizations

[Organizations](https://auth0.com/docs/organizations) is a set of features that provide better support for developers who build and maintain SaaS and Business-to-Business (B2B) applications.

Using Organizations, you can:

- Represent teams, business customers, partner companies, or any logical grouping of users that should have different ways of accessing your applications, as organizations.
- Manage their membership in a variety of ways, including user invitation.
- Configure branded, federated login flows for each organization.
- Implement role-based access control, such that users can have different roles when authenticating in the context of different organizations.
- Build administration capabilities into your products, using Organizations APIs, so that those businesses can manage their own organizations.

Note that Organizations is currently only available to customers on our Enterprise and Startup subscription plans.

#### Log in to an organization

```kotlin
WebAuthProvider.login(account)
    .withOrganization(organizationId)
    .start(this, callback)
```

#### Accept user invitations

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

## Credentials Manager

This library ships with two additional classes that help you manage the Credentials received during authentication.

### Basic

The basic version supports asking for `Credentials` existence, storing them and getting them back. If the credentials have expired and a refresh_token was saved, they are automatically refreshed. The class is called `CredentialsManager`.

#### Usage
1. **Instantiate the manager:**
   You'll need an `AuthenticationAPIClient` instance to renew the credentials when they expire and a `Storage` object. We provide a `SharedPreferencesStorage` class that makes use of `SharedPreferences` to create a file in the application's directory with **Context.MODE_PRIVATE** mode.

```kotlin
val authentication = AuthenticationAPIClient(account)
val storage = SharedPreferencesStorage(this)
val manager = CredentialsManager(authentication, storage)
```

<details>
  <summary>Using Java</summary>

```java
AuthenticationAPIClient authentication = new AuthenticationAPIClient(account);
Storage storage = new SharedPreferencesStorage(this);
CredentialsManager manager = new CredentialsManager(authentication, storage);
```
</details>

2. **Save credentials:**
   The credentials to save **must have** `expires_at` and at least an `access_token` or `id_token` value. If one of the values is missing when trying to set the credentials, the method will throw a `CredentialsManagerException`. If you want the manager to successfully renew the credentials when expired you must also request the `offline_access` scope when logging in in order to receive a `refresh_token` value along with the rest of the tokens. i.e. Logging in with a database connection and saving the credentials:

```kotlin
authentication
    .login("info@auth0.com", "a secret password", "my-database-connection")
    .setScope("openid email profile offline_access")
    .start(object : Callback<Credentials, AuthenticationException> {
        override fun onFailure(exception: AuthenticationException) {
            // Error
        }

        override fun onSuccess(credentials: Credentials) {
            //Save the credentials
            manager.saveCredentials(credentials)
        }
    })
``` 

<details>
  <summary>Using coroutines</summary>

```kotlin
try {
    val credentials = authentication
        .login("info@auth0.com", "a secret password", "my-database-connection")
        .setScope("openid email profile offline_access")
        .await()
    manager.saveCredentials(credentials)
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
    .setScope("openid email profile offline_access")
    .start(new BaseCallback<Credentials, AuthenticationException>() {
        @Override
        public void onSuccess(Credentials payload) {
            //Save the credentials
            manager.saveCredentials(credentials);
        }

        @Override
        public void onFailure(AuthenticationException error) {
            //Error!
        }
    });
```
</details>

**Note:** This method has been made thread-safe after version 2.8.0.

3. **Check credentials existence:**
   There are cases were you just want to check if a user session is still valid (i.e. to know if you should present the login screen or the main screen). For convenience, we include a `hasValidCredentials` method that can let you know in advance if a non-expired token is available without making an additional network call. The same rules of the `getCredentials` method apply:

```kotlin
val authenticated = manager.hasValidCredentials()
```

<details>
  <summary>Using Java</summary>

```java
boolean authenticated = manager.hasValidCredentials();
```
</details>

4. **Retrieve credentials:**
   Existing credentials will be returned if they are still valid, otherwise the `refresh_token` will be used to attempt to renew them. If the `expires_at` or both the `access_token` and `id_token` values are missing, the method will throw a `CredentialsManagerException`. The same will happen if the credentials have expired and there's no `refresh_token` available.

```kotlin
manager.getCredentials(object : Callback<Credentials, CredentialsManagerException> {
    override fun onFailure(exception: CredentialsManagerException) {
        // Error
    }

    override fun onSuccess(credentials: Credentials) {
        // Use the credentials
    }
})
``` 

<details>
  <summary>Using coroutines</summary>

```kotlin
try {
    val credentials = manager.awaitCredentials()
    println(credentials)
} catch (e: CredentialsManagerException) {
    e.printStacktrace()
}
```
</details>

<details>
  <summary>Using Java</summary>

```java
manager.getCredentials(new BaseCallback<Credentials, CredentialsManagerException>() {
    @Override
    public void onSuccess(Credentials credentials){
        //Use the Credentials
    }

    @Override
    public void onFailure(CredentialsManagerException error){
        //Error!
    }
});
```
</details>

**Note:** In the scenario where the stored credentials have expired and a `refresh_token` is available, the newly obtained tokens are automatically saved for you by the Credentials Manager. This method has been made thread-safe after version 2.8.0.

5. **Clear credentials:**
   When you want to log the user out:

```kotlin
manager.clearCredentials()
```

### Encryption enforced

This version adds encryption to the data storage. Additionally, in those devices where a Secure Lock Screen has been configured it can require the user to authenticate before letting them obtain the stored credentials. The class is called `SecureCredentialsManager`.

#### Usage
The usage is similar to the previous version, with the slight difference that the manager now requires a valid android `Context` as shown below:

```kotlin
val authentication = AuthenticationAPIClient(account)
val storage = SharedPreferencesStorage(this)
val manager = SecureCredentialsManager(this, authentication, storage)
```

<details>
  <summary>Using Java</summary>

```java
AuthenticationAPIClient authentication = new AuthenticationAPIClient(account);
Storage storage = new SharedPreferencesStorage(this);
SecureCredentialsManager manager = new SecureCredentialsManager(this, authentication, storage);
```
</details>

#### Requiring Authentication

You can require the user authentication to obtain credentials. This will make the manager prompt the user with the device's configured Lock Screen, which they must pass correctly in order to obtain the credentials. **This feature is only available on devices where the user has setup a secured Lock Screen** (PIN, Pattern, Password or Fingerprint).

To enable authentication you must call the `requireAuthentication` method passing a valid _Activity_ context, a request code that represents the authentication call, and the title and description to display in the Lock Screen. As seen in the snippet below, you can leave these last two parameters with `null` to use the system's default title and description. It's only safe to call this method before the Activity is started.

```kotlin
//You might want to define a constant with the Request Code
companion object {
    const val AUTH_REQ_CODE = 111
}

manager.requireAuthentication(this, AUTH_REQ_CODE, null, null)
```

<details>
  <summary>Using Java</summary>

```java
//You might want to define a constant with the Request Code
private static final int AUTH_REQ_CODE = 11;

manager.requireAuthentication(this, AUTH_REQ_CODE, null, null);
```
</details>

When the above conditions are met and the manager requires the user authentication, it will use the activity context to launch the Lock Screen activity and wait for its result. If your activity is a subclass of `ComponentActivity`, this will be handled automatically for you internally. Otherwise, your activity must override the `onActivityResult` method and pass the request code and result code to the manager's `checkAuthenticationResult` method to verify if this request was successful or not.

```kotlin
 override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
    if (manager.checkAuthenticationResult(requestCode, resultCode)) {
        return
    }
    super.onActivityResult(requestCode, resultCode, data)
}
```

<details>
  <summary>Using Java</summary>

```java
@Override
protected void onActivityResult(int requestCode, int resultCode, Intent data) {
    if (manager.checkAuthenticationResult(requestCode, resultCode)) {
        return;
    }
    super.onActivityResult(requestCode, resultCode, data);
}
```
</details>

If the manager consumed the event, it will return true and later invoke the callback's `onSuccess` with the decrypted credentials.


#### Handling exceptions

In the event that something happened while trying to save or retrieve the credentials, a `CredentialsManagerException` will be thrown. These are some of the expected failure scenarios:

- Invalid Credentials format or values. e.g. when it's missing the `access_token`, the `id_token` or the `expires_at` values.
- Tokens have expired but no `refresh_token` is available to perform a refresh credentials request.
- Device's Lock Screen security settings have changed (e.g. the PIN code was changed). Even when `hasCredentials` returns true, the encryption keys will be deemed invalid and until `saveCredentials` is called again it won't be possible to decrypt any previously existing content, since they keys used back then are not the same as the new ones.
- Device is not compatible with some of the algorithms required by the `SecureCredentialsManager` class. This is considered a catastrophic event and might happen when the OEM has modified the Android ROM removing some of the officially included algorithms. Nevertheless, it can be checked in the exception instance itself by calling `isDeviceIncompatible`. By doing so you can decide the fallback for storing the credentials, such as using the regular `CredentialsManager`.

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

## FAQ

### Why is the Android Lint _error_ `'InvalidPackage'` considered a _warning_?

When building the project with `build`, an error appeared regarding an `invalid package` on the `okio` dependency. This snippet is in the `build.gradle` file so that the build runs fine:

```gradle
android {
    //...
    lintOptions {
       warning 'InvalidPackage'
    }
}
```

ref: https://github.com/square/okio/issues/58#issuecomment-72672263

### Why do I need to declare Manifest Placeholders for the Auth0 domain and scheme?

The library internally declares a `RedirectActivity` in its Android Manifest file. While this approach prevents the developer from adding an activity declaration to their application's Android Manifest file, it requires the use of Manifest Placeholders.

Alternatively, you can re-declare the `RedirectActivity` in the `AndroidManifest.xml` file with your own **intent-filter** so it overrides the library's default. If you do this then the `manifestPlaceholders` don't need to be set as long as the activity contains the `tools:node="replace"` like in the snippet below.

```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:tools="http://schemas.android.com/tools"
    package="your.app.package">
    <application android:theme="@style/AppTheme">

        <!-- ... -->

        <activity
            android:name="com.auth0.android.provider.RedirectActivity"
            tools:node="replace">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />

                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />

                <data
                    android:host="@string/com_auth0_domain"
                    android:pathPrefix="/android/${applicationId}/callback"
                    android:scheme="https" />
            </intent-filter>
        </activity>

        <!-- ... -->

    </application>
</manifest>
```

Recall that if you request a different scheme, you must replace the above `android:scheme` property value and initialize the provider with the new scheme. Read [this section](#a-note-about-app-deep-linking) to learn more.


### Is the Web Authentication module setup optional?

If you don't plan to use the _Web Authentication_ feature, you will notice that the compiler will still prompt you to provide the `manifestPlaceholders` values, since the `RedirectActivity` included in this library will require them, and the Gradle tasks won't be able to run without them.

Re-declare the activity manually with `tools:node="remove"` in your app's Android Manifest in order to make the manifest merger remove it from the final manifest file. Additionally, one more unused activity can be removed from the final APK by using the same process. A complete snippet to achieve this is:

```xml
<activity
    android:name="com.auth0.android.provider.AuthenticationActivity"
    tools:node="remove"/>
    <!-- Optional: Remove RedirectActivity -->
<activity
android:name="com.auth0.android.provider.RedirectActivity"
tools:node="remove"/>
```

### Unit testing with JUnit 4 or JUnit 5
#### Handling `Method getMainLooper in android.os.Looper not mocked` errors
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

#### Handling SSL errors
You might encounter errors similar to `PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target`, which means that you need to set up your unit tests in a way that ignores or trusts all SSL certificates. In that case, you may have to implement your own `NetworkingClient` so that you can supply your own `SSLSocketFactory` and `X509TrustManager`, and use that in creating your `Auth0` object. See the [`DefaultClient`](https://github.com/auth0/Auth0.Android/blob/main/auth0/src/main/java/com/auth0/android/request/DefaultClient.kt) class for an idea on how to extend `NetworkingClient`.

## Proguard
The rules should be applied automatically if your application is using `minifyEnabled = true`. If you want to include them manually check the [proguard directory](proguard).
By default you should at least use the following files:
* `proguard-okio.pro`
* `proguard-gson.pro`

## What is Auth0?

Auth0 helps you to:

* Add authentication with [multiple authentication sources](https://docs.auth0.com/identityproviders), either social like **Google, Facebook, Microsoft Account, LinkedIn, GitHub, Twitter, Box, Salesforce, among others**, or enterprise identity systems like **Windows Azure AD, Google Apps, Active Directory, ADFS or any SAML Identity Provider**.
* Add authentication through more traditional **[username/password databases](https://docs.auth0.com/mysql-connection-tutorial)**.
* Add support for **[linking different user accounts](https://docs.auth0.com/link-accounts)** with the same user.
* Support for generating signed [Json Web Tokens](https://docs.auth0.com/jwt) to call your APIs and **flow the user identity** securely.
* Analytics of how, when and where users are logging in.
* Pull data from other sources and add it to the user profile, through [JavaScript rules](https://docs.auth0.com/rules).

## Create a free Auth0 Account

1. Go to [Auth0](https://auth0.com) and click Sign Up.
2. Use Google, GitHub or Microsoft Account to login.

## Issue Reporting

If you have found a bug or if you have a feature request, please report them at this repository issues section. Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/whitehat) details the procedure for disclosing security issues.

## Author

[Auth0](https://auth0.com)

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for more info.
