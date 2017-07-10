# Auth0.Android

[![CircleCI](https://img.shields.io/circleci/project/github/auth0/Auth0.Android.svg?style=flat-square)](https://circleci.com/gh/auth0/Auth0.Android/tree/master)
[![Coverage Status](https://img.shields.io/codecov/c/github/auth0/Auth0.Android/master.svg?style=flat-square)](https://codecov.io/github/auth0/Auth0.Android)
[![License](http://img.shields.io/:license-mit-blue.svg?style=flat)](http://doge.mit-license.org)
[![Maven Central](https://img.shields.io/maven-central/v/com.auth0.android/auth0.svg)](http://search.maven.org/#search%7Cgav%7C1%7Cg%3A%22com.auth0.android%22%20AND%20a%3A%22auth0%22)
[![Bintray](https://api.bintray.com/packages/auth0/android/auth0/images/download.svg)](https://bintray.com/auth0/android/auth0/_latestVersion)

Android java toolkit for Auth0 API

## Requirements

Android API version 15 or newer

## Installation

### Gradle

Auth0.android is available through [Gradle](https://gradle.org/). To install it, simply add the following line to your `build.gradle` file:

```gradle
dependencies {
    compile 'com.auth0.android:auth0:1.9.0'
}
```

### Permissions

Open your app's `AndroidManifest.xml` file and add the following permission.

```xml
<uses-permission android:name="android.permission.INTERNET" />
```

## Usage

First create an instance of `Auth0` with your client information

```java
Auth0 account = new Auth0("{YOUR_CLIENT_ID}", "{YOUR_DOMAIN}");
```

Alternatively, you can save your client information in the `strings.xml` file using the following names:

```xml
<resources>
    <string name="com_auth0_client_id">YOUR_CLIENT_ID</string>
    <string name="com_auth0_domain">YOUR_DOMAIN</string>
</resources>

```

And then create a new Auth0 instance by passing an Android Context:

```java
Auth0 account = new Auth0(context);
```

### OIDC Conformant Mode

It is strongly encouraged that this SDK be used in OIDC Conformant mode. When this mode is enabled, it will force the SDK to use Auth0's current authentication pipeline and will prevent it from reaching legacy endpoints. By default is `false`

```java
Auth0 account = new Auth0("{YOUR_CLIENT_ID}", "{YOUR_DOMAIN}");
//Configure the account in OIDC conformant mode
account.setOIDCConformant(true);
//Use the account in the API clients
```

Passwordless authentication *cannot be used* with this flag set to `true`. For more information, please see the [OIDC adoption guide](https://auth0.com/docs/api-auth/tutorials/adoption).


### Authentication with Hosted Login Page

First go to [Auth0 Dashboard](https://manage.auth0.com/#/applications) and go to your application's settings. Make sure you have in *Allowed Callback URLs* a URL with the following format:

```
https://{YOUR_AUTH0_DOMAIN}/android/{YOUR_APP_PACKAGE_NAME}/callback
```

Remember to replace `{YOUR_APP_PACKAGE_NAME}` with your actual application's package name, available in your `app/build.gradle` file as the `applicationId` value.


Next, define a placeholder for the Auth0 Domain which is going to be used internally by the library to register an **intent-filter**. Go to your application's `build.gradle` file and add the `manifestPlaceholders` line as shown below:

```groovy
apply plugin: 'com.android.application'

android {
    compileSdkVersion 25
    defaultConfig {
        applicationId "com.auth0.samples"
        minSdkVersion 15
        targetSdkVersion 25
        //...

        //---> Add the next line
        manifestPlaceholders = [auth0Domain: "@string/auth0_domain"]
        //<---
    }
    //...
}
```

It's a good practice to define reusable resources like `@string/auth0_domain` but you can also hard code the value in the file.

Alternatively, you can declare the `RedirectActivity` in the `AndroidManifest.xml` file with your own **intent-filter** so it overrides the library's default. If you do this then the `manifestPlaceholders` don't need to be set as long as the activity contains the `tools:node="replace"` like in the snippet below. If you choose to use a [custom scheme](#a-note-about-app-deep-linking) you must define your own intent-filter as explained below.

In your manifest inside your application's tag add the `RedirectActivity` declaration:

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
                    android:host="@string/auth0_domain"
                    android:pathPrefix="/android/${applicationId}/callback"
                    android:scheme="https" />
            </intent-filter>
        </activity>

        <!-- ... -->

    </application>
</manifest>
```

If you request a different scheme you must replace the `android:scheme` property value. Finally, don't forget to add the internet permission.

```xml
<uses-permission android:name="android.permission.INTERNET" />
```


> In versions 1.8.0 and before you had to define the **intent-filter** inside your activity to capture the result in the `onNewIntent` method and call `WebAuthProvider.resume()` with the received intent. This call is no longer required for versions greater than 1.8.0 as it's now done for you by the library.


Finally, authenticate by showing the **Auth0 Hosted Login Page**:

```java
WebAuthProvider.init(account)
                .start(MainActivity.this, authCallback);
```

If you've followed the configuration steps, the authentication result will be redirected from the browser to your application and you'll receive it in the Callback.


##### A note about App Deep Linking:

Currently, the default scheme used in the Callback Uri is `https`. This works best for Android API 23 or newer if you're using [Android App Links](https://developer.android.com/training/app-links/index.html), but in previous Android versions this may show the intent chooser dialog prompting the user to chose either your application or the browser. You can change this behaviour by using a custom unique scheme, so that the OS opens directly the link with your app.

1. Update the intent filter in the Android Manifest and change the custom scheme.
2. Update the allowed callback urls in your [Auth0 Dashboard](https://manage.auth0.com/#/applications) client's settings.
3. Call `withScheme()` passing the scheme you want to use.


```java
WebAuthProvider.init(account)
                .withScheme("myapp")
                .start(MainActivity.this, authCallback);
```


#### Authenticate with any Auth0 connection

```java
WebAuthProvider.init(account)
                .withConnection("twitter")
                .start(MainActivity.this, authCallback);
```

#### Use Code grant with PKCE

> Before you can use `Code Grant` in Android, make sure to go to your [client's section](https://manage.auth0.com/#/applications) in dashboard and check in the Settings that `Client Type` is `Native`.


```java
WebAuthProvider.init(account)
                .useCodeGrant(true)
                .start(MainActivity.this, authCallback);
```

#### Specify audience

The snippet below requests the "userinfo" audience in order to guarantee OIDC compliant responses from the server. This can also be achieved by flipping the "OIDC Conformant" switch on in the OAuth Advanced Settings of your client. For more information check [this documentation](https://auth0.com/docs/api-auth/intro#how-to-use-the-new-flows).

```java
WebAuthProvider.init(account)
                .withAudience("https://{YOUR_AUTH0_DOMAIN}/userinfo")
                .start(MainActivity.this, authCallback);
```

> Replace `{YOUR_AUTH0_DOMAIN}` with your actual Auth0 domain (i.e. `mytenant.auth0.com`).

#### Specify scope

```java
WebAuthProvider.init(account)
                .withScope("openid profile email")
                .start(MainActivity.this, authCallback);
```

> The default scope used is `openid`

#### Specify Connection scope

```java
WebAuthProvider.init(account)
                .withConnectionScope("email", "profile", "calendar:read")
                .start(MainActivity.this, authCallback);
```


## Next steps

### Learning resources

Check out the [Android QuickStart Guide](https://auth0.com/docs/quickstart/native/android) to find out more about the Auth0.Android toolkit and explore our tutorials and sample projects.

### Authentication API

The client provides methods to authenticate the user against Auth0 server.

Create a new instance by passing the account:

```java
AuthenticationAPIClient authentication = new AuthenticationAPIClient(account);
```

#### Login with database connection

If the `Auth0` instance wasn't configured as "OIDC conformant", this call requires the client to have the *Resource Owner* Client Grant Type enabled. Check [this article](https://auth0.com/docs/clients/client-grant-types) to learn how to enable it.

```java
authentication
    .login("info@auth0.com", "a secret password", "my-database-connection")
    .start(new BaseCallback<Credentials>() {
        @Override
        public void onSuccess(Credentials payload) {
            //Logged in!
        }

        @Override
        public void onFailure(AuthenticationException error) {
            //Error!
        }
    });
```

> The default scope used is `openid`

#### Passwordless Login

This feature requires your client to have the *Resource Owner* Legacy Grant Type enabled. Check [this article](https://auth0.com/docs/clients/client-grant-types) to learn how to enable it. Note that Passwordless authentication *cannot be used* with the [OIDC Conformant Mode](#oidc-conformant-mode) enabled.

Passwordless it's a 2 steps flow:

Step 1: Request the code

```java
authentication
    .passwordlessWithEmail("info@auth0.com", PasswordlessType.CODE, "my-passwordless-connection")
    .start(new BaseCallback<Credentials>() {
        @Override
        public void onSuccess(Void payload) {
            //Code sent!
        }

        @Override
        public void onFailure(AuthenticationException error) {
            //Error!
        }
    });
```

> The default scope used is `openid`

Step 2: Input the code

```java
authentication
    .loginWithEmail("info@auth0.com", "123456", "my-passwordless-connection")
        @Override
        public void onSuccess(Credentials payload) {
            //Logged in!
        }

        @Override
        public void onFailure(AuthenticationException error) {
            //Error!
        }
    });
```


#### Sign Up with database connection

```java
authentication
    .signUp("info@auth0.com", "a secret password", "my-database-connection")
    .start(new BaseCallback<Credentials>() {
        @Override
        public void onSuccess(Credentials payload) {
            //Signed Up & Logged in!
        }

        @Override
        public void onFailure(AuthenticationException error) {
            //Error!
        }
    });
```


#### Get user information

```java
authentication
   .userInfo("user access_token")
   .start(new BaseCallback<Credentials>() {
       @Override
       public void onSuccess(UserProfile payload) {
           //Got the profile!
       }

       @Override
       public void onFailure(AuthenticationException error) {
           //Error!
       }
   });
```


### Management API (Users)

The client provides methods to link and unlink users account.

Create a new instance by passing the account and the primary user token:

```java
Auth0 account = new Auth0("client id", "domain");
UsersAPIClient users = new UsersAPIClient(account, "api token");
```

#### Link users

```java
users
    .link("primary user id", "secondary user token")
    .start(new BaseCallback<List<UserIdentity>>() {
        @Override
        public void onSuccess(List<UserIdentity> payload) {
            //Got the updated identities! Accounts linked.
        }

        @Override
        public void onFailure(Auth0Exception error) {
            //Error!
        }
    });
```

#### Unlink users

```java
users
    .unlink("primary user id", "secondary user id", "secondary provider")
    .start(new BaseCallback<List<UserIdentity>>() {
        @Override
        public void onSuccess(List<UserIdentity> payload) {
            //Got the updated identities! Accounts linked.
        }

        @Override
        public void onFailure(Auth0Exception error) {
            //Error!
        }
    });
```

#### Get User Profile

```java
users
    .getProfile("user id")
    .start(new BaseCallback<UserProfile, ManagementException>() {
        @Override
        public void onSuccess(UserProfile payload) {
            //Profile
        }

        @Override
        public void onFailure(ManagementException error) {
            //Error!
        }
    });
```

#### Update User Metadata

```java
Map<String, Object> metadata = new HashMap<>();
metadata.put("name", Arrays.asList("My", "Name", "Is"));
metadata.put("phoneNumber", "1234567890");

users
    .updateMetadata("user id", metadata)
    .start(new BaseCallback<UserProfile, ManagementException>() {
        @Override
        public void onSuccess(UserProfile payload) {
            //Metadata updated
        }

        @Override
        public void onFailure(ManagementException error) {
            //Error!
        }
    });
```

> In all the cases, the `User ID` parameter is the unique identifier of the auth0 account instance. i.e. in `google-oauth2|123456789081523216417` it would be the part after the '|' pipe: `123456789081523216417`.


### Credentials Manager
This library ships with a `CredentialsManager` class to easily store and retrieve fresh Credentials from a given `Storage`.

#### Usage
1. **Instantiate the manager**
You'll need an `AuthenticationAPIClient` instance used to renew the credentials when they expire and a `Storage`. The Storage implementation is up to you. We provide a `SharedPreferencesStorage` that uses `SharedPreferences` to create a file in the application's directory with Context.MODE_PRIVATE mode. This implementation is thread safe and can either be obtained through a Singleton like method or be created every time it's needed.

```java
AuthenticationAPIClient authentication = new AuthenticationAPIClient(account);
Storage storage = new SharedPreferencesStorage(this);
CredentialsManager manager = new CredentialsManager(authentication, storage);
```

2. **Save credentials**
The credentials to save **must have** `expires_in` and at least an `access_token` or `id_token` value. If one of the values is missing when trying to set the credentials, the method will throw a `CredentialsManagerException`. If you want the manager to successfully renew the credentials when expired you must also request the `offline_access` scope when logging in in order to receive a `refresh_token` value along with the rest of the tokens. i.e. Logging in with a database connection and saving the credentials:

```java
authentication
    .login("info@auth0.com", "a secret password", "my-database-connection")
    .setScope("openid offline_access")
    .start(new BaseCallback<Credentials>() {
        @Override
        public void onSuccess(Credentials credentials) {
            //Save the credentials
            manager.saveCredentials(credentials);
        }

        @Override
        public void onFailure(AuthenticationException error) {
            //Error!
        }
    });
```

3. **Check credentials existence**
There are cases were you just want to check if a user session is still valid (i.e. to know if you should present the login screen or the main screen). For convenience we include a `hasValidCredentials` method that can let you know in advance if a non-expired token is available without making an additional network call. The same rules of the `getCredentials` method apply:

```java
boolean authenticated = manager.hasValidCredentials();
```

4. **Retrieve credentials**
Existing credentials will be returned if they are still valid, otherwise the `refresh_token` will be used to attempt to renew them. If the `expires_in` or both the `access_token` and `id_token` values are missing, the method will throw a `CredentialsManagerException`. The same will happen if the credentials have expired and there's no `refresh_token` available.

```java
manager.getCredentials(new BaseCallback<Credentials, CredentialsManagerException>(){
   public void onSuccess(Credentials credentials){
      //Use the Credentials
   }

    public void onFailure(CredentialsManagerException error){
      //Error!
   }
});
```


5. **Clear credentials**
When you want to log the user out:

```java
manager.clearCredentials();
```

## FAQ

* Why is the Android Lint _error_ `'InvalidPackage'` considered a _warning_?

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

## Proguard
The rules should be applied automatically if your application is using `minifyEnabled = true`. If you want to include them manually check the [proguard directory](proguard).
By default you should at least use the following files:
* `proguard-okio.pro`
* `proguard-gson.pro`


## What is Auth0?

Auth0 helps you to:

* Add authentication with [multiple authentication sources](https://docs.auth0.com/identityproviders), either social like **Google, Facebook, Microsoft Account, LinkedIn, GitHub, Twitter, Box, Salesforce, amont others**, or enterprise identity systems like **Windows Azure AD, Google Apps, Active Directory, ADFS or any SAML Identity Provider**.
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

[Auth0](auth0.com)

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE.txt) file for more info.
