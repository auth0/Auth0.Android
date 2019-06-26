# Auth0.Android

[![CircleCI](https://img.shields.io/circleci/project/github/auth0/Auth0.Android.svg?style=flat-square)](https://circleci.com/gh/auth0/Auth0.Android/tree/master)
[![Coverage Status](https://img.shields.io/codecov/c/github/auth0/Auth0.Android/master.svg?style=flat-square)](https://codecov.io/github/auth0/Auth0.Android)
[![License](http://img.shields.io/:license-mit-blue.svg?style=flat-square)](http://doge.mit-license.org)
[![Maven Central](https://img.shields.io/maven-central/v/com.auth0.android/auth0.svg?style=flat-square)](http://search.maven.org/#search%7Cgav%7C1%7Cg%3A%22com.auth0.android%22%20AND%20a%3A%22auth0%22)
[![Bintray](https://img.shields.io/bintray/v/auth0/android/auth0.svg?style=flat-square)](https://bintray.com/auth0/android/auth0/_latestVersion)

Android Java toolkit for Auth0 API

## Requirements

Android API version 15 or newer

## Installation

### Gradle

Auth0.android is available through [Gradle](https://gradle.org/). To install it, simply add the following line to your `build.gradle` file:

```gradle
dependencies {
    implementation 'com.auth0.android:auth0:1.16.0'
}
```

#### Android SDK Versions Troubleshooting
Those using this library from version `1.14.0` and up should start targeting latest android SDK versions, as [recommended by Google](https://developer.android.com/distribute/best-practices/develop/target-sdk). Those running into conflicts because of different `com.android.support` libraries versions can choose to use the latest release `28.0.0` or exclude the ones required by this library and require a different version in their app's `build.gradle` file as shown below:

 e.g. if choosing an older version such as `25.4.0`

```groovy
apply plugin: 'com.android.application'
 android {
    //...
}
 dependencies {
    implementation ('com.auth0.android:lock:1.14.1'){
        exclude group: 'com.android.support', module: 'appcompat-v7'
        exclude group: 'com.android.support', module: 'customtabs'
    }
    implementation 'com.android.support:appcompat-v7:25.4.0'
    implementation 'com.android.support:customtabs:25.4.0'
    //...
}
```

### Permissions

Open your app's `AndroidManifest.xml` file and add the following permission.

```xml
<uses-permission android:name="android.permission.INTERNET" />
```

## Usage

First create an instance of `Auth0` with your Application information

```java
Auth0 account = new Auth0("{YOUR_CLIENT_ID}", "{YOUR_DOMAIN}");
```

Alternatively, you can save your Application information in the `strings.xml` file using the following names:

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


### Authentication with Universal Login

First go to the [Auth0 Dashboard](https://manage.auth0.com/#/applications) and go to your application's settings. Make sure you have in *Allowed Callback URLs* a URL with the following format:

```
https://{YOUR_AUTH0_DOMAIN}/android/{YOUR_APP_PACKAGE_NAME}/callback
```

Remember to replace `{YOUR_APP_PACKAGE_NAME}` with your actual application's package name, available in your `app/build.gradle` file as the `applicationId` value.


Next, define the Manifest Placeholders for the Auth0 Domain and Scheme which are going to be used internally by the library to register an **intent-filter**. Go to your application's `build.gradle` file and add the `manifestPlaceholders` line as shown below:

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
        manifestPlaceholders = [auth0Domain: "@string/com_auth0_domain", auth0Scheme: "https"]
        //<---
    }
    //...
}
```

It's a good practice to define reusable resources like `@string/com_auth0_domain` but you can also hard code the value in the file. The scheme value can be either `https` or a custom one. Read [this section](#a-note-about-app-deep-linking) to learn more.

Alternatively, you can declare the `RedirectActivity` in the `AndroidManifest.xml` file with your own **intent-filter** so it overrides the library's default. If you do this then the `manifestPlaceholders` don't need to be set as long as the activity contains the `tools:node="replace"` like in the snippet below.

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
                    android:host="@string/com_auth0_domain"
                    android:pathPrefix="/android/${applicationId}/callback"
                    android:scheme="https" />
            </intent-filter>
        </activity>

        <!-- ... -->

    </application>
</manifest>
```

If you request a different scheme you must replace the above `android:scheme` property value and initialize the provider with the new scheme. Read [this section](#a-note-about-app-deep-linking) to learn more. 

Finally, don't forget to add the internet permission.

```xml
<uses-permission android:name="android.permission.INTERNET" />
```


> In versions 1.8.0 and before you had to define the **intent-filter** inside your activity to capture the result in the `onNewIntent` method and call `WebAuthProvider.resume()` with the received intent. This call is no longer required for versions greater than 1.8.0 as it's now done for you by the library.


Finally, authenticate by showing the **Auth0 Universal Login**:

```java
//Configure and launch the authentication
WebAuthProvider.init(account)
                .start(MainActivity.this, authCallback);

// Define somewhere in the code the callback
AuthCallback authCallback = new AuthCallback() {
    @Override
    public void onFailure(@NonNull Dialog dialog) {
        //failed with a dialog
    }

    @Override
    public void onFailure(AuthenticationException exception) {
        //failed with an exception
    }

    @Override
    public void onSuccess(@NonNull Credentials credentials) {
        //succeeded!
    }
};
```

If you've followed the configuration steps, the authentication result will be redirected from the browser to your application and you'll receive it in the Callback.

#### Those who don't need Web Authentication in their app

If you don't plan to use the _Web Authentication_ feature you will still be prompted to provide the `manifestPlaceholders` values since the `AuthenticationActivity` included in this library will require them and the Gradle tasks won't be able to run. Declare the activity manually with `tools:node="remove"` in your app's Android Manifest in order to make the manifest merger remove it from the final manifest file. Additionally, 2 more unused activities can be removed from the final APK by using the same process. A complete snippet to achieve this is:

```xml
<activity
    android:name="com.auth0.android.provider.AuthenticationActivity"
    tools:node="remove"/>
<!--Optional: Remove RedirectActivity and WebAuthActivity -->
<activity
    android:name="com.auth0.android.provider.RedirectActivity"
    tools:node="remove"/>
<activity
    android:name="com.auth0.android.provider.WebAuthActivity"
    tools:node="remove"/>
```


##### A note about App Deep Linking:

If you've followed this documents' configuration steps you've noticed that the default scheme used in the Callback URI is `https`. This works best for Android API 23 or newer if you're using [Android App Links](https://auth0.com/docs/applications/enable-android-app-links), but in previous Android versions this may show the intent chooser dialog prompting the user to choose either your application or the browser. You can change this behaviour by using a custom unique scheme so that the OS opens directly the link with your app.

1. Update the `auth0Scheme` Manifest Placeholder on the `app/build.gradle` file or update the intent-filter declaration in the `AndroidManifest.xml` to use the new scheme.
2. Update the allowed callback urls in your [Auth0 Dashboard](https://manage.auth0.com/#/applications) application's settings.
3. Call `withScheme()` passing the custom scheme you want to use.


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

> To use the `Code Grant` in Android, go to your [Application](https://manage.auth0.com/#/applications) in the dashboard, Settings tab, set `Application Type` to `Native` and `Token Endpoint Authentication Method` to `None`.


```java
WebAuthProvider.init(account)
                .useCodeGrant(true)
                .start(MainActivity.this, authCallback);
```

#### Specify audience

The snippet below requests the "userinfo" audience in order to guarantee OIDC compliant responses from the server. This can also be achieved by flipping the "OIDC Conformant" switch on in the OAuth Advanced Settings of your application. For more information check [this documentation](https://auth0.com/docs/api-auth/intro#how-to-use-the-new-flows).

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


#### Customize the Custom Tabs UI

If the device where the app is running has a Custom Tabs compatible Browser, a Custom Tab will be preferred for the authentication flow. You can customize the Page Title visibility and the Toolbar color by using the `CustomTabsOptions` class.
 
```java
 CustomTabsOptions options = CustomTabsOptions.newBuilder()
    .withToolbarColor(R.color.ct_toolbar_color)
    .showTitle(true)
    .build();
 
  WebAuthProvider.init(account)
                  .withCustomTabsOptions(options)
                  .start(MainActivity.this, authCallback);
```


### Clearing the session

To log the user out and clear the SSO cookies that the Auth0 Server keeps attached to your browser app, you need to call the [logout endpoint](https://auth0.com/docs/api/authentication?#logout). This can be done is a similar fashion to how you authenticated before: using the `WebAuthProvider` class.

Make sure to [revisit that section](#authentication-with-universal-login) to configure the Manifest Placeholders if you still cannot authenticate successfully. The values set there are used to generate the URL that the server will redirect the user back to after a successful log out.

In order for this redirection to happen, you must copy the *Allowed Callback URLs* value you added for authentication into the *Allowed Logout URLs* field in your [application settings](https://manage.auth0.com/#/applications). Both fields should have an URL with the following format:


```
https://{YOUR_AUTH0_DOMAIN}/android/{YOUR_APP_PACKAGE_NAME}/callback
```

Remember to replace `{YOUR_APP_PACKAGE_NAME}` with your actual application's package name, available in your `app/build.gradle` file as the `applicationId` value.



Initialize the provider, this time calling the static method `clearSession`.

```java
//Configure and launch the log out
WebAuthProvider.clearSession(account)
                .start(MainActivity.this, logoutCallback);

//Declare the callback that will receive the result
BaseCallback logoutCallback = new BaseCallback<Void, Auth0Exception>() {
    @Override
    public void onFailure(Auth0Exception exception) {
        //failed with an exception
    }

    @Override
    public void onSuccess(@NonNull Void payload) {
        //succeeded!
    }
};
```


The callback will get invoked when the user returns to your application. If this is the result of being redirected back by the server, that would be considered a success. There are some scenarios in which this can fail:
* When the domain is not [correctly set up](#usage) in the Auth0 instance. The cause of the exception will be an instance of `IllegalArgumentException`.
* When there is no browser application that can open a URL. The cause of the exception will be an instance of `ActivityNotFoundException`.
* When the user closes the browser manually, e.g. by pressing the back key on their device.
* When the `returnTo` URL is not whitelisted in your application settings.


#### Customize the Custom Tabs UI

Similarly to when you authenticated your users, for log out you can also customize the styling of the Custom Tabs browser. However, do note the browser is briefly shown to the user.

```java
 CustomTabsOptions options = CustomTabsOptions.newBuilder()
    .withToolbarColor(R.color.ct_toolbar_color)
    .showTitle(true)
    .build();

  WebAuthProvider.clearSession(account)
                  .withCustomTabsOptions(options)
                  .start(MainActivity.this, logoutCallback);
```


#### Changing the scheme
The scheme used can be changed as well. This configuration will probably match what you've done for the [authentication setup](#a-note-about-app-deep-linking).

```java
WebAuthProvider.clearSession(account)
                .withScheme("myapp")
                .start(MainActivity.this, logoutCallback);
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

If the `Auth0` instance wasn't configured as "OIDC conformant", this call requires the Application to have the *Resource Owner* Client Grant Type enabled. Check [this article](https://auth0.com/docs/clients/client-grant-types) to learn how to enable it.

```java
authentication
    .login("info@auth0.com", "a secret password", "my-database-connection")
    .start(new BaseCallback<Credentials, AuthenticationException>() {
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


#### Login using MFA with One Time Password code

This call requires the client to have the *MFA* Client Grant Type enabled. Check [this article](https://auth0.com/docs/clients/client-grant-types) to learn how to enable it.

When you sign in to a multifactor authentication enabled connection using the `login` method, you receive an error standing that MFA is required for that user along with an `mfa_token` value. Use this value to call `loginWithOTP` and complete the MFA flow passing the One Time Password from the enrolled MFA code generator app.


```java
authentication
    .loginWithOTP("the mfa token", "123456")
    .start(new BaseCallback<Credentials, AuthenticationException>() {
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



#### Passwordless Login

This feature requires your Application to have the *Resource Owner* Legacy Grant Type enabled. Check [this article](https://auth0.com/docs/clients/client-grant-types) to learn how to enable it. Note that Passwordless authentication *cannot be used* with the [OIDC Conformant Mode](#oidc-conformant-mode) enabled.

Passwordless it's a 2 steps flow:

Step 1: Request the code

```java
authentication
    .passwordlessWithEmail("info@auth0.com", PasswordlessType.CODE, "my-passwordless-connection")
    .start(new BaseCallback<Void, AuthenticationException>() {
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
    .start(new BaseCallback<Credentials, AuthenticationException>() {
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
    .start(new BaseCallback<Credentials, AuthenticationException>() {
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
   .start(new BaseCallback<UserProfile, AuthenticationException>() {
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
    .start(new BaseCallback<List<UserIdentity>, ManagementException>() {
        @Override
        public void onSuccess(List<UserIdentity> payload) {
            //Got the updated identities! Accounts linked.
        }

        @Override
        public void onFailure(ManagementException error) {
            //Error!
        }
    });
```

#### Unlink users

```java
users
    .unlink("primary user id", "secondary user id", "secondary provider")
    .start(new BaseCallback<List<UserIdentity>, ManagementException>() {
        @Override
        public void onSuccess(List<UserIdentity> payload) {
            //Got the updated identities! Accounts linked.
        }

        @Override
        public void onFailure(ManagementException error) {
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
            //Profile received
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
            //User Metadata updated
        }

        @Override
        public void onFailure(ManagementException error) {
            //Error!
        }
    });
```

> In all the cases, the `User ID` parameter is the unique identifier of the auth0 account instance. i.e. in `google-oauth2|123456789081523216417` it would be the part after the '|' pipe: `123456789081523216417`.



## Credentials Manager

This library ships with two additional classes that help you manage the Credentials received during authentication. Depending on the minimum API level that your application is targeting you may like to use a different implementation.

### Basic (Min API 15)

The basic version supports asking for `Credentials` existence, storing them and getting them back. If the credentials have expired and a refresh_token was saved, they are automatically refreshed. The class is called `CredentialsManager` and requires at minimum Android API 15.

#### Usage
1. **Instantiate the manager:**
You'll need an `AuthenticationAPIClient` instance to renew the credentials when they expire and a `Storage` object. We provide a `SharedPreferencesStorage` class that makes use of `SharedPreferences` to create a file in the application's directory with **Context.MODE_PRIVATE** mode. This implementation is thread safe and can either be obtained through a shared method or on demand.

```java
AuthenticationAPIClient authentication = new AuthenticationAPIClient(account);
Storage storage = new SharedPreferencesStorage(this);
CredentialsManager manager = new CredentialsManager(authentication, storage);
```

2. **Save credentials:**
The credentials to save **must have** `expires_in` and at least an `access_token` or `id_token` value. If one of the values is missing when trying to set the credentials, the method will throw a `CredentialsManagerException`. If you want the manager to successfully renew the credentials when expired you must also request the `offline_access` scope when logging in in order to receive a `refresh_token` value along with the rest of the tokens. i.e. Logging in with a database connection and saving the credentials:

```java
authentication
    .login("info@auth0.com", "a secret password", "my-database-connection")
    .setScope("openid offline_access")
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

3. **Check credentials existence:**
There are cases were you just want to check if a user session is still valid (i.e. to know if you should present the login screen or the main screen). For convenience, we include a `hasValidCredentials` method that can let you know in advance if a non-expired token is available without making an additional network call. The same rules of the `getCredentials` method apply:

```java
boolean authenticated = manager.hasValidCredentials();
```

4. **Retrieve credentials:**
Existing credentials will be returned if they are still valid, otherwise the `refresh_token` will be used to attempt to renew them. If the `expires_in` or both the `access_token` and `id_token` values are missing, the method will throw a `CredentialsManagerException`. The same will happen if the credentials have expired and there's no `refresh_token` available.

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


5. **Clear credentials:**
When you want to log the user out:

```java
manager.clearCredentials();
```


### Encryption enforced (Min API 21)

This version expands the minimum version and adds encryption to the data storage. Additionally, in those devices where a Secure Lock Screen has been configured it can require the user authentication before letting them obtain the stored credentials. The class is called `SecureCredentialsManager` and requires at minimum Android API 21.


#### Usage
The usage is similar to the previous version, with the slight difference that the manager now requires a valid android `Context` as shown below:

```java
AuthenticationAPIClient authentication = new AuthenticationAPIClient(account);
Storage storage = new SharedPreferencesStorage(this);
SecureCredentialsManager manager = new SecureCredentialsManager(this, authentication, storage);
```

#### Requiring Authentication

You can require the user authentication to obtain credentials. This will make the manager prompt the user with the device's configured Lock Screen, which they must pass correctly in order to obtain the credentials. **This feature is only available on devices where the user has setup a secured Lock Screen** (PIN, Pattern, Password or Fingerprint).

To enable authentication you must call the `requireAuthentication` method passing a valid _Activity_ context, a Request Code that represents the authentication call, and the title and description to display in the LockScreen. As seen in the snippet below, you can leave these last two parameters with `null` to use the system default resources.

```java
//You might want to define a constant with the Request Code
private static final int AUTH_REQ_CODE = 11;

manager.requireAuthentication(this, AUTH_REQ_CODE, null, null);
```

When the above conditions are met and the manager requires the user authentication, it will use the activity context to launch a new activity for the result. The outcome of getting approved or rejected by the Lock Screen is given back to the activity in the `onActivityResult` method, which your activity must override to redirect the data to the manager using the `checkAuthenticationResult` method.

```java
@Override
protected void onActivityResult(int requestCode, int resultCode, Intent data) {
    if (manager.checkAuthenticationResult(requestCode, resultCode)) {
        return;
    }
    super.onActivityResult(requestCode, resultCode, data);
}
```

The `checkAuthenticationResult` method will continue the retrieval of credentials on a successful authentication, and the decrypted credentials will be delivered to the callback passed on the `getCredentials` call.


#### Handling exceptions

In the event that something happened while trying to save or retrieve the credentials, a `CredentialsManagerException` will be thrown. These are some of the expected failure scenarios:

- Invalid Credentials format or values. e.g. when it's missing the `access_token`, the `id_token` or the `expires_at` values.
- Tokens have expired but no `refresh_token` is available to perform a refresh credentials request.
- Device's Lock Screen security settings have changed (e.g. the PIN code was changed). Even when `hasCredentials` returns true, the encryption keys will be deemed invalid and until `saveCredentials` is called again it won't be possible to decrypt any previously existing content, since they keys used back then are not the same as the new ones.
- Device is not compatible with some of the algorithms required by the `SecureCredentialsManager` class. This is considered a catastrophic event and might happen when the OEM has modified the Android ROM removing some of the officially included algorithms. Nevertheless, it can be checked in the exception instance itself by calling `isDeviceIncompatible`. By doing so you can decide the fallback for storing the credentials, such as using the regular `CredentialsManager`.

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
