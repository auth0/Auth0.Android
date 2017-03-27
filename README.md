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

###Gradle

Auth0.android is available through [Gradle](https://gradle.org/). To install it, simply add the following line to your `build.gradle` file:

```gradle
dependencies {
    compile 'com.auth0.android:auth0:1.6.0'
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


### Authentication API

The client provides methods to authenticate the user against Auth0 server.

Create a new instance by passing the account:

```java
AuthenticationAPIClient authentication = new AuthenticationAPIClient(account);
```

#### Login with database connection

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

### Get User Profile

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

### Update User Metadata

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


### Web-based Auth

First go to [Auth0 Dashboard](https://manage.auth0.com/#/applications) and go to your application's settings. Make sure you have in *Allowed Callback URLs* a URL with the following format:

```
https://{YOUR_AUTH0_DOMAIN}/android/{YOUR_APP_PACKAGE_NAME}/callback
```

Open your app's `AndroidManifest.xml` file and add the following permission.

```xml
<uses-permission android:name="android.permission.INTERNET" />
```

Also register the intent filters inside your activity's tag, so you can receive the call in your activity. Note that you will have to specify the callback url inside the `data` tag.

```xml
    <application android:theme="@style/AppTheme">

        <!-- ... -->

        <activity
            android:name="com.mycompany.MainActivity"
            android:theme="@style/MyAppTheme"
            android:launchMode="singleTask">

            <intent-filter android:autoVerify="true">
                <action android:name="android.intent.action.VIEW" />

                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />

                <data
                    android:host="{YOUR_AUTH0_DOMAIN}"
                    android:pathPrefix="/android/{YOUR_APP_PACKAGE_NAME}/callback"
                    android:scheme="https" />
            </intent-filter>

        </activity>

        <!-- ... -->

    </application>
```

Make sure the Activity's **launchMode** is declared as "singleTask" or the result won't come back after the authentication.

When you launch the WebAuthProvider you'll expect a result back. To capture the response override the `onNewIntent` method and call `WebAuthProvider.resume()` with the received parameters:

```java
public class MyActivity extends Activity {

    @Override
    protected void onNewIntent(Intent intent) {
        if (WebAuthProvider.resume(intent)) {
            return;
        }
        super.onNewIntent(intent);
    }
}

```

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

#### Specify scope

```java
WebAuthProvider.init(account)
                .withScope("user openid")
                .start(MainActivity.this, authCallback);
```

> The default scope used is `openid`

#### Specify Connection scope

```java
WebAuthProvider.init(account)
                .withConnectionScope("email", "profile", "calendar:read")
                .start(MainActivity.this, authCallback);
```

#### Authenticate with Auth0 hosted login page
Simply don't specify any custom connection and the Lock web widget will show.

```java
WebAuthProvider.init(account)
                .start(MainActivity.this, authCallback);
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

##Proguard
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
