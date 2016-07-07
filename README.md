# Auth0.Android

[![CI Status](http://img.shields.io/travis/auth0/auth0.android.svg?style=flat-square)](https://travis-ci.org/auth0/auth0.android)

Android java toolkit for Auth0 API

## Requirements

Android API version 15 or newer

## Installation

###Gradle

Auth0.android is available through [Gradle](https://gradle.org/). To install it, simply add the following line to your `build.gradle` file:

```gradle
dependencies {
    compile "com.auth0.android:auth0:1.0.0-beta.1"
}
```

## Usage

First create an instance of `Auth0` with your client information

```java
Auth0 account = new Auth0("{YOUR_CLIENT_ID}", "{YOUR_DOMAIN}");
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
    .login("info@auth0.com", "a secret password")
    .setConnection("Username-Password-Authentication")
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

#### Passwordless Login

```java
authentication
    .loginWithEmail("info@auth0.com", "a secret password")
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
    .signUp("info@auth0.com", "a secret password")
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
   .tokenInfo("user id_token")
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

Create a new instance by passing the account:

```java
Auth0 account = new Auth0("clientId", "domain");
UsersAPIClient apiClient = new UsersAPIClient(account);
```


#### Link users

```java
apiClient
    .link("primary user_id", "primary id_token", "secondary id_token")
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
apiClient
    .unlink("primary user_id", "primary id_token", "secondary user_id", "secondary provider")
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

### Web-based Auth

In your application's `AndroidManifest.xml` file register the WebAuthActivity inside the `application` tag like


```xml
    <application android:theme="@style/AppTheme">

        <!-- ... -->
        
        <activity
            android:name="com.auth0.android.provider.WebViewActivity"
            android:theme="@style/MyAppTheme" />

        <!-- ... -->

    </application>
```


And define a constant like `WEB_REQ_CODE` that holds the request code (an `int`), that will be sent back with the intent once the auth is finished in the browser/webview

#### Authenticate with any Auth0 connection

```java
WebAuthProvider.init(account)
                .withConnection("twitter")
                .start(MainActivity.this, authCallback, WEB_REQ_CODE);
```

#### Use Code grant with PKCE

```java
WebAuthProvider.init(account)
                .useCodeGrant(true)
                .start(MainActivity.this, authCallback, WEB_REQ_CODE);
```

#### Use browser instead of WebView

```java
WebAuthProvider.init(account)
                .useCodeGrant(true)
                .useBrowser(true)
                .start(MainActivity.this, authCallback, WEB_REQ_CODE);
```

#### Specify scope

```java
WebAuthProvider.init(account)
                .withScope("user openid")
                .start(MainActivity.this, authCallback, WEB_REQ_CODE);
```

#### Authenticate with Auth0 hosted login page

```java
WebAuthProvider.init(account)
                .useBrowser(true)
                .start(MainActivity.this, authCallback, WEB_REQ_CODE);
```


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
