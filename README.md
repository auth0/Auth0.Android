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
    compile "com.auth0.android:auth0:1.0.0"
}
```

 > Replace version with the latest.


## Usage

### Authentication API

The client provides methods to authenticate the user against Auth0 server.
 
 Create a new instance by passing the account:
 
 ```java
 Auth0 account = new Auth0("clientId", "domain");
 AuthenticationAPIClient apiClient = new AuthenticationAPIClient(account);
 ```

#### Login with database connection

```java
apiClient
    .login("email@domain.com", "password123")
    .setConnection("Username-Password-Authentication")
    .start(new BaseCallback<Credentials>() {
        @Override
        public void onSuccess(Credentials payload) {
            //Got my credentials!
        }
    
        @Override
        public void onFailure(AuthenticationException error) {
            //Error!
        }
    });
```

#### Passwordless Login

```java
apiClient
    .loginWithEmail("email@domain.com", "password123")
    .start(new BaseCallback<Credentials>() {
        @Override
        public void onSuccess(Credentials payload) {
            //Got my credentials!
        }
    
        @Override
        public void onFailure(AuthenticationException error) {
            //Error!
        }
    });
```


#### Sign Up with database connection

```swift
apiClient
    .signUp("email@domain.com", "password123")
    .start(new BaseCallback<Credentials>() {
        @Override
        public void onSuccess(Credentials payload) {
            //Got my credentials!
        }
    
        @Override
        public void onFailure(AuthenticationException error) {
            //Error!
        }
    });
```


#### Get user information

```java
apiClient
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

In your application's `AndroidManifest.xml` file register the WebAuthActivity


```xml
    <application android:theme="@style/AppTheme">

        <!-- ... -->
        
        <activity
            android:name="com.auth0.android.provider.WebViewActivity"
            android:theme="@style/MyAppTheme" />
    </application>
```


#### Authenticate with any Auth0 connection

```java
Auth0 account = new Auth0("clientId", "domain");
WebAuthProvider.init(account)
                .useBrowser(true)
                .withConnection("twitter")
                .start(MainActivity.this, authCallback, WEB_REQ_CODE);
```


#### Specify scope

```java
Auth0 account = new Auth0("clientId", "domain");
WebAuthProvider.init(account)
                .useBrowser(true)
                .withScope("user openid")
                .withState("123456")
                .withConnection("twitter")
                .start(MainActivity.this, authCallback, WEB_REQ_CODE);
```

#### Authenticate with Auth0 hosted login page

```java
Auth0 account = new Auth0("clientId", "domain");
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
