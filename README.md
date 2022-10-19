# Auth0.Android

[![CircleCI](https://img.shields.io/circleci/project/github/auth0/Auth0.Android.svg?style=flat-square)](https://circleci.com/gh/auth0/Auth0.Android/tree/master)
[![Coverage Status](https://img.shields.io/codecov/c/github/auth0/Auth0.Android/master.svg?style=flat-square)](https://codecov.io/github/auth0/Auth0.Android)
[![License](https://img.shields.io/:license-mit-blue.svg?style=flat-square)](https://doge.mit-license.org/)
[![Maven Central](https://img.shields.io/maven-central/v/com.auth0.android/auth0.svg?style=flat-square)](https://search.maven.org/artifact/com.auth0.android/auth0)
[![javadoc](https://javadoc.io/badge2/com.auth0.android/auth0/javadoc.svg)](https://javadoc.io/doc/com.auth0.android/auth0)

📚 [Documentation](#documentation) • 🚀 [Getting Started](#getting-started) • ⏭️ [Next Steps](#next-steps) • ❓ [FAQs](/FAQ.md) • 💬 [Feedback](#feedback)

## Documentation
- [Quickstart](https://auth0.com/docs/quickstart/native/android/interactive)
- [Sample App](https://github.com/auth0-samples/auth0-android-sample/tree/master/00-Login-Kt)
- [FAQs](/FAQ.md)
- [Examples](/EXAMPLES.md)
- [Docs Site](https://javadoc.io/doc/com.auth0.android/auth0/latest/index.html)


## Getting Started

### Requirements

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

### Installation


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

### Configure the SDK

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

## Feedback

### Contributing

We appreciate feedback and contribution to this repo! Before you get started, please see the following:

- [Auth0's general contribution guidelines](https://github.com/auth0/open-source-template/blob/master/GENERAL-CONTRIBUTING.md)
- [Auth0's code of conduct guidelines](https://github.com/auth0/Auth0.Android/blob/main/CODE-OF-CONDUCT.md)

### Raise an issue
To provide feedback or report a bug, [please raise an issue on our issue tracker](https://github.com/auth0/Auth0.Android/issues).

### Vulnerability Reporting
Please do not report security vulnerabilities on the public Github issue tracker. The [Responsible Disclosure Program](https://auth0.com/whitehat) details the procedure for disclosing security issues.

---

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: light)" srcset="./assets/auth0_brand_light.png"   width="150">
    <source media="(prefers-color-scheme: dark)" srcset="./assets/auth0_brand_dark.png" width="150">
    <img alt="Auth0 Logo" src="./assets/auth0_brand_light.png" width="150">
  </picture>
</p>
<p align="center">Auth0 is an easy to implement, adaptable authentication and authorization platform. To learn more checkout <a href="https://auth0.com/why-auth0">Why Auth0?</a></p>
<p align="center">
This project is licensed under the MIT license. See the <a href="./LICENSE"> LICENSE</a> file for more info.</p>