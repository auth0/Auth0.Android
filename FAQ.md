# Frequently Asked Questions

1. [Why is the Android Lint _error_ `'InvalidPackage'` considered a _warning_?](#1-why-is-the-android-lint-_error_-invalidpackage-considered-a-_warning_)
2. [Why do I need to declare Manifest Placeholders for the Auth0 domain and scheme?](#2-why-do-i-need-to-declare-manifest-placeholders-for-the-auth0-domain-and-scheme)
3. [Is the Web Authentication module setup optional?](#3-is-the-web-authentication-module-setup-optional)

### 1. Why is the Android Lint _error_ `'InvalidPackage'` considered a _warning_?

When building the project with `build`, an error appeared regarding an `invalid package` on the `okio` dependency. This snippet is in the `build.gradle` file so that the build runs fine:

```gradle
android {
    //...
    lint {
       warning 'InvalidPackage'
    }
}
```

ref: https://github.com/square/okio/issues/58#issuecomment-72672263

### 2. Why do I need to declare Manifest Placeholders for the Auth0 domain and scheme?

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


### 3. Is the Web Authentication module setup optional?

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