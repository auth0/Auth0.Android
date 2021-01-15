# V2 Migration Guide

v2 of the Auth0 Android SDK includes a number of improvements to integrating Auth0 into your Android application, and contains breaking changes. Please review this guide to understand the changes required when migrating to v2.

## Requirements changes

v2 requires Android API version 21 or later.

## OIDC only

v2 only supports OIDC-Conformant applications. When using this SDK to authenticate users, only the current Auth0 authentication pipeline and endpoints will be used.
As a result, the `setOIDCConformant(boolean value)` method has been removed from the `Auth0` class.

You can learn more about the OpenID Connect Protocol [here](https://auth0.com/docs/protocols/openid-connect-protocol).

## Authorization Code with PKCE

Version 2 only supports the [Authorization Code with Proof Key for Code Exchange (PKCE)](https://auth0.com/docs/flows/authorization-code-flow-with-proof-key-for-code-exchange-pkce) flow. Accordingly, the `withResponseType(@ResponseType int type)` method on `WebAuthProvider.Builder` has been removed.

## Removal of WebView support

The deprecated ability to authenticate using a `WebView` component has been removed. External browser applications will always be used instead for increased security and user trust. Please refer to [this blog post](https://auth0.com/blog/google-blocks-oauth-requests-from-embedded-browsers/) for additional information.

## Removal of legacy Authentication API support

Methods and classes specific to calling any [Authentication APIs](https://auth0.com/docs/api/authentication) categorized as Legacy have been removed in v2. The detailed listing of the removals are documented below.

## Request interfaces changes

The `com.auth0.android.request` package defines the top-level interfaces for building and executing HTTP requests. Historically, a common issue has been the inability to add custom headers and request parameters to all request types. We've refactored the request interfaces to enable any request to be customized with additional headers and request parameters. Note that these parameters now need to be of type `String`.

The top-level `Request` interface now specifies the following methods:

- `public fun addParameters(parameters: Map<String, String>): Request<T, U>`
- `public fun addParameter(name: String, value: String): Request<T, U>`
- `public fun addHeader(name: String, value: String): Request<T, U>`

As a result, the following interfaces have been removed:

- `ParameterizableRequest`
- `AuthRequest`

`AuthenticationAPIClient` contains many changes to the return type of methods as a result. The full changes can be found below, but in summary:

- Any methods that returned a `ParameterizableRequest`, `TokenRequest`, or `DatabaseConnectionRequest`, now return a `Request`.
- Any method that returned a `AuthRequest` now returns an `AuthenticationRequest`.

If you are using the return type of any of these methods directly, you will need to change your code to expect the type as documented above. If you are chaining a call to `start` or `execute` to make the request, no changes are required.

The `AuthenticationRequest` interface no longer has a `setAccessToken("{ACCESS-TOKEN}")` method. This method was for setting the token to the request made to the [/oauth/access_token](https://auth0.com/docs/api/authentication#social-with-provider-s-access-token) Authentication API legacy endpoint, disabled as of June 2017. If you need to send a parameter with this name, please use `addParameter("access_token", "{ACCESS-TOKEN}")`.

Additionally, any classes that implemented `ParameterizableRequest` or `AuthRequest` have been updated to accommodate these changes, and are called out in the detailed changes listed below.

## Detailed change listing

### Files that changed their package
- The `com.auth0.android.authentication.request.ProfileRequest` class was moved to `com.auth0.android.request.ProfileRequest`
- The `com.auth0.android.authentication.request.SignUpRequest` class was moved to `com.auth0.android.request.SignUpRequest`

### Internal package
The previous version of this library used to expose a few classes in the `com.auth0.android.request.internal` package. These were never meant to be part of the library's Public API, and the direct usage of them was discouraged on the Javadocs. Since the codebase had migrated to Kotlin, we now take advantage of the `internal` modifier and use it were necessary. These classes might appear as `public` classes for Java projects but should still not be used, as they are still not part of this library's Public API. 

We will not provide support and will change these as required without any previous notice.   

### Classes and Interfaces removed

- The `com.auth0.android.util.Base64` class has been removed. Use `android.util.Base64` instead.
- The `com.auth0.android.request.ParameterizableRequest` interface has been removed. The ability to add request headers and parameters has been moved to the `com.auth0.android.request.Request` interface.
- The `com.auth0.android.request.AuthRequest` interface has been removed. The `com.auth0.android.request.AuthenticationRequest` interface can be used instead.
- The `com.auth0.android.provider.WebAuthActivity` class has been removed. External browser applications will always be used for authentication.
- The `com.auth0.android.result.Delegation` class has been removed. This was used as the result of the request to the [/delegation](https://auth0.com/docs/api/authentication#delegation) Authentication API legacy endpoint, disabled as of June 2017.
- The `com.auth0.android.authentication.request.DelegationRequest` class has been removed. This was used to represent the request to the legacy Authentication API [/delegation](https://auth0.com/docs/api/authentication#delegation) endpoint, disabled as of June 2017.
- The `com.auth0.android.util.Telemetry` class has been renamed to `com.auth0.android.util.Auth0UserAgent`.
- The `com.auth0.android.request.AuthorizableRequest` class has been removed. You can achieve the same result using `addHeader("Authorization", "Bearer {TOKEN_VALUE}")`.
- The `com.auth0.android.authentication.request.TokenRequest` class has been removed. The ability to set a Code Verifier, and any request headers and parameters has been moved to the `com.auth0.android.request.Request` interface.
- The `com.auth0.android.authentication.request.DatabaseConnectionRequest` class has been removed. The ability to set any request headers and parameters has been moved to the `com.auth0.android.request.Request` interface.
- The `com.auth0.android.provider.VoidCallback` class has been removed. The ability to use a callback that doesn't take an argument can be replaced with `Callback<Void, AuthenticationException>`.

### Constants removed

- `ParameterBuilder.GRANT_TYPE_JWT` has been removed.
- `ParameterBuilder.ID_TOKEN_KEY` has been removed.
- `ParameterBuilder.DEVICE_KEY` has been removed.
- `ParameterBuilder.ACCESS_TOKEN_KEY` has been removed.
- `ResponseType.CODE`, `ResponseType.ID_TOKEN`, and `ResponseType.ACCESS_TOKEN` have been removed.

### Classes and Interfaces changed

- `SignupRequest` now implements `AuthenticationRequest` instead of the now-removed `AuthRequest`
- `AuthorizableRequest` now extends `Request` instead of the now-removed `ParameterizableRequest`
- `BaseCallback` has been deprecated; use `Callback` instead.

### Constructors changed

- `AuthenticationAPIClient` can no longer be constructed from a `Context`. Use `AuthenticationAPIClient(auth0: Auth0)` instead. You can create an instance of `Auth0` using a `Context`.
- `UsersAPIClient` can no longer be constructed from a `Context`. Use UsersAPIClient(auth0: Auth0, token: String)` instead. You can create an instance of `Auth0` using a `Context`.
- `SignupRequest` now requires the second parameter to be an `AuthenticationRequest`.
- `ProfileRequest` now requires an `AuthenticationRequest` and a `Request<UserProfile, AuthenticationException>`.

### Methods removed or changed

#### `Auth0` methods removed

- `setOIDCConformant(boolean enabled)` and `isOIDCConformant()` have been removed. The SDK now only supports OIDC-Conformant applications.
- `doNotSendTelemetry()` has been removed. There is no replacement.
- `setWriteTimeoutInSeconds(seconds)` and `getWriteTimeoutInSeconds(seconds)` have been removed. There is no replacement; only connect and read timeouts can be configured.
- `setTLS12Enforced()` and `isTLS12Enforced()` have been removed. The SDK now supports modern TLS by default.

#### `AuthenticationAPIClient` methods removed or changed

Methods and classes specific to calling any [Authentication APIs](https://auth0.com/docs/api/authentication) categorized as Legacy have been removed in v2. The following methods have been removed:

- `delegation()`, `delegationWithIdToken("{ID-TOKEN}")`, `delegationWithRefreshToken("{REFRESH-TOKEN}")`, and `delegationWithIdToken("{ID-TOKEN}", "{API-TYPE}}")`. Support for Legacy Authentication API endpoints have been removed.
- `loginWithOAuthAccessToken("{TOKEN}", {CONNECTION})`. For selected social providers, you can use `loginWithNativeSocialToken("{TOKEN}", "{TOKEN-TYPE}")` instead.
- `tokenInfo("{ID-TOKEN}")`. Use `userInfo("{ACCESS-TOKEN}")` instead.

Methods that returned a `ParameterizableRequest` now return a `Request`:

- `userInfo("{ACCESS-TOKEN}")`
- `revokeToken("{REFRESH-TOKEN}")`
- `renewAuth("{REFRESH-TOKEN}")`
- `passwordlessWithEmail("{EMAIL}", PasswordlessType, "{CONNECTION}")`
- `passwordlessWithSMS("{PHONE-NUNBER}", PasswordlessType, "{CONNECTION}")`
- `fetchJsonWebKeys()`

Methods that returned an `AuthRequest` now return an `AuthenticationRequest`:

- `login("{USERNAME-OR-EMAIL}", "{PASSWORD}", "{REALM-OR-CONNECTION}")`
- `login("{USERNAME-OR-EMAIL}", "{PASSWORD}")`
- `loginWithOTP("{MFA-TOKEN}", "{OTP}")`
- `loginWithNativeSocialToken("{TOKEN}", "{TOKEN-TYPE}")`
- `loginWithPhoneNumber("{PHONE-NUMBER}", "{VERIFICATION-CODE}", "{REALM-OR-CONNECTION}")`
- `loginWithEmail("{EMAIL}", "{VERIFICATION-CODE}", "{REALM-OR-CONNECTION}")`

Methods that returned a `DatabaseConnectionRequest` now return a `Request`:

- `createUser("{EMAIL}", "{PASSWORD}", "{USERNAME}", "{CONNECTION}")`
- `resetPassword("{EMAIL}","{CONNECTION}")`

Methods that returned a `TokenRequest` now return a `Request`:

- `token("{AUTHORIZATION-CODE}", "{CODE-VERIFIER}", "{REDIRECT-URI}")`

#### `AuthenticationRequest` methods removed

- `addAuthenticationParameters(parameters)` has been removed. Use `addParameters(parameters)` instead.
- `setDevice("{DEVICE}")`. Use `addParameter("device", "{VALUE}")` instead.

#### `WebAuthProvider.Builder` methods removed

- `useCodeGrant(boolean useCodeGrant)`. There is no replacement; only Code + PKCE flow supported in v2.
- `useBrowser(boolean useBrowser)`. There is no replacement; this library no longer supports WebView authentication.
- `useFullscreen(boolean useFullscreen)`. There is no replacement; this library no longer supports WebView authentication.
- `withResponseType(@ResponseType int type)`. There is no replacement; only Code + PKCE flow supported in v2.
- `start(activity: Activity, callback: AuthCallback, requestCode: Int)` has been removed. Use `start(activity: Activity, callback: Callback<Credentials, AuthenticationException>)` instead.

#### `WebAuthProvider.LogoutBuilder` methods removed

- `start(context: Context, callback: VoidCallback)`. Use `start(context: Context, callback: Callback<Void, AuthenticationException>)` instead.

#### `WebAuthProvider` methods removed

- `init(account: Auth0)` has been removed. Use `login(account: Auth0)` instead.
- `init(context: Context)` has been removed. Use `login(account: Auth0)` instead.
- `resume(requestCode: Int, resultCode: Int, intent: Intent)` has been removed. Use `resume(intent: Intent)` instead.
- `init(account: Auth0)` has been removed. Use `login(account: Auth0)` instead.
- 
#### `ParameterBuilder` methods removed

- `setDevice("{DEVICE}")` has been removed. Use `set("device", "{VALUE}")` instead.

#### `UsersAPIClient` methods changed

Methods that returned a `ParameterizableRequest` now return a `Request`:

- `link("{PRIMARY-USER-ID}", "{SECONDARY-TOKEN}")`
- `unlink("{PRIMARY-USER-ID}", "{SECONDARY-USER-ID}", "{SECONDARY-PROVIDER}")`
- `updateMetadata("{USER-ID}", userMetadata)`
- `getProfile("{USER-ID}")`

#### `RequestFactory` methods removed or changed

The `RequestFactory` class contains methods to facilitate making HTTP requests, including the serialization and deserialization of the JSON request body and response. As part of the `com.auth0.android.request.internal` package, it is not intended for public use, but as a public type the summary of changes are documented below.

- All request methods have been refactored to be decoupled from a specific HTTP request library (e.g., `OkHttp`)
- All request methods now return a `Request`.
- All request methods are now lower-cased (e.g., `POST()` -> `post()`).
- The `authenticationPOST` method was removed without a replacement, as all `Request` instances can be parameterized with any headers as needed.

#### `ProfileRequest` methods changed

- The `addParameters` method now requires the value to be Map of String to String, instead of String to Object (`addParameters(mapOf("key" to "val"))`)

#### `SignUpRequest` methods changed

Methods that set parameters now requires the value to be a Map of String to String, instead of String to Object:

- `addAuthenticationParameters(mapOf("key" to "val"))`
- `addSignupParameters(mapOf("key" to "val"))`
- `addParameters(mapOf("key" to "val"))`

Additionally, `setDevice("device")` was removed. Use `addParameter("device", "{VALUE}")` instead.
