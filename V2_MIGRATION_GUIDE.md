# V2 Migration Guide

> This document is a work-in-progress, and will be edited and amended as development on version 2 continues.

## Requirements changes

- Android API version 21 or later.

## OIDC only

Version 2 only supports OIDC-Conformant applications. When using this SDK to authenticate users, only the current Auth0 authentication pipeline and endpoints will be used.

Previously, it was recommended to use OIDC-Conformant mode, by calling `setOIDCConformant(true)` on the `Auth0` class. This method has been removed, and the SDK now only supports OIDC-Conformant applications.

You can learn more about the OpenID Connect Protocol [here](https://auth0.com/docs/protocols/openid-connect-protocol).

## Authorization Code with PKCE

Version 2 only supports the [Authorization Code with Proof Key for Code Exchange (PKCE)](https://auth0.com/docs/flows/authorization-code-flow-with-proof-key-for-code-exchange-pkce) flow. Accordingly, the `withResponseType(@ResponseType int type)` method on `WebAuthProvider.Builder` has been removed.

## Removal of WebView support

The deprecated ability to sign using a WebView component has been removed. External browser applications will always be used instead for increased security and user trust. Please refer to [This blog post](https://auth0.com/blog/google-blocks-oauth-requests-from-embedded-browsers/) for additional information.

## Request interfaces changes

The `com.auth0.android.request` package defines the top-level interfaces for building and executing HTTP requests. Historically, a common issue has been the inability to add custom headers and request parameters to all request types. We've refactored the request interfaces to enable any request to be customized with additional headers and request parameters. Note that these parameters now need to be of type String.

The top-level `com.auth0.android.request.Request` interface now specifies the following methods:

- `Request<T, U> addParameters(@NonNull Map<String, String> parameters)`
- `Request<T, U> addParameter(@NonNull String name, @NonNull String value)`
- `Request<T, U> addHeader(@NonNull String name, @NonNull String value)`

As a result, the following interfaces have been removed:

- `com.auth0.android.request.ParameterizableRequest`
- `com.auth0.android.request.AuthRequest`

The `com.auth0.android.authentication.AuthenticationAPIClient` contains many changes to the return type of methods as a result. The full changes can be found below, but in summary:

- Any method that returned a `ParameterizableRequest` now returns a `Request`.
- Any method that returned a `TokenRequest` now returns a `Request`.
- Any method that returned a `AuthRequest` now returns an `AuthenticationRequest`.

If you are using the return type of any of these methods directly, you will need to change your code to expect the type as documented above. If you are chaining a call to `start` or `execute` to make the request, no changes are required.

The `AuthenticationRequest` interface no longer has a `AuthenticationRequest setAccessToken(@NonNull String accessToken)` method. This method was for setting the token to the request made to the [/oauth/access_token](https://auth0.com/docs/api/authentication#social-with-provider-s-access-token) Authentication API legacy endpoint, disabled as of June 2017. If you need to send a parameter with this name, please use the `addParameter("access_token", value)` method.

Additionally, any classes that implemented `ParameterizableRequest` or `AuthRequest` have been updated to accommodate these changes, and are called out in the detailed changes listed below.

## Detailed change listing

### Classes removed

- The `com.auth0.android.util.Base64` class has been removed. Use `android.util.Base64` instead.
- The `com.auth0.android.request.ParameterizableRequest` interface has been removed. The ability to add request headers and parameters has been moved to the `com.auth0.android.request.Request` interface.
- The `com.auth0.android.request.AuthRequest` interface has been removed. The `com.auth0.android.request.AuthenticationRequest` interface can be used instead.
- The `com.auth0.android.provider.WebAuthActivity` class has been removed. External browser applications will always be used for authentication.
- The `com.auth0.android.result.Delegation` class has been removed. This was used as the result of the request to the [/delegation](https://auth0.com/docs/api/authentication#delegation) Authentication API legacy endpoint, disabled as of June 2017.
- The `com.auth0.android.authentication.request.DelegationRequest` class has been removed. This was used to represent the request to the legacy Authentication API [/delegation](https://auth0.com/docs/api/authentication#delegation) endpoint, disabled as of June 2017.
- The `com.auth0.android.util.Telemetry` class has been renamed to `com.auth0.android.util.Auth0UserAgent`.
- The `com.auth0.android.request.AuthorizableRequest` class has been removed. You can achieve the same result using the method in Request: `Request#addHeader("Authorization", "Bearer TOKEN_VALUE")`.
- The `com.auth0.android.authentication.request.TokenRequest` class has been removed. The ability to set a Code Verifier, and any request headers and parameters has been moved to the `com.auth0.android.request.Request` interface.
- The `com.auth0.android.authentication.request.DatabaseConnectionRequest` class has been removed. The ability to set any request headers and parameters has been moved to the `com.auth0.android.request.Request` interface.

### Class changes

- `SignupRequest` now implements `AuthenticationRequest` instead of the now-removed `AuthRequest`
- `AuthorizableRequest` now extends `Request` instead of the now-removed `ParameterizableRequest`
- `BaseCallback` has been deprecated; use `Callback` instead.

### Constructors removed or changed

#### AuthenticationAPIClient

- `public AuthenticationAPIClient(@NonNull Context context)`. Use `public AuthenticationAPIClient(new Auth0(context))`.

#### UsersAPIClient

- `public UsersAPIClient(@NonNull Context context, @NonNull String token)`. Use `public UsersAPIClient(new Auth0(context), token)`.

#### SignupRequest

- `public SignUpRequest(@NonNull DatabaseConnectionRequest<DatabaseUser, AuthenticationException> signUpRequest, @NonNull AuthRequest authRequest)`. Use `public SignUpRequest(@NonNull DatabaseConnectionRequest<DatabaseUser, AuthenticationException> signUpRequest, @NonNull AuthenticationRequest authenticationRequest)` instead.

#### ProfileRequest

- `public ProfileRequest(@NonNull AuthenticationRequest authenticationRequest, @NonNull ParameterizableRequest<UserProfile, AuthenticationException> userInfoRequest)`. Use `public ProfileRequest(@NonNull AuthenticationRequest authenticationRequest, @NonNull Request<UserProfile, AuthenticationException> userInfoRequest)` instead
- `public ProfileRequest(@NonNull AuthRequest authRequest, @NonNull ParameterizableRequest<UserProfile, AuthenticationException> userInfoRequest)`. Use `public ProfileRequest(@NonNull AuthenticationRequest authRequest, @NonNull Request<UserProfile, AuthenticationException> userInfoRequest)` instead.

#### DatabaseConnectionTest

- `public DatabaseConnectionRequest(@NonNull ParameterizableRequest<T, U> request)`. Use `public DatabaseConnectionRequest(@NonNull Request<T, U> request)` instead.
- `public DelegationRequest(@NonNull ParameterizableRequest<T, AuthenticationException> request)`. Use `public DelegationRequest(@NonNull Request<T, AuthenticationException> request)` instead.

### Methods added

#### SignUpRequest

- `public SignUpRequest addParameters(@NonNull Map<String, String> parameters)`
- `public SignUpRequest addParameter(@NonNull String name, @NonNull String value)`

#### ProfileRequest

- `public ProfileRequest addParameter(@NonNull String name, @NonNull String value)`

### Methods removed or changed

#### ParameterBuilder

- `public ParameterBuilder setDevice(@NonNull String device)`. Please use `public ParameterBuilder set("device", value)`.

#### Auth0

- `public void setOIDCConformant(boolean enabled)`. The SDK now only supports OIDC-Conformant applications.
- `public boolean isOIDCConformant()`. The SDK now only supports OIDC-Conformant applications.
- `public void doNotSendTelemetry()` has been removed. There is no replacement.

#### AuthenticationAPIClient

- `public ParameterizableRequest<UserProfile, AuthenticationException> tokenInfo(@NonNull String idToken)`. Use `public ParameterizableRequest<UserProfile, AuthenticationException> userInfo(@NonNull String accessToken)` instead.
- `public ParameterizableRequest<UserProfile, AuthenticationException> userInfo(@NonNull String accessToken)`. Use `public Request<UserProfile, AuthenticationException> userInfo(@NonNull String accessToken)` instead.
- `public ParameterizableRequest<Void, AuthenticationException> revokeToken(@NonNull String refreshToken)`. Use `public Request<Void, AuthenticationException> revokeToken(@NonNull String refreshToken)` instead.
- `public ParameterizableRequest<Credentials, AuthenticationException> renewAuth(@NonNull String refreshToken)`. Use `public Request<Credentials, AuthenticationException> renewAuth(@NonNull String refreshToken)` instead.
- `public ParameterizableRequest<Void, AuthenticationException> passwordlessWithEmail(@NonNull String email, @NonNull PasswordlessType passwordlessType, @NonNull String connection)`. Use `public Request<Void, AuthenticationException> passwordlessWithEmail(@NonNull String email, @NonNull PasswordlessType passwordlessType, @NonNull String connection)` instead.
- `public ParameterizableRequest<Void, AuthenticationException> passwordlessWithEmail(@NonNull String email, @NonNull PasswordlessType passwordlessType)`. Use `public Request<Void, AuthenticationException> passwordlessWithEmail(@NonNull String email, @NonNull PasswordlessType passwordlessType)` instead.
- `public ParameterizableRequest<Void, AuthenticationException> passwordlessWithSMS(@NonNull String phoneNumber, @NonNull PasswordlessType passwordlessType, @NonNull String connection)`. Use `public Request<Void, AuthenticationException> passwordlessWithSMS(@NonNull String phoneNumber, @NonNull PasswordlessType passwordlessType, @NonNull String connection)` instead.
- `public ParameterizableRequest<Void, AuthenticationException> passwordlessWithSMS(@NonNull String phoneNumber, @NonNull PasswordlessType passwordlessType)`. Use `public Request<Void, AuthenticationException> passwordlessWithSMS(@NonNull String phoneNumber, @NonNull PasswordlessType passwordlessType)` instead.
- `public ParameterizableRequest<Map<String, PublicKey>, AuthenticationException> fetchJsonWebKeys()`. Use `public Request<Map<String, PublicKey>, AuthenticationException> fetchJsonWebKeys()` instead.
- `public AuthRequest login(@NonNull String usernameOrEmail, @NonNull String password, @NonNull String realmOrConnection)`. Use `public AuthenticationRequest login(@NonNull String usernameOrEmail, @NonNull String password, @NonNull String realmOrConnection)` instead.
- `public AuthRequest login(@NonNull String usernameOrEmail, @NonNull String password)`. Use `public AuthenticationRequest login(@NonNull String usernameOrEmail, @NonNull String password)` instead.
- `public AuthRequest loginWithOTP(@NonNull String mfaToken, @NonNull String otp)`. Use `public AuthenticationRequest loginWithOTP(@NonNull String mfaToken, @NonNull String otp)` instead.
- `public AuthRequest loginWithOAuthAccessToken(@NonNull String token, @NonNull String connection)`. Use `public AuthenticationRequest loginWithOAuthAccessToken(@NonNull String token, @NonNull String connection)` instead.
- `public AuthRequest loginWithNativeSocialToken(@NonNull String token, @NonNull String tokenType)`. Use `public AuthenticationRequest loginWithNativeSocialToken(@NonNull String token, @NonNull String tokenType)` instead.
- `public AuthRequest loginWithPhoneNumber(@NonNull String phoneNumber, @NonNull String verificationCode, @NonNull String realmOrConnection)`. Use `public AuthenticationRequest loginWithPhoneNumber(@NonNull String phoneNumber, @NonNull String verificationCode, @NonNull String realmOrConnection)` instead.
- `public AuthRequest loginWithPhoneNumber(@NonNull String phoneNumber, @NonNull String verificationCode)`. Use `public AuthenticationRequest loginWithPhoneNumber(@NonNull String phoneNumber, @NonNull String verificationCode)` instead.
- `public AuthRequest loginWithEmail(@NonNull String email, @NonNull String verificationCode, @NonNull String realmOrConnection)`. Use `public AuthenticationRequest loginWithEmail(@NonNull String email, @NonNull String verificationCode, @NonNull String realmOrConnection)` instead.
- `public AuthRequest loginWithEmail(@NonNull String email, @NonNull String verificationCode)`. Use `public AuthenticationRequest loginWithEmail(@NonNull String email, @NonNull String verificationCode)` instead.
- `public TokenRequest token(@NonNull String authorizationCode, @NonNull String redirectUri)`. Use `public Request<Credentials, AuthenticationException> token(@NonNull String authorizationCode, @NonNull String codeVerifier, @NonNull String redirectUri)` instead.
- `public DatabaseConnectionRequest<DatabaseUser, AuthenticationException> createUser(@NonNull String email, @NonNull String password, @Nullable String username, @NonNull String connection)`. Use `public Request<DatabaseUser, AuthenticationException> createUser(@NonNull String email, @NonNull String password, @Nullable String username, @NonNull String connection)` instead.
- `public DatabaseConnectionRequest<DatabaseUser, AuthenticationException> createUser(@NonNull String email, @NonNull String password, @NonNull String connection)`. Use `public Request<DatabaseUser, AuthenticationException> createUser(@NonNull String email, @NonNull String password, @NonNull String connection)` instead.
- `public DatabaseConnectionRequest<Void, AuthenticationException> resetPassword(@NonNull String email, @NonNull String connection)`. Use `public Request<Void, AuthenticationException> resetPassword(@NonNull String email, @NonNull String connection)` instead.

##### Social Provider's Access Token Exchange
The ability to exchange a third-party provider access token for Auth0 access tokens is part of the [/oauth/access_token](https://auth0.com/docs/api/authentication#social-with-provider-s-access-token) Authentication API legacy endpoint, disabled as of June 2017. The method below was removed because of this.
- `public AuthenticationRequest loginWithOAuthAccessToken(@NonNull String token, @NonNull String connection)`.

For selected social providers, there's support for a similar token exchange using the ["Native Social" token exchange](https://auth0.com/docs/api/authentication#token-exchange-for-native-social) endpoint.
- `public AuthenticationRequest loginWithNativeSocialToken(@NonNull String token, @NonNull String tokenType)`

##### Delegation
The ability to make requests to the [/delegation](https://auth0.com/docs/api/authentication#delegation) Authentication API legacy endpoint is disabled server-side as of June 2017. The methods listed below were removed because of this.

- `public ParameterizableRequest<Map<String, Object>, AuthenticationException> delegation()`.
- `public DelegationRequest<Delegation> delegationWithIdToken(@NonNull String idToken)`.
- `public DelegationRequest<Delegation> delegationWithRefreshToken(@NonNull String refreshToken)`.
- `public DelegationRequest<Map<String, Object>> delegationWithIdToken(@NonNull String idToken, @NonNull String apiType)`.

#### WebAuthProvider

- `public static Builder init(@NonNull Auth0 account)`. Use `public static Builder login(@NonNull Auth0 account)` instead.
- `public static Builder init(@NonNull Context context)`. Use `public static Builder login(@NonNull Auth0 account)` instead.
- `public static boolean resume(int requestCode, int resultCode, @Nullable Intent intent)`. Use `public static boolean resume(@Nullable Intent intent)` instead.
- `public static Builder init(@NonNull Auth0 account)`. Use `public static Builder login(@NonNull Auth0 account)` instead.

#### WebAuthProvider.Builder

- `public Builder useCodeGrant(boolean useCodeGrant)`. There is no replacement; only Code + PKCE flow supported in v2.
- `public Builder useBrowser(boolean useBrowser)`. There is no replacement; Google no longer supports WebView authentication.
- `public Builder useFullscreen(boolean useFullscreen)`. There is no replacement; Google no longer supports WebView authentication.
- `public void start(@NonNull Activity activity, @NonNull AuthCallback callback, int requestCode)`. Use `public void start(@NonNull Activity activity, @NonNull Callback<Credentials, AuthenticationException> callback)` instead.
- `public Builder withResponseType(@ResponseType int type)`. There is no replacement; only Code + PKCE flow supported in v2.

#### WebAuthProvider.LogoutBuilder

- `public void start(@NonNull Context context, @NonNull VoidCallback callback)`. Use `public void start(@NonNull Context context, @NonNull Callback<Void, AuthenticationException> callback)` instead.

#### UsersAPIClient

- `public ParameterizableRequest<List<UserIdentity>, ManagementException> link(@NonNull String primaryUserId, @NonNull String secondaryToken)`. Use `public Request<List<UserIdentity>, ManagementException> link(@NonNull String primaryUserId, @NonNull String secondaryToken)` instead.
- `public ParameterizableRequest<List<UserIdentity>, ManagementException> unlink(@NonNull String primaryUserId, @NonNull String secondaryUserId, @NonNull String secondaryProvider)`. Use `public Request<List<UserIdentity>, ManagementException> unlink(@NonNull String primaryUserId, @NonNull String secondaryUserId, @NonNull String secondaryProvider)` instead.
- `public ParameterizableRequest<UserProfile, ManagementException> updateMetadata(@NonNull String userId, @NonNull Map<String, Object> userMetadata)`. Use `public Request<UserProfile, ManagementException> updateMetadata(@NonNull String userId, @NonNull Map<String, Object> userMetadata)` instead.
- `public ParameterizableRequest<UserProfile, ManagementException> getProfile(@NonNull String userId)`. Use `public Request<UserProfile, ManagementException> getProfile(@NonNull String userId)` instead.

#### RequestFactory

- `public <T, U extends Auth0Exception> ParameterizableRequest<T, U> POST(@NonNull HttpUrl url, @NonNull OkHttpClient client, @NonNull Gson gson, @NonNull Class<T> clazz, @NonNull ErrorBuilder<U> errorBuilder) `. Use `public <T, U extends Auth0Exception> Request<T, U> POST(@NonNull HttpUrl url, @NonNull OkHttpClient client, @NonNull Gson gson, @NonNull Class<T> clazz, @NonNull ErrorBuilder<U> errorBuilder)` instead.
- `public <T, U extends Auth0Exception> ParameterizableRequest<T, U> POST(@NonNull HttpUrl url, @NonNull OkHttpClient client, @NonNull Gson gson, @NonNull TypeToken<T> typeToken, @NonNull ErrorBuilder<U> errorBuilder)`. Use `public <T, U extends Auth0Exception> Request<T, U> POST(@NonNull HttpUrl url, @NonNull OkHttpClient client, @NonNull Gson gson, @NonNull TypeToken<T> typeToken, @NonNull ErrorBuilder<U> errorBuilder)` instead.
- `public <U extends Auth0Exception> ParameterizableRequest<Map<String, Object>, U> rawPOST(@NonNull HttpUrl url, @NonNull OkHttpClient client, @NonNull Gson gson, @NonNull ErrorBuilder<U> errorBuilder)`. Use `public <U extends Auth0Exception> Request<Map<String, Object>, U> rawPOST(@NonNull HttpUrl url, @NonNull OkHttpClient client, @NonNull Gson gson, @NonNull ErrorBuilder<U> errorBuilder)` instead.
- `public <U extends Auth0Exception> ParameterizableRequest<Void, U> POST(@NonNull HttpUrl url, @NonNull OkHttpClient client, @NonNull Gson gson, @NonNull ErrorBuilder<U> errorBuilder)`. Use `public <U extends Auth0Exception> Request<Void, U> POST(@NonNull HttpUrl url, @NonNull OkHttpClient client, @NonNull Gson gson, @NonNull ErrorBuilder<U> errorBuilder)` instead.
- `public <T, U extends Auth0Exception> ParameterizableRequest<T, U> PATCH(@NonNull HttpUrl url, @NonNull OkHttpClient client, @NonNull Gson gson, @NonNull Class<T> clazz, @NonNull ErrorBuilder<U> errorBuilder)`. Use ` public <T, U extends Auth0Exception> Request<T, U> PATCH(@NonNull HttpUrl url, @NonNull OkHttpClient client, @NonNull Gson gson, @NonNull Class<T> clazz, @NonNull ErrorBuilder<U> errorBuilder)` instead.
- `public <T, U extends Auth0Exception> ParameterizableRequest<T, U> DELETE(@NonNull HttpUrl url, @NonNull OkHttpClient client, @NonNull Gson gson, @NonNull TypeToken<T> typeToken, @NonNull ErrorBuilder<U> errorBuilder)`. Use `public <T, U extends Auth0Exception> Request<T, U> DELETE(@NonNull HttpUrl url, @NonNull OkHttpClient client, @NonNull Gson gson, @NonNull TypeToken<T> typeToken, @NonNull ErrorBuilder<U> errorBuilder)` instead.
- `public <T, U extends Auth0Exception> ParameterizableRequest<T, U> GET(@NonNull HttpUrl url, @NonNull OkHttpClient client, @NonNull Gson gson, @NonNull Class<T> clazz, @NonNull ErrorBuilder<U> errorBuilder)`. Use `public <T, U extends Auth0Exception> Request<T, U> GET(@NonNull HttpUrl url, @NonNull OkHttpClient client, @NonNull Gson gson, @NonNull Class<T> clazz, @NonNull ErrorBuilder<U> errorBuilder)` instead.
- `public <T, U extends Auth0Exception> ParameterizableRequest<T, U> GET(@NonNull HttpUrl url, @NonNull OkHttpClient client, @NonNull Gson gson, @NonNull TypeToken<T> typeToken, @NonNull ErrorBuilder<U> errorBuilder)`. Use `public <T, U extends Auth0Exception> Request<T, U> GET(@NonNull HttpUrl url, @NonNull OkHttpClient client, @NonNull Gson gson, @NonNull TypeToken<T> typeToken, @NonNull ErrorBuilder<U> errorBuilder)` instead.
- `public AuthRequest authenticationPOST(@NonNull HttpUrl url, @NonNull OkHttpClient client, @NonNull Gson gson)`. Use `public AuthRequest authenticationPOST(@NonNull HttpUrl url, @NonNull OkHttpClient client, @NonNull Gson gson)` instead.

#### DatabaseConnectionRequest
- `public DatabaseConnectionRequest<T, U> addParameters(@NonNull Map<String, Object> parameters)`. Use `public DatabaseConnectionRequest<T, U> addParameters(@NonNull Map<String, String> parameters)` instead.
- `public DatabaseConnectionRequest<T, U> addParameter(@NonNull String name, @NonNull String value)`. Use `public DatabaseConnectionRequest<T, U> addParameter(@NonNull String name, @NonNull String value)` instead.

#### DelegationRequest
- `public DelegationRequest<T> addParameters(@NonNull Map<String, Object> parameters)`. Use `public DelegationRequest<T> addParameters(@NonNull Map<String, String> parameters)` instead.
- `public DelegationRequest<T> addParameter(@NonNull String name, @NonNull String value)`. Use `public DelegationRequest<T> addParameter(@NonNull String name, @NonNull String value)` instead.

#### ProfileRequest
- `public ProfileRequest addParameters(@NonNull Map<String, Object> parameters)`. Use `public ProfileRequest addParameters(@NonNull Map<String, String> parameters)` instead.
- `public ProfileRequest addParameter(@NonNull String name, @NonNull String value)`. Use `public ProfileRequest addParameter(@NonNull String name, @NonNull String value)` instead.

#### SignUpRequest
- `public SignUpRequest addAuthenticationParameters(@NonNull Map<String, Object> parameters)`. Use `public SignUpRequest addAuthenticationParameters(@NonNull Map<String, String> parameters)` instead.
- `public SignUpRequest addSignUpParameters(@NonNull Map<String, Object> parameters)`. Use `public SignUpRequest addSignUpParameters(@NonNull Map<String, String> parameters)` instead.
- `public SignUpRequest addParameters(@NonNull Map<String, Object> parameters)`. Use `public SignUpRequest addParameters(@NonNull Map<String, String> parameters)` instead.
- `public SignUpRequest addParameter(@NonNull String name, @NonNull String value)`. Use `public SignUpRequest addParameter(@NonNull String name, @NonNull String value)` instead.
- `public SignUpRequest setDevice(@NonNull String device)`. Use `public Request<Credentials, AuthenticationException> addParameter("device", value)` instead.

#### AuthenticationRequest
- `public AuthenticationRequest addAuthenticationParameters(@NonNull Map<String, String> parameters)`. Use `public Request<Credentials, AuthenticationException> addParameters(@NonNull Map<String, String> parameters)` instead.
- `public AuthenticationRequest setDevice(@NonNull String device)`. Use `public Request<Credentials, AuthenticationException> addParameter("device", value)` instead.

### Constants removed

- `ParameterBuilder.GRANT_TYPE_JWT` has been removed.
- `ParameterBuilder.ID_TOKEN_KEY` has been removed.
- `ParameterBuilder.DEVICE_KEY` has been removed.
- `ParameterBuilder.ACCESS_TOKEN_KEY` has been removed.
- `ResponseType.CODE`, `ResponseType.ID_TOKEN`, and `ResponseType.ACCESS_TOKEN` have been removed.
