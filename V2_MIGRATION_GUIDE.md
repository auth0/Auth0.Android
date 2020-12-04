# V2 Migration Guide

> This document is a work-in-progress, and will be edited and amended as development on version 2 continues.

## Requirements changes

- Android API version 21 or later.

## Classes removed

- The `com.auth0.android.util.Base64` class has been removed. Use `android.util.Base64` instead.

## Constructors removed

- `public SignUpRequest(@NonNull DatabaseConnectionRequest<DatabaseUser, AuthenticationException> signUpRequest, @NonNull AuthenticationRequest authenticationRequest)`. Use `public SignUpRequest(@NonNull DatabaseConnectionRequest<DatabaseUser, AuthenticationException> signUpRequest, @NonNull AuthRequest authRequest)` instead.

## Methods removed

The following methods were removed in v2:

### AuthenticationAPIClient

- `public ParameterizableRequest<UserProfile, AuthenticationException> tokenInfo(@NonNull String idToken)`. Use `public ParameterizableRequest<UserProfile, AuthenticationException> userInfo(@NonNull String accessToken)` instead.

### WebAuthProvider

- `public static Builder init(@NonNull Auth0 account)`. Use `public static Builder login(@NonNull Auth0 account)` instead.
- `public static Builder init(@NonNull Context context)`. Use `public static Builder login(@NonNull Auth0 account)` instead.
- `public static boolean resume(int requestCode, int resultCode, @Nullable Intent intent)`. Use `public static boolean resume(@Nullable Intent intent)` instead.

### WebAuthProvider.Builder

- `public Builder useCodeGrant(boolean useCodeGrant)`. There is no replacement; only Code + PKCE flow supported in v2.
- `public Builder useBrowser(boolean useBrowser)`. There is no replacement; Google no longer supports WebView authentication.
- `public Builder useFullscreen(boolean useFullscreen)`. There is no replacement; Google no longer supports WebView authentication.
- `public void start(@NonNull Activity activity, @NonNull AuthCallback callback, int requestCode)`. Use `public void start(@NonNull Activity activity, @NonNull AuthCallback callback)` instead.    

