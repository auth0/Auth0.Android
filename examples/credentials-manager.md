## Credentials Manager

### Secure Credentials Manager

This version adds encryption to the data storage. Additionally, in those devices where a Secure Lock Screen has been configured it can require the user to authenticate before letting them obtain the stored credentials. The class is called `SecureCredentialsManager`.

#### Usage

`SecureCredentialsManager` requires an `AuthenticationAPIClient` instance. The manager uses the supplied client for all token renewals and DPoP-bound refreshes, so configure that client first and then pass the same instance into `SecureCredentialsManager`. Create one from your `Auth0` configuration object and pass it to the manager:

```kotlin
val account = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN")
val apiClient = AuthenticationAPIClient(account)
val storage = SharedPreferencesStorage(this)
val manager = SecureCredentialsManager(apiClient, this, storage)
```

<details>
  <summary>Using Java</summary>

```java
Auth0 account = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN");
AuthenticationAPIClient apiClient = new AuthenticationAPIClient(account);
Storage storage = new SharedPreferencesStorage(this);
SecureCredentialsManager manager = new SecureCredentialsManager(apiClient, this, storage);
```
</details>

To configure the `AuthenticationAPIClient` with advanced features such as DPoP, set them up on the client before passing it in:

```kotlin
val auth0 = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN")
val apiClient = AuthenticationAPIClient(auth0).useDPoP(this)
val storage = SharedPreferencesStorage(this)
val manager = SecureCredentialsManager(apiClient, this, storage)
```

<details>
  <summary>Using Java</summary>

```java
Auth0 auth0 = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN");
AuthenticationAPIClient apiClient = new AuthenticationAPIClient(auth0).useDPoP(this);
Storage storage = new SharedPreferencesStorage(this);
SecureCredentialsManager manager = new SecureCredentialsManager(apiClient, this, storage);
```
</details>

#### Requiring Authentication

You can require the user authentication to obtain credentials. This will make the manager prompt the user with the device's configured Lock Screen, which they must pass correctly in order to obtain the credentials. **This feature is only available on devices where the user has setup a secured Lock Screen** (PIN, Pattern, Password or Fingerprint).

To enable authentication you must supply an instance of `FragmentActivity` on which the authentication prompt to be shown, and an instance of `LocalAuthenticationOptions` to configure the authentication prompt with details like title and authentication level when creating an instance of `SecureCredentialsManager` as shown in the snippet below.

```kotlin
val localAuthenticationOptions =
    LocalAuthenticationOptions.Builder().setTitle("Authenticate").setDescription("Accessing Credentials")
        .setAuthenticationLevel(AuthenticationLevel.STRONG).setNegativeButtonText("Cancel")
        .setDeviceCredentialFallback(true)
        .setPolicy(BiometricPolicy.Session(300)) // Optional: Use session-based policy (5 minutes)
        .build()
val account = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN")
val apiClient = AuthenticationAPIClient(account)
val storage = SharedPreferencesStorage(this)
val manager = SecureCredentialsManager(
    apiClient, this, storage, fragmentActivity,
    localAuthenticationOptions
)
```

<details>
  <summary>Using Java</summary>

```java
LocalAuthenticationOptions localAuthenticationOptions =
        new LocalAuthenticationOptions.Builder().setTitle("Authenticate").setDescription("Accessing Credentials")
                .setAuthenticationLevel(AuthenticationLevel.STRONG).setNegativeButtonText("Cancel")
                .setDeviceCredentialFallback(true)
                .setPolicy(new BiometricPolicy.Session(300)) // Optional: Use session-based policy (5 minutes)
                .build();
Auth0 account = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN");
AuthenticationAPIClient apiClient = new AuthenticationAPIClient(account);
Storage storage = new SharedPreferencesStorage(context);
SecureCredentialsManager secureCredentialsManager = new SecureCredentialsManager(
        apiClient, context, storage, fragmentActivity,
        localAuthenticationOptions);
```
</details>

You can also combine biometric authentication with a custom `AuthenticationAPIClient`:

```kotlin
val auth0 = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN")
val apiClient = AuthenticationAPIClient(auth0).useDPoP(this)
val localAuthenticationOptions =
    LocalAuthenticationOptions.Builder()
        .setTitle("Authenticate")
        .setDescription("Accessing Credentials")
        .setAuthenticationLevel(AuthenticationLevel.STRONG)
        .setNegativeButtonText("Cancel")
        .setDeviceCredentialFallback(true)
        .setPolicy(BiometricPolicy.Session(300))
        .build()
val storage = SharedPreferencesStorage(this)
val manager = SecureCredentialsManager(
    apiClient, this, storage, fragmentActivity,
    localAuthenticationOptions
)
```

<details>
  <summary>Using Java</summary>

```java
Auth0 auth0 = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN");
AuthenticationAPIClient apiClient = new AuthenticationAPIClient(auth0).useDPoP(this);
LocalAuthenticationOptions localAuthenticationOptions =
        new LocalAuthenticationOptions.Builder()
                .setTitle("Authenticate")
                .setDescription("Accessing Credentials")
                .setAuthenticationLevel(AuthenticationLevel.STRONG)
                .setNegativeButtonText("Cancel")
                .setDeviceCredentialFallback(true)
                .setPolicy(new BiometricPolicy.Session(300))
                .build();
Storage storage = new SharedPreferencesStorage(this);
SecureCredentialsManager secureCredentialsManager = new SecureCredentialsManager(
        apiClient, this, storage, fragmentActivity,
        localAuthenticationOptions);
```
</details>

**Points to be Noted**:

On Android API 29 and below, specifying **DEVICE_CREDENTIAL** alone as the authentication level is not supported.
On Android API 28 and 29, specifying **STRONG** as the authentication level along with enabling device credential fallback is not supported.


#### Creating LocalAuthenticationOptions object for requiring Authentication while using SecureCredentialsManager

`LocalAuthenticationOptions` class exposes a Builder class to create an instance of it. Details about the methods are explained below:

- **setTitle(title: String): Builder** - Sets the title to be displayed in the Authentication Prompt.
- **setSubTitle(subtitle: String?): Builder** - Sets the subtitle of the Authentication Prompt.
- **setDescription(description: String?): Builder** - Sets the description for the Authentication Prompt.
- **setAuthenticationLevel(authenticationLevel: AuthenticationLevel): Builder** - Sets the authentication level, more on this can be found [here](#authenticationlevel-enum-values)
- **setDeviceCredentialFallback(enableDeviceCredentialFallback: Boolean): Builder** - Enables/disables device credential fallback.
- **setNegativeButtonText(negativeButtonText: String): Builder** - Sets the negative button text, used only when the device credential fallback is disabled (or) the authentication level is not set to `AuthenticationLevel.DEVICE_CREDENTIAL`.
- **setPolicy(policy: BiometricPolicy): Builder** - Sets the biometric policy that controls when biometric authentication is required. See [BiometricPolicy Types](#biometricpolicy-types) for more details.
- **build(): LocalAuthenticationOptions** - Constructs the LocalAuthenticationOptions instance.


#### AuthenticationLevel Enum Values

AuthenticationLevel is an enum that defines the different levels of authentication strength required for local authentication mechanisms.

**Enum Values**:
- **STRONG**: Any biometric (e.g., fingerprint, iris, or face) on the device that meets or exceeds the requirements for Class 3 (formerly Strong).
- **WEAK**: Any biometric (e.g., fingerprint, iris, or face) on the device that meets or exceeds the requirements for Class 2 (formerly Weak), as defined by the Android CDD.
- **DEVICE_CREDENTIAL**: The non-biometric credential used to secure the device (i.e., PIN, pattern, or password).


#### BiometricPolicy Types

BiometricPolicy controls when biometric authentication is required when accessing stored credentials. There are three types of policies available:

**Policy Types**:
- **BiometricPolicy.Always**: Requires biometric authentication every time credentials are accessed. This is the default policy and provides the highest security level.
- **BiometricPolicy.Session(timeoutInSeconds)**: Requires biometric authentication only if the specified time (in seconds) has passed since the last successful authentication. Once authenticated, subsequent access within the timeout period will not require re-authentication.
- **BiometricPolicy.AppLifecycle(timeoutInSeconds = 3600)**: Similar to Session policy, but the session persists for the lifetime of the app process. The default timeout is 1 hour (3600 seconds).

**Examples**:

```kotlin
// Always require biometric authentication (default)
val alwaysPolicy = LocalAuthenticationOptions.Builder()
    .setTitle("Authenticate")
    .setAuthenticationLevel(AuthenticationLevel.STRONG)
    .setPolicy(BiometricPolicy.Always)
    .build()

// Require authentication only once per 5-minute session
val sessionPolicy = LocalAuthenticationOptions.Builder()
    .setTitle("Authenticate")
    .setAuthenticationLevel(AuthenticationLevel.STRONG)
    .setPolicy(BiometricPolicy.Session(300)) // 5 minutes
    .build()

// Require authentication once per app lifecycle (1 hour default)
val appLifecyclePolicy = LocalAuthenticationOptions.Builder()
    .setTitle("Authenticate")
    .setAuthenticationLevel(AuthenticationLevel.STRONG)
    .setPolicy(BiometricPolicy.AppLifecycle()) // Default: 3600 seconds (1 hour)
    .build()
```

<details>
  <summary>Using Java</summary>

```java
// Always require biometric authentication (default)
LocalAuthenticationOptions alwaysPolicy = new LocalAuthenticationOptions.Builder()
    .setTitle("Authenticate")
    .setAuthenticationLevel(AuthenticationLevel.STRONG)
    .setPolicy(BiometricPolicy.Always.INSTANCE)
    .build();

// Require authentication only once per 5-minute session  
LocalAuthenticationOptions sessionPolicy = new LocalAuthenticationOptions.Builder()
    .setTitle("Authenticate")
    .setAuthenticationLevel(AuthenticationLevel.STRONG)
    .setPolicy(new BiometricPolicy.Session(300)) // 5 minutes
    .build();

// Require authentication once per app lifecycle (default 1 hour)
LocalAuthenticationOptions appLifecyclePolicy = new LocalAuthenticationOptions.Builder()
    .setTitle("Authenticate")
    .setAuthenticationLevel(AuthenticationLevel.STRONG)
    .setPolicy(new BiometricPolicy.AppLifecycle()) // Default: 3600 seconds
    .build();
```
</details>

**Managing Biometric Sessions**:

You can manually clear the biometric session to force re-authentication on the next credential access:

```kotlin
// Clear the biometric session
secureCredentialsManager.clearBiometricSession()

// Check if the current session is valid
val isValid = secureCredentialsManager.isBiometricSessionValid()
```


### Other Credentials

#### API credentials

When the user logs in, you can request an access token for a specific API by passing its API identifier as the [audience](web-auth-configuration.md#specify-audience) value. The access token in the resulting credentials can then be used to make authenticated requests to that API.

However, if you need an access token for a different API, you can exchange the [refresh token](https://auth0.com/docs/secure/tokens/refresh-tokens) for credentials containing an access token specific to this other API.

> [!IMPORTANT]
> Currently, only the Auth0 My Account API is supported. Support for other APIs will be added in the future.

```kotlin

credentialsManager.getApiCredentials(
    audience = "https://example.com/me", scope = " create:me:authentication_methods",
    callback = object : Callback<APICredentials, CredentialsManagerException> {
        override fun onSuccess(result: APICredentials) {
            print("Obtained API credentials: $result")
        }

        override fun onFailure(error: CredentialsManagerException) {
            print("Failed with: $error")
        }
    })

```

<details>
  <summary>Using Coroutines</summary>

```kotlin

  try {
          val result =   credentialsManager.awaitApiCredentials(
                audience = "https://example.com/me",
                scope = "create:me:authentication_methods"
            )
            print("Obtained API credentials: $result")
        } catch (error: CredentialsManagerException) {
            print("Failed with: $error")
        }

```

</details>

<details>
    <summary>Using Java</summary>

```java

credentialsManager.getApiCredentials("audience",
                "scope",
                0,
                new HashMap<>(),
                new HashMap<>(),
                new Callback<APICredentials, CredentialsManagerException>() {
                    @Override
                    public void onSuccess(APICredentials result) {
                        System.out.println(result);
                    }

                    @Override
                    public void onFailure(@NonNull CredentialsManagerException error) {
                        System.out.println(error);
                    }
                });

```
</details>

### Handling Credentials Manager exceptions

In the event that something happened while trying to save or retrieve the credentials, a `CredentialsManagerException` will be thrown. These are some of the expected failure scenarios:

- Invalid Credentials format or values. e.g. when it's missing the `access_token`, the `id_token` or the `expires_at` values.
- Tokens have expired but no `refresh_token` is available to perform a refresh credentials request.
- Device's Lock Screen security settings have changed (e.g. the PIN code was changed). Even when `hasCredentials` returns true, the encryption keys will be deemed invalid and until `saveCredentials` is called again it won't be possible to decrypt any previously existing content, since they keys used back then are not the same as the new ones.
- Device is not compatible with some of the algorithms required by the `SecureCredentialsManager` class. This is considered a catastrophic event and might happen when the OEM has modified the Android ROM removing some of the officially included algorithms. Nevertheless, it can be checked in the exception instance itself by calling `isDeviceIncompatible`. By doing so you can decide the fallback for storing the credentials, such as using the regular `CredentialsManager`.
- **DPoP key pair lost** — The DPoP key pair is no longer available in the Android KeyStore. The stored credentials are cleared and re-authentication is required.
- **DPoP key pair mismatch** — The DPoP key pair exists but is different from the one used when the credentials were saved. The stored credentials are cleared and re-authentication is required.
- **DPoP not configured** — The stored credentials are DPoP-bound but the `AuthenticationAPIClient` used by the credentials manager was not configured with `useDPoP(context)`. The developer needs to call `AuthenticationAPIClient(auth0).useDPoP(context)` and pass the configured client to the credentials manager.
- **Session expired** — The session has reached the `session_expiry` ceiling asserted by the upstream identity provider. The stored credentials are cleared and re-authentication is required. See [Upstream session expiry](#upstream-session-expiry) below.

You can access the `code` property of the `CredentialsManagerException` to understand why the operation with `CredentialsManager` has failed and the `message` property of the `CredentialsManagerException` would give you a description of the exception.

Starting from version `3.0.0` you can even pass the exception to a `when` expression and handle the exception accordingly in your app's logic as shown in the below code snippet:

```kotlin
when(credentialsManagerException) {
    CredentialsManagerException.NO_CREDENTIALS -> {
        // handle no credentials scenario
    }

    CredentialsManagerException.NO_REFRESH_TOKEN -> {
        // handle no refresh token scenario
    }

    CredentialsManagerException.STORE_FAILED -> {
        // handle store failed scenario
    }

    CredentialsManagerException.DPOP_KEY_MISSING -> {
        // DPoP key was lost 
        // Clear local state and prompt user to re-authenticate
    }

    CredentialsManagerException.DPOP_KEY_MISMATCH -> {
        // DPoP key exists but doesn't match the one used at login (key rotation)
        // Clear local state and prompt user to re-authenticate
    }

    CredentialsManagerException.DPOP_NOT_CONFIGURED -> {
        // Developer forgot to call useDPoP() on the AuthenticationAPIClient
        // passed to the credentials manager. Fix the client configuration.
    }

    CredentialsManagerException.SESSION_EXPIRED -> {
        // The upstream identity provider's session_expiry ceiling was reached.
        // The stored credentials have already been cleared; prompt the user to
        // re-authenticate.
    }
    // ... similarly for other error codes
}
```

### Upstream session expiry

When an enterprise connection (for example an OIDC or Okta connection) is configured to assert a session lifetime, Auth0 includes a `session_expiry` claim in the ID token. This claim is an absolute ceiling — expressed in **Unix seconds** — on how long the local session may live, independently of the access-token expiry. It usually sits much further out than `expiresAt`, and it cannot be extended by a refresh-token renewal.

The credentials managers enforce this ceiling automatically:

- The ceiling is read from the ID token at login and persisted, so it survives refreshes whose ID token does not re-emit the claim.
- `saveCredentials` rejects an already-expired session up front: if the ID token is already past its ceiling at login, the save throws `CredentialsManagerException.SESSION_EXPIRED` and nothing is persisted.
- On every `getCredentials` call, if the ceiling has been reached the stored credentials are cleared and the call fails with `CredentialsManagerException.SESSION_EXPIRED`. The refresh token is **never** used to renew a session past the ceiling.
- A small negative clock-skew leeway (~30 seconds) is applied, so the session is treated as expired slightly *before* the wall-clock ceiling, never after.
- Connections that do not emit the claim are unaffected — there is no ceiling and behavior is unchanged.

> ⚠️ **The `session_expiry` value must be Unix seconds.** Per [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519), the claim is interpreted as seconds since the Unix epoch. A millisecond-magnitude value (e.g. `1700000000000`) resolves to a date ~50,000 years out and would **silently disable** the ceiling, so the SDK treats any implausibly large value (`>= 10_000_000_000`) as "no ceiling". The SDK also **fails open** on any malformed value — a non-numeric, zero, negative, or millisecond value is treated as "no ceiling" and the session proceeds without enforcement. When emitting the claim from an Action, always use seconds (divide a milliseconds timestamp by 1000).

> ⚠️ **Upgrade note:** For a user whose connection asserts `session_expiry`, a `getCredentials` call that previously succeeded can now fail with `SESSION_EXPIRED` once the ceiling is reached. Make sure your error handling treats `SESSION_EXPIRED` as a prompt to re-authenticate.

#### Emitting the claim

The `session_expiry` claim is not emitted by default — it is set on your tenant by a [Post-Login Action](https://auth0.com/docs/customize/actions/flows-and-triggers/login-flow) that adds it to the ID token, for example:

```javascript
exports.onExecutePostLogin = async (event, api) => {
  // session_expiry must be expressed in Unix seconds
  const sessionExpiry = Math.floor(Date.now() / 1000) + 8 * 60 * 60; // 8 hours from now
  api.idToken.setCustomClaim('session_expiry', sessionExpiry);
};
```

> 📝 A link to the canonical Auth0 `session_expiry` Action guide will be added here once it is published.

You can read the ceiling for a given credential set from `Credentials.sessionExpiresAt` (a nullable `Long` of Unix seconds, `null` when the connection does not emit the claim):

```kotlin
val credentials = credentialsManager.awaitCredentials()
val ceiling: Long? = credentials.sessionExpiresAt
```
