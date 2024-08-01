# Migration Guide from SDK v2 to v3

## Breaking Changes

### Auth0 Class
- **Constructor**: The constructor of the `Auth0` class is now private. Use `Auth0.getInstance(clientId, domain)` to get an instance. This method checks if an instance with the given configuration exists; if yes, it returns it, otherwise, it creates a new one.

### BaseCredentialsManager Interface
- **New Methods**: Added multiple overloads of `getCredentials()` and `awaitCredentials()` to the `BaseCredentialsManager` interface. All implementations of this interface must now override these new methods.

### Request Interface
- **await Function**: The `await` function of the `Request` interface is now abstract. All implementations must implement this method.

### Credentials Class
- **Data Class**: The `Credentials` class is now a data class and can no longer be extended. The `currentTimeInMillis` property has been removed.

### SecureCredentialsManager
- **requireAuthentication Method**: The `requireAuthentication` method, used to enable authentication before obtaining credentials, has been removed. Refer to the [Enabling Authentication](#enabling-authentication-before-obtaining-credentials) section for the new approach.

## Changes

### Biometrics Authentication
- **Library Update**: Implementation of biometrics authentication for retrieving credentials securely is now done using the `androidx.biometric.biometric` library.

### CredentialsManagerException
- **Enum Code**: The `CredentialsManagerException` now contains an enum code. You can use a `when` expression to handle different error scenarios:

```kotlin
when (credentialsManagerException) {
    CredentialsManagerException.NO_CREDENTIALS -> {
        // handle no credentials scenario
    }
    CredentialsManagerException.NO_REFRESH_TOKEN -> {
        // handle no refresh token scenario
    }
    CredentialsManagerException.STORE_FAILED -> {
        // handle store failed scenario
    }
    // ... similarly for other error codes
}
```

## Enabling Authentication before Obtaining Credentials

To enable authentication before obtaining credentials, you need to pass the below to the constructor of `SecureCredentialsManager`:
- An instance of `FragmentActivity` where the authentication prompt should be shown.
- An instance of `LocalAuthenticationOptions` to configure details like the level of authentication (Strong, Weak), prompt title, etc.

### Example

```kotlin
private val localAuthenticationOptions = LocalAuthenticationOptions.Builder()
    .setTitle("Authenticate to Access Credentials")
    .setDescription("description")
    .setAuthenticationLevel(AuthenticationLevel.STRONG)
    .setDeviceCredentialFallback(true)
    .build()

val storage = SharedPreferencesStorage(context)
val manager = SecureCredentialsManager(
    context, account, storage, fragmentActivity,
    localAuthenticationOptions
)
```

If you need more information, please refer to the [examples.md](examples.md#requiring-authentication) file under the section **Requiring Authentication**.