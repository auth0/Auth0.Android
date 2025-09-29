# Auth0.Android SDK Development Guide

## Architecture Overview

This is a multi-module Android SDK for Auth0 authentication with these key components:

- **`auth0/`** - Main library module containing the core SDK
- **`sample/`** - Example application demonstrating SDK usage

The SDK follows the Builder pattern for WebAuthentication (see `WebAuthProvider.login()` and `WebAuthProvider.logout()`) and supports both callback-based and coroutine-based APIs.

## Core Components

### Authentication Flow
- **`WebAuthProvider`** - Primary entry point for web-based auth (Universal Login)
- **`AuthenticationAPIClient`** - Direct API calls for database connections, passwordless, etc.
- **`Auth0`** - Main configuration class holding client ID and domain

### Credential Management
- **`CredentialsManager`** - Basic token storage with automatic refresh
- **`SecureCredentialsManager`** - Enhanced version with biometric protection
- **Storage interfaces** - `SharedPreferencesStorage` for persistence

### Provider Architecture
Authentication providers in `auth0/src/main/java/com/auth0/android/provider/`:
- Handle browser redirects via `AuthenticationActivity` and `RedirectActivity`
- Support Custom Tabs, Trusted Web Activity, and fallback browsers

## Development Workflows

### Building & Testing
```bash
# Build all modules
./gradlew clean build

# Run unit tests with coverage
./gradlew clean test jacocoTestReport

# Run lint checks
./gradlew lint

# CI command (matches GitHub Actions)
./gradlew clean test jacocoTestReport lint --continue --console=plain --max-workers=1 --no-daemon
```

### Module Structure
- Use `auth0/build.gradle` for main library dependencies
- Version management via `gradle/versioning.gradle` reading from `.version` file
- Publishing configuration in `gradle/maven-publish.gradle`

### Testing Patterns
- **Unit tests** use Robolectric for Android components
- **Mock testing** with PowerMock, Mockito, and MockWebServer for HTTP
- **Coroutine testing** with `kotlinx-coroutines-test`
- Test files follow `*Test.kt` convention in `auth0/src/test/`

## Project-Specific Conventions

### Error Handling
- Custom exceptions inherit from `Auth0Exception`
- `AuthenticationException` for auth-related errors
- `CredentialsManagerException` for storage/retrieval issues

### Callback Pattern
```kotlin
// Standard callback pattern used throughout
val callback = object : Callback<Credentials, AuthenticationException> {
    override fun onSuccess(result: Credentials) { /* ... */ }
    override fun onFailure(error: AuthenticationException) { /* ... */ }
}
```

### Coroutine Support
Most APIs offer both callback and suspend function variants:
```kotlin
// Callback style
WebAuthProvider.login(account).start(context, callback)

// Coroutine style  
val credentials = WebAuthProvider.login(account).await(context)
```

### Configuration Management
- **Manifest placeholders** required: `auth0Domain` and `auth0Scheme` in `build.gradle`
- **String resources** pattern: `com_auth0_client_id` and `com_auth0_domain`
- **URL scheme validation** for redirect handling

### SDK Versioning
- Version stored in `.version` file at project root
- Gradle reads version via `getVersionFromFile()` function
- BuildConfig fields auto-generated with library name and version

## Key Integration Points

### Browser Integration
- Custom Tabs preferred, with fallback to system browser
- **App Links** support for `https://` schemes (recommended over custom schemes)
- **Trusted Web Activity** for native-like web auth experience

### Android Components
- Activities handle auth redirects and state management
- **Biometric authentication** via AndroidX Biometric library
- **Credential Manager** integration for Android 14+ passkey support

### Network Layer
- **OkHttp** for all HTTP communication
- **Gson** for JSON serialization
- Custom `NetworkingClient` interface for request handling

### Security Features
- **PKCE** (Proof Key for Code Exchange) enabled by default
- **DPoP** (Demonstration of Proof of Possession) support for enhanced security
- **JWT validation** with configurable options

## Common Patterns

When adding new authentication methods, follow the established patterns:
- Implement both callback and coroutine APIs
- Add comprehensive unit tests with mocked network responses
- Update `EXAMPLES.md` with usage documentation