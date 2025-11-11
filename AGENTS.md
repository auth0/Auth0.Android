# AI Agent Guidelines for Auth0.Android SDK

This document provides context and guidelines for AI coding assistants working with the Auth0.Android SDK codebase.

## Project Overview

**Auth0.Android** is a native Android SDK for integrating Auth0 authentication and authorization into Android applications. The SDK provides a comprehensive solution for:

- Web-based authentication (Universal Login via Custom Tabs)
- Direct API authentication (database connections, passwordless)
- Secure credential storage with biometric protection
- Token management with automatic refresh
- Modern Android development patterns (Coroutines, AndroidX libraries)

## Repository Structure

```
Auth0.Android/
├── auth0/                          # Main SDK library module
│   ├── src/main/java/com/auth0/android/
│   │   ├── provider/              # Browser-based auth providers
│   │   ├── authentication/        # Direct API authentication
│   │   ├── management/            # Management API client
│   │   ├── myaccount/             # My Account API client
│   │   ├── request/               # Network request abstractions
│   │   ├── result/                # Response/error handling
│   │   └── Auth0.kt               # Main configuration class
│   └── src/test/                  # Unit tests
├── sample/                        # Demo application
├── .github/                       # CI/CD workflows
├── gradle/                        # Build configuration
│   ├── versioning.gradle          # Version management
│   └── maven-publish.gradle       # Publishing setup
└── .version                       # Current SDK version
```

## Key Technical Decisions

### Architecture Patterns
- **Builder Pattern**: Used extensively for web based authentication flows (e.g., `WebAuthProvider.login()`)
- **Callback + Coroutines**: Dual API support for both traditional callbacks and modern suspend functions
- **Provider Architecture**: Pluggable authentication providers with fallback strategies

### Authentication Flow
1. **WebAuthProvider** (Recommended): Browser-based auth via Custom Tabs
   - Uses App Links (`https://` schemes) or custom URL schemes
   - Handles PKCE automatically
   - Supports DPoP for enhanced security
   
2. **AuthenticationAPIClient**: Direct API calls without browser
   - Database connections (login/signup)
   - Passwordless (email/SMS)
   - Token refresh and revocation

### Credential Management Strategy
- **CredentialsManager**: Basic storage with automatic refresh
- **SecureCredentialsManager**: Adds biometric/device credential protection with encrypted storage
- Storage abstraction via `Storage` interface (default: SharedPreferences)
- Encryption using Android Keystore

## Development Guidelines

### Code Style
- **Language**: Kotlin (primary), with Java interop support
- **Minimum SDK**: API 21 (Android 5.0)
- **Target SDK**: Latest stable Android version
- **Testing**: Robolectric for Android components, MockWebServer for HTTP

### API Design Principles
When adding or modifying APIs:

1. **Dual API Support**: Provide both callback and suspend function variants
   ```kotlin
   // Callback style
   fun operation(callback: Callback<Result, Error>)
   
   // Coroutine style
   suspend fun operation(): Result
   ```

2. **Builder Pattern**: Use for WebAuthProvider operations
   ```kotlin
   WebAuthProvider.login(account)
       .withScheme("https")
       .withScope("openid profile")
       .start(context, callback)
   ```

3. **Error Handling**: Use typed exceptions
   - `AuthenticationException` for auth failures
   - `CredentialsManagerException` for storage issues
   - All inherit from `Auth0Exception`

### Testing Requirements
- Unit tests for all new functionality
- Code coverage tracked via JaCoCo (target: >80%)
- Mock external dependencies (network, Android framework)
- Test both success and failure scenarios

### Common Tasks

#### Adding a New Authentication Method
1. Create request class in `auth0/src/main/java/com/auth0/android/request/`
2. Implement both callback and suspend variants
3. Add unit tests with mocked responses
4. Update `EXAMPLES.md` with usage example
5. Add integration test in sample app

#### Modifying Browser Authentication
Key files:
- `WebAuthProvider.kt`: Main entry point
- `AuthenticationActivity.kt`: Handles redirects
- `OAuthManager.kt`: OAuth2 flow logic
- `PKCE.kt`: PKCE implementation

#### Updating Credential Storage
Key files:
- `CredentialsManager.kt`: Basic implementation
- `SecureCredentialsManager.kt`: Biometric support
- `SharedPreferencesStorage.kt`: Persistence layer

## Build & Testing Commands

```bash
# Full build with tests and coverage
./gradlew clean test jacocoTestReport

# Run lint checks
./gradlew lint

# Build sample app
./gradlew sample:assembleDebug

# CI simulation (matches GitHub Actions)
./gradlew clean test jacocoTestReport lint --continue --console=plain --max-workers=1 --no-daemon
```

## Configuration Files

### Version Management
- **`.version`**: Single source of truth for SDK version
- Read by `gradle/versioning.gradle` and injected into BuildConfig

### Required Manifest Placeholders
```gradle
android {
    defaultConfig {
        manifestPlaceholders = [
            auth0Domain: "YOUR_DOMAIN",
            auth0Scheme: "https" // or custom scheme
        ]
    }
}
```

### String Resources Pattern
```xml
<string name="com_auth0_client_id">YOUR_CLIENT_ID</string>
<string name="com_auth0_domain">YOUR_DOMAIN</string>
```

## Dependencies

### Core Libraries
- **AndroidX**: Activity, Browser, Biometric, Lifecycle
- **Kotlin Coroutines**: For async operations
- **OkHttp**: HTTP client
- **Gson**: JSON serialization
- **JWT**: Token parsing and validation

### Testing Libraries
- **JUnit 4**: Test framework
- **Robolectric**: Android unit testing
- **Mockito/PowerMock**: Mocking
- **MockWebServer**: HTTP testing
- **Hamcrest**: Assertions

## Security Considerations

1. **PKCE**: Enabled by default for all OAuth flows
2. **DPoP**: Optional enhanced token security
3. **Keystore**: All credentials encrypted using Android Keystore
4. **Biometric**: LocalAuthentication for secure access
5. **Certificate Pinning**: Configurable via OkHttp interceptors

## Documentation

- **README.md**: Getting started and installation
- **EXAMPLES.md**: Detailed usage examples
- **API docs**: Generated via Dokka (KDoc comments)
- **CHANGELOG.md**: Release notes and breaking changes
- **MIGRATION.md**: Upgrade guides between major versions

## Release Process

1. Update `.version` file
2. Update `CHANGELOG.md`
3. Create release branch
4. CI runs full test suite
5. Manual approval for publication
6. Maven Central publication via `gradle/maven-publish.gradle`

## Common Pitfalls

- **Redirect URIs**: Must match exactly between Auth0 dashboard and app configuration
- **Custom Tabs**: Require Chrome or Chrome Custom Tabs provider installed
- **Biometric**: Requires device credential fallback configuration
- **Coroutines**: Must use appropriate dispatcher for Android operations
- **Proguard**: Keep rules defined in `consumer-rules.pro`

## Getting Help

- **Issues**: GitHub Issues for bugs and feature requests
- **Discussions**: GitHub Discussions for questions
- **Auth0 Community**: https://community.auth0.com/
- **Auth0 Support**: For Auth0 account/dashboard issues

## AI Agent Best Practices

When assisting with this codebase:

1. **Preserve patterns**: Follow existing Builder and callback/coroutine patterns
2. **Test coverage**: Always include tests for new functionality
3. **Backward compatibility**: Consider impact on existing users
4. **Documentation**: Update relevant docs when changing public APIs
5. **Security**: Never compromise security features (PKCE, encryption, etc.)
6. **Android compatibility**: Test across Android versions (API 21+)
7. **Error handling**: Provide clear, actionable error messages

## Example Workflows

### Web Authentication
```kotlin
val account = Auth0(clientId, domain)
WebAuthProvider.login(account)
    .withScheme("https")
    .withScope("openid profile email")
    .start(context, object : Callback<Credentials, AuthenticationException> {
        override fun onSuccess(result: Credentials) { /* ... */ }
        override fun onFailure(error: AuthenticationException) { /* ... */ }
    })
```


### Direct API Authentication
```kotlin
val authClient = AuthenticationAPIClient(account)
authClient.login(email, password, "Username-Password-Authentication")
    .start(callback)
```

---

