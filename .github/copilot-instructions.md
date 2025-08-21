# Auth0.Android SDK - AI Coding Agent Instructions

## Project Overview

Auth0.Android is an OAuth 2.0/OpenID Connect authentication SDK for Android applications (API 21+, Java 8+). The SDK provides secure authentication flows including Web Authentication (WebAuth), Management API access, and credential management with support for advanced security features like DPoP (Demonstrating Proof of Possession).

## Architecture Patterns

### Core Components

1. **Auth0 Class** (`com.auth0.android.Auth0`)
   - Central configuration class holding client ID, domain, and networking client
   - Factory pattern with `getInstance()` methods
   - Supports custom configuration domains and user agents

2. **WebAuthProvider** (`com.auth0.android.provider.WebAuthProvider`)
   - Main entry point for web authentication flows
   - Builder pattern with fluent API: `WebAuthProvider.login(auth0).withScheme("demo").start(activity, callback)`
   - Supports Custom Tabs, Trusted Web Activity (TWA), and fallback browsers
   - PKCE implementation for security

3. **AuthenticationAPIClient** (`com.auth0.android.authentication.AuthenticationAPIClient`)
   - Direct API client for authentication endpoints
   - Supports login, signup, password reset, token refresh
   - DPoP integration for sender-constrained tokens

4. **OAuthManager** (`com.auth0.android.provider.OAuthManager`)
   - Internal OAuth flow orchestration
   - State management and callback handling
   - PKCE and DPoP integration

### Security Features

#### DPoP (Demonstrating Proof of Possession)
- **DPoPKeyStore**: Android Keystore management with StrongBox support and fallback
- **DPoP**: Thread-safe proof generation and nonce management
- **DPoPUtil**: JWT creation and cryptographic operations
- Key rotation and hardware-backed security

#### Credential Management
- **SecureCredentialsManager**: Encrypted credential storage with biometric authentication
- **CredentialsManager**: Basic credential storage
- Automatic token refresh and scope validation

## Development Conventions

### Testing Standards

#### Test Framework Setup
```kotlin
@RunWith(RobolectricTestRunner::class)
@Config(shadows = [ThreadSwitcherShadow::class])
public class ExampleTest {
    @Mock
    private lateinit var mockClient: AuthenticationAPIClient
    
    @Before
    fun setUp() {
        MockitoAnnotations.openMocks(this)
    }
}
```

#### Common Test Patterns
- **Robolectric**: For Android unit tests requiring Android framework
- **Mockito**: Extensive use of mocking with `@Mock`, `verify()`, `when()`
- **Hamcrest Matchers**: Assertions with `assertThat()`, `is()`, `notNullValue()`
- **ArgumentCaptor**: Capture and verify method arguments
- **Thread Safety**: Use `CountDownLatch` and executors for concurrent testing

#### Mock Objects
- Use provided mock classes: `AuthenticationRequestMock`, `RequestMock`, `MockAuthCallback`
- Mock network responses with `MockWebServer` patterns
- Create test credentials with `CredentialsMock.create()`

### Code Organization

#### Package Structure
```
com.auth0.android/
├── authentication/          # API clients and requests
├── provider/               # Web auth providers and OAuth
├── result/                 # Data models (Credentials, UserProfile)
├── management/             # Management API client
├── request/                # HTTP networking and requests
├── callback/               # Callback interfaces
├── util/                   # Utility classes
└── dpop/                   # DPoP implementation
```

#### Builder Patterns
Most public APIs use builder patterns:
```kotlin
WebAuthProvider.login(auth0)
    .withScheme("demo")
    .withAudience("api-audience")
    .withScope("openid profile")
    .start(activity, callback)
```

### DPoP Implementation Guidelines

#### Key Management
- **Android Keystore**: Always use hardware-backed keys when available
- **StrongBox Support**: Implement with fallback for older devices
- **Error Handling**: Handle `ProviderException` with retry logic:
```kotlin
try {
    generator.generateKeyPair()
} catch (e: ProviderException) {
    // Fallback without StrongBox
    generateKeyPairWithoutStrongBox()
}
```

#### Thread Safety
- Use `@Volatile` for shared state variables
- Implement `synchronized` blocks for critical sections
- DPoP nonce storage must be thread-safe

#### Proof Generation
- JWT-based proofs with EC P-256 keys
- Include `jti`, `htm`, `htu`, `iat` claims
- Handle nonce challenges from server responses

### Networking Patterns

#### Request Building
```kotlin
private fun buildRequest(): Request<T, AuthenticationException> {
    val request = client.POST(url, adapter)
    request.addHeader("Authorization", "Bearer $token")
    parameters.forEach { (key, value) -> request.addParameter(key, value) }
    return request
}
```

#### Error Handling
- Custom exceptions: `AuthenticationException`, `Auth0Exception`
- Network errors with proper HTTP status code handling
- Callback pattern: `Callback<T, E>` with `onSuccess(T)` and `onFailure(E)`

### Custom Tabs Integration

#### Browser Selection
- **BrowserPicker**: Intelligent browser selection with filtering
- **Custom Tabs**: Preferred for seamless UX
- **Trusted Web Activity**: Native-like experience with domain verification

#### Configuration
```kotlin
val customTabsOptions = CustomTabsOptions.newBuilder()
    .showTitle(true)
    .withToolbarColor(Color.PRIMARY)
    .withBrowserPicker(browserPicker)
    .build()
```

## Build System

### Gradle Configuration
- **Android Library**: `compileSdk 35`, `minSdk 21`, `targetSdk 35`
- **Kotlin Support**: Mixed Java/Kotlin project
- **Dependencies**: OkHttp, Gson, AndroidX libraries
- **Proguard**: Consumer rules for R8/Proguard compatibility

### Maven Publishing
- Central repository publishing via Sonatype OSSRH
- GPG signing for release artifacts
- GitHub Actions automation: `.github/actions/maven-publish/`

### Testing Dependencies
```gradle
testImplementation 'junit:junit:4.13.2'
testImplementation 'org.robolectric:robolectric:4.11.1'
testImplementation 'org.mockito:mockito-core:5.8.0'
testImplementation 'com.nhaarman.mockitokotlin2:mockitokotlin2:2.2.0'
testImplementation 'com.squareup.okhttp3:mockwebserver:4.12.0'
```

## Common Development Tasks

### Adding New Authentication Methods
1. Create request class extending `BaseAuthenticationRequest`
2. Add endpoint method to `AuthenticationAPIClient`
3. Implement builder pattern with parameter validation
4. Add comprehensive test coverage with edge cases
5. Update documentation and examples

### Implementing Security Features
1. Follow Android security best practices
2. Use hardware-backed storage when available
3. Implement proper error handling and fallbacks
4. Add thread safety for concurrent access
5. Include penetration testing scenarios

### Testing Guidelines
1. **Unit Tests**: Focus on business logic and edge cases
2. **Robolectric Tests**: For Android framework interactions
3. **Mock Everything**: External dependencies, network calls, system services
4. **Thread Safety**: Test concurrent access patterns
5. **Error Scenarios**: Network failures, malformed responses, edge cases

### Code Review Checklist
- [ ] Thread safety for shared state
- [ ] Proper error handling with fallbacks
- [ ] Comprehensive test coverage (>90%)
- [ ] Builder pattern validation
- [ ] Backward compatibility
- [ ] Security best practices
- [ ] Documentation updates

## Integration Examples

### Basic Authentication Flow
```kotlin
// Setup
val auth0 = Auth0.getInstance("clientId", "domain")

// Web Authentication
WebAuthProvider.login(auth0)
    .withScheme("demo")
    .withAudience("https://api.example.com")
    .start(this) { result ->
        when (result) {
            is Credentials -> handleSuccess(result)
            is AuthenticationException -> handleError(result)
        }
    }
```

### DPoP Integration
```kotlin
// Enable DPoP for enhanced security
AuthenticationAPIClient(auth0).apply {
    enableDPoP(context)
    login("email", "password")
        .start(callback)
}
```

### Credential Management
```kotlin
// Secure storage with biometric authentication
val manager = SecureCredentialsManager(client, storage, context)
manager.saveCredentials(credentials)
manager.getCredentials(object : Callback<Credentials, CredentialsManagerException> {
    override fun onSuccess(result: Credentials) { /* use credentials */ }
    override fun onFailure(error: CredentialsManagerException) { /* handle error */ }
})
```

## Troubleshooting

### Common Issues
1. **Looper Errors**: Use `ThreadSwitcherShadow` or `CommonThreadSwitcherRule` in tests
2. **Android Keystore**: Handle device-specific failures with fallbacks
3. **Custom Tabs**: Verify browser compatibility and package visibility
4. **SSL Errors**: Implement custom `NetworkingClient` for certificate handling

### Debug Patterns
- Enable verbose logging for network requests
- Use Android Studio's Network Inspector
- Validate JWT tokens with online decoders
- Check Android Keystore entries with debugging tools

This SDK prioritizes security, developer experience, and Android platform integration. When contributing, maintain these standards and ensure comprehensive testing of authentication flows.
