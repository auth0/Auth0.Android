# Auth0 Android SDK - Biometric Policy Guide

## Overview

The Auth0 Android SDK now supports configurable biometric authentication policies through the `BiometricPolicy` class. This feature allows developers to control when biometric prompts are shown when retrieving credentials from `SecureCredentialsManager`.

The policy is configured through the `LocalAuthenticationOptions.Builder.setPolicy()` method, providing a clean and integrated API design.

## 📋 Available Policies

### 1. Always (Default)
Shows a biometric prompt for every call to `getCredentials()`.

```kotlin
val localAuthOptions = LocalAuthenticationOptions.Builder()
    .setTitle("Authenticate")
    .setDescription("Use your biometric to access your account")
    .setNegativeButtonText("Cancel")
    .setPolicy(BiometricPolicy.Always)
    .build()

val manager = SecureCredentialsManager(
    context,
    auth0,
    storage,
    fragmentActivity,
    localAuthOptions
)
```

**Use Case**: Maximum security scenarios where every access requires fresh authentication.

### 2. Session-based
Shows a biometric prompt only once within a specified timeout period.

```kotlin
val localAuthOptions = LocalAuthenticationOptions.Builder()
    .setTitle("Authenticate")
    .setSubtitle("Use your biometric to access your account")
    .setDescription("Place your finger on the sensor")
    .setNegativeButtonText("Cancel")
    .setPolicy(BiometricPolicy.Session(timeoutInSeconds = 300)) // 5 minutes
    .build()

val manager = SecureCredentialsManager(
    context,
    auth0,
    storage,
    fragmentActivity,
    localAuthOptions
)
```

**Use Case**: Balanced security and user experience for frequent access patterns.

### 3. App Lifecycle
Shows a biometric prompt only once while the app is in the foreground. The session remains valid until manually cleared or after the specified timeout (default 1 hour).

```kotlin
val localAuthOptions = LocalAuthenticationOptions.Builder()
    .setTitle("Authenticate")
    .setSubtitle("Use your biometric to access your account")  
    .setDescription("Place your finger on the sensor")
    .setNegativeButtonText("Cancel")
    .setPolicy(BiometricPolicy.AppLifecycle()) // Default 1 hour timeout
    .build()

val manager = SecureCredentialsManager(
    context,
    auth0,
    storage,
    fragmentActivity,
    localAuthOptions
)

// Or with custom timeout
val localAuthOptionsCustom = LocalAuthenticationOptions.Builder()
    .setTitle("Authenticate")
    .setPolicy(BiometricPolicy.AppLifecycle(timeoutInSeconds = 7200)) // 2 hours
    .build()

// Manually clear the session when needed
manager.clearBiometricSession()
```

**Use Case**: Minimal interruption during active app usage sessions with a reasonable security timeout.

## 🔧 Implementation Details

### Core Components

1. **`BiometricPolicy.kt`** - Sealed class defining the three policy types
2. **`LocalAuthenticationOptions.kt`** - Enhanced with `setPolicy()` method in the Builder to configure biometric policy
3. **`SecureCredentialsManager.kt`** - Enhanced with session management and policy evaluation, reads policy from LocalAuthenticationOptions

### Key Features

- **Policy Configuration**: Biometric policy is now configured through `LocalAuthenticationOptions.Builder.setPolicy()`
- **Integrated Design**: Policy is part of the authentication options, not a separate constructor parameter
- **Simplified Constructor**: SecureCredentialsManager constructor remains clean with only LocalAuthenticationOptions parameter
- **Lock-free Thread Safety**: Uses AtomicLong for biometric session management, providing better performance than synchronized blocks
- **Backward compatible**: Default behavior remains unchanged (`BiometricPolicy.Always`)
- **Automatic session management**: Sessions are updated after successful authentication
- **Manual session control**: `clearBiometricSession()` can be called anytime
- **Integrated clearing**: `clearCredentials()` also clears biometric session

### API Changes

The biometric policy is now configured as part of the `LocalAuthenticationOptions` instead of being a separate constructor parameter:

**New API (Recommended):**
```kotlin
val localAuthOptions = LocalAuthenticationOptions.Builder()
    .setTitle("Authenticate")
    .setPolicy(BiometricPolicy.Session(300))
    .build()

val manager = SecureCredentialsManager(context, auth0, storage, activity, localAuthOptions)
```

**AppLifecycle with default 1-hour timeout:**
```kotlin
val localAuthOptions = LocalAuthenticationOptions.Builder()
    .setTitle("Authenticate")
    .setPolicy(BiometricPolicy.AppLifecycle()) // 1 hour default
    .build()

// Or with custom timeout
val localAuthOptionsCustom = LocalAuthenticationOptions.Builder()
    .setTitle("Authenticate")
    .setPolicy(BiometricPolicy.AppLifecycle(timeoutInSeconds = 7200)) // 2 hours
    .build()
```

**Previous API (No longer available):**
```kotlin
// This constructor signature has been removed
val manager = SecureCredentialsManager(context, auth0, storage, activity, localAuthOptions, biometricPolicy)
```

### How It Works

1. **Session tracking**: Maintains a timestamp of the last successful biometric authentication
2. **Policy evaluation**: Before showing biometric prompt, checks if current session is valid based on the configured policy
3. **Session updates**: Updates session timestamp after successful biometric authentication
4. **Session clearing**: Automatically clears session when credentials are cleared, or manually via `clearBiometricSession()`

### Session Validation Logic

```kotlin
internal fun isBiometricSessionValid(): Boolean {
    val lastAuth = lastBiometricAuthTime.get()
    if (lastAuth == -1L) return false // No session exists
    
    return when (biometricPolicy) {
        is BiometricPolicy.Session -> {
            val timeoutMillis = biometricPolicy.timeoutInSeconds * 1000L
            System.currentTimeMillis() - lastAuth < timeoutMillis
        }
        is BiometricPolicy.AppLifecycle -> {
            val timeoutMillis = biometricPolicy.timeoutInSeconds * 1000L
            System.currentTimeMillis() - lastAuth < timeoutMillis
        }
        is BiometricPolicy.Always -> false // Always require authentication
    }
}
```

## 💡 Usage Examples

### Basic Implementation

```kotlin
class MainActivity : FragmentActivity() {
    private lateinit var credentialsManager: SecureCredentialsManager
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        val auth0 = Auth0("clientId", "domain")
        val storage = SharedPreferencesStorage(this)
        val localAuthOptions = LocalAuthenticationOptions.Builder()
            .setTitle("Authenticate")
            .setSubtitle("Use your biometric to access your account")
            .setDescription("Place your finger on the sensor")
            .setNegativeButtonText("Cancel")
            .setPolicy(BiometricPolicy.Session(timeoutInSeconds = 600)) // 10 minutes
            .build()
        
        // Use session-based policy with 10 minute timeout
        credentialsManager = SecureCredentialsManager(
            this,
            auth0,
            storage,
            this,
            localAuthOptions
        )
    }
    
    private fun getCredentials() {
        credentialsManager.getCredentials(object : Callback<Credentials, CredentialsManagerException> {
            override fun onSuccess(result: Credentials) {
                // Handle success - biometric prompt may or may not have been shown
                // depending on the policy and session state
            }
            
            override fun onFailure(error: CredentialsManagerException) {
                // Handle error
            }
        })
    }
    
    private fun logout() {
        credentialsManager.clearCredentials() // This also clears biometric session
    }
    
    private fun clearBiometricSession() {
        credentialsManager.clearBiometricSession() // Force next call to show biometric prompt
    }
}
```

### Advanced Usage with Multiple Policies

```kotlin
class AdvancedAuthActivity : FragmentActivity() {
    
    // High-security operations - always prompt
    private val highSecurityManager = SecureCredentialsManager(
        context, auth0, storage, this, LocalAuthenticationOptions.Builder()
            .setTitle("High Security")
            .setPolicy(BiometricPolicy.Always)
            .build()
    )
    
    // Regular operations - 5 minute session
    private val regularManager = SecureCredentialsManager(
        context, auth0, storage, this, LocalAuthenticationOptions.Builder()
            .setTitle("Regular Access")
            .setPolicy(BiometricPolicy.Session(300))
            .build()
    )
    
    // App session operations - 1 hour default timeout
    private val sessionManager = SecureCredentialsManager(
        context, auth0, storage, this, LocalAuthenticationOptions.Builder()
            .setTitle("Session Access")
            .setPolicy(BiometricPolicy.AppLifecycle()) // 1 hour default
            .build()
    )
    
    fun performHighSecurityOperation() {
        highSecurityManager.getCredentials(callback) // Always shows biometric prompt
    }
    
    fun performRegularOperation() {
        regularManager.getCredentials(callback) // Cached for 5 minutes
    }
    
    fun performSessionOperation() {
        sessionManager.getCredentials(callback) // Cached for 1 hour (default) or until cleared
    }
}
```

## 🧪 Testing with Sample App

The sample app has been enhanced with a comprehensive testing interface for all biometric policies.

### Setup Instructions

#### Prerequisites
1. Device with biometric authentication (fingerprint, face unlock, etc.)
2. Biometric authentication enabled on the device
3. Auth0 account with valid credentials configured in the app

#### Test Interface
The sample app includes a "Biometric Policy Examples" section with:
- **"Get Creds (Always Policy)"** - Shows biometric prompt every time
- **"Get Creds (Session Policy)"** - Shows prompt once per 5-minute session
- **"Get Creds (AppLifecycle Policy)"** - Shows prompt once until manually cleared
- **"Clear Biometric Sessions"** - Resets all sessions for testing

### Testing Procedures

#### Test 1: BiometricPolicy.Always
**Expected Behavior**: Biometric prompt appears every time credentials are requested.

1. Launch the sample app and login
2. Scroll to "Biometric Policy Examples" section
3. Tap **"Get Creds (Always Policy)"** button
4. **✅ Expected**: Biometric prompt appears
5. Authenticate with biometric
6. **✅ Expected**: Credentials retrieved successfully
7. Tap **"Get Creds (Always Policy)"** button again immediately
8. **✅ Expected**: Biometric prompt appears again (no session caching)

#### Test 2: BiometricPolicy.Session
**Expected Behavior**: Biometric prompt appears once, then cached for the timeout period.

1. Tap **"Clear Biometric Sessions"** to reset any existing sessions
2. Tap **"Get Creds (Session Policy)"** button
3. **✅ Expected**: Biometric prompt appears
4. Authenticate with biometric
5. **✅ Expected**: Credentials retrieved successfully
6. Tap **"Get Creds (Session Policy)"** button again within 5 minutes
7. **✅ Expected**: No biometric prompt appears, credentials retrieved directly
8. Wait for 5+ minutes
9. Tap **"Get Creds (Session Policy)"** button again
10. **✅ Expected**: Biometric prompt appears again (session expired)

#### Test 3: BiometricPolicy.AppLifecycle
**Expected Behavior**: Biometric prompt appears once, then cached for 1 hour (default) until manually cleared or timeout expires.

1. Tap **"Clear Biometric Sessions"** to reset any existing sessions
2. Tap **"Get Creds (AppLifecycle Policy)"** button
3. **✅ Expected**: Biometric prompt appears
4. Authenticate with biometric
5. **✅ Expected**: Credentials retrieved successfully
6. Tap **"Get Creds (AppLifecycle Policy)"** button multiple times within 1 hour
7. **✅ Expected**: No biometric prompt appears for subsequent calls
8. **Option A - Manual Clear**: Tap **"Clear Biometric Sessions"** button
9. Tap **"Get Creds (AppLifecycle Policy)"** button
10. **✅ Expected**: Biometric prompt appears again (session manually cleared)
11. **Option B - Timeout**: Wait for 1+ hours
12. Tap **"Get Creds (AppLifecycle Policy)"** button
13. **✅ Expected**: Biometric prompt appears again (session expired)

#### Test 4: Mixed Policy Testing
**Expected Behavior**: Different policies maintain separate session states.

1. Test that different managers with different policies work independently
2. Verify session clearing affects all policies
3. Confirm proper error handling for authentication failures

### UI Enhancements

The sample app includes:
- ✅ **ScrollView with fillViewport**: Proper scrolling on all screen sizes
- ✅ **Improved spacing**: Better margins and padding to prevent UI overlap
- ✅ **Visual sections**: Color-coded section headers for better organization
- ✅ **Responsive layout**: Handles varying content length gracefully

## 📝 Important Notes

- **Memory Storage**: The biometric session is stored in memory using AtomicLong and will be cleared when the app process is killed
- **Time-based Sessions**: For both `BiometricPolicy.Session` and `BiometricPolicy.AppLifecycle`, the timeout is checked against `System.currentTimeMillis()`
- **AppLifecycle Default**: `BiometricPolicy.AppLifecycle` now defaults to 1 hour (3600 seconds) timeout for better security
- **Manual Control**: Sessions can be explicitly cleared using `clearBiometricSession()` regardless of timeout
- **Backward Compatibility**: All existing `SecureCredentialsManager` functionality remains unchanged
- **Lock-free Thread Safety**: Session operations use AtomicLong for better performance and thread safety
- **Session State**: Uses -1L to represent "no session" state instead of nullable values

## 🔍 Troubleshooting

### Common Issues

1. **Biometric prompt doesn't appear**: 
   - Verify device has secure lock screen enabled
   - Check if biometric hardware is available and configured
   - Ensure LocalAuthenticationOptions are properly configured

2. **Session not being cached**:
   - Verify you're using the same SecureCredentialsManager instance
   - Check that the policy is configured correctly
   - Ensure sufficient time hasn't passed for Session policy timeout

3. **App crashes on biometric authentication**:
   - Verify FragmentActivity reference is valid
   - Check LocalAuthenticationOptions configuration
   - Ensure proper error handling in callbacks

### Debug Tips

1. Enable verbose logging to see biometric session state changes
2. Use Android Studio debugger to inspect session timestamps
3. Check device settings for biometric authentication setup
4. Test on multiple devices with different biometric capabilities

## 📊 Expected Test Results Summary

| Test Case | Action | Expected Result |
|-----------|--------|-----------------|
| Always Policy | Every call | Biometric prompt appears |
| Session Policy (within timeout) | Subsequent calls | No prompt, direct access |
| Session Policy (after timeout) | Call after timeout | Biometric prompt appears |
| App Lifecycle (within 1 hour) | Subsequent calls | No prompt, direct access |
| App Lifecycle (after manual clear) | Call after manual clear | Biometric prompt appears |
| App Lifecycle (after 1 hour timeout) | Call after timeout | Biometric prompt appears |
| Session Clearing | Any policy after clear | Biometric prompt appears |

This implementation provides a robust, flexible, and user-friendly approach to biometric authentication in the Auth0 Android SDK while maintaining backward compatibility and ensuring thread safety.
