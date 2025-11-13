package com.auth0.android.authentication.storage

/**
 * Defines the policy for when a biometric prompt should be shown when using SecureCredentialsManager.
 */
public sealed class BiometricPolicy {
    /**
     * Default behavior. A biometric prompt will be shown for every call to getCredentials().
     */
    public object Always : BiometricPolicy()

    /**
     * A biometric prompt will be shown only once within the specified timeout period.
     * @param timeoutInSeconds The duration for which the session remains valid.
     */
    public data class Session(val timeoutInSeconds: Int) : BiometricPolicy()

    /**
     * A biometric prompt will be shown only once while the app is in the foreground.
     * The session is invalidated by calling clearBiometricSession() or after the default timeout.
     * @param timeoutInSeconds The duration for which the session remains valid. Defaults to 3600 seconds (1 hour).
     */
    public data class AppLifecycle @JvmOverloads constructor(val timeoutInSeconds: Int = 3600) : BiometricPolicy() // Default 1 hour
}
