package com.auth0.android.authentication.storage

import androidx.biometric.BiometricManager


public class LocalAuthenticationOptions private constructor(
    public val title: String,
    public val subtitle: String?,
    public val description: String?,
    public val authenticationLevel: AuthenticationLevel,
    public val enableDeviceCredentialFallback: Boolean,
    public val negativeButtonText: String,
    public val policy: BiometricPolicy
) {
    public class Builder(
        private var title: String? = null,
        private var subtitle: String? = null,
        private var description: String? = null,
        private var authenticationLevel: AuthenticationLevel = AuthenticationLevel.STRONG,
        private var enableDeviceCredentialFallback: Boolean = false,
        private var negativeButtonText: String = "Cancel",
        private var policy: BiometricPolicy = BiometricPolicy.Always
    ) {

        public fun setTitle(title: String): Builder = apply { this.title = title }
        public fun setSubTitle(subtitle: String?): Builder = apply { this.subtitle = subtitle }
        public fun setDescription(description: String?): Builder =
            apply { this.description = description }

        public fun setAuthenticationLevel(authenticationLevel: AuthenticationLevel): Builder =
            apply { this.authenticationLevel = authenticationLevel }

        public fun setDeviceCredentialFallback(enableDeviceCredentialFallback: Boolean): Builder =
            apply { this.enableDeviceCredentialFallback = enableDeviceCredentialFallback }

        public fun setNegativeButtonText(negativeButtonText: String): Builder =
            apply { this.negativeButtonText = negativeButtonText }

        public fun setPolicy(policy: BiometricPolicy): Builder =
            apply { this.policy = policy }

        public fun build(): LocalAuthenticationOptions = LocalAuthenticationOptions(
            title ?: throw IllegalArgumentException("Title must be provided"),
            subtitle,
            description,
            authenticationLevel,
            enableDeviceCredentialFallback,
            negativeButtonText,
            policy
        )
    }
}

public enum class AuthenticationLevel(public val value: Int) {
    STRONG(BiometricManager.Authenticators.BIOMETRIC_STRONG),
    WEAK(BiometricManager.Authenticators.BIOMETRIC_WEAK),
    DEVICE_CREDENTIAL(BiometricManager.Authenticators.DEVICE_CREDENTIAL);
}
