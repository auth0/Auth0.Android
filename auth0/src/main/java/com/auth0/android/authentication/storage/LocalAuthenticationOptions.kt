package com.auth0.android.authentication.storage

import androidx.biometric.BiometricManager


public class LocalAuthenticationOptions private constructor(
    public val title: String,
    public val subtitle: String?,
    public val description: String?,
    public val authenticationLevel: AuthenticationLevel,
    public val enableDeviceCredentialFallback: Boolean,
    public val negativeButtonText: String
) {
    public class Builder(
        private var title: String? = null,
        private var subtitle: String? = null,
        private var description: String? = null,
        private var authenticator: AuthenticationLevel = AuthenticationLevel.STRONG,
        private var enableDeviceCredentialFallback: Boolean = false,
        private var negativeButtonText: String = "Cancel"
    ) {

        public fun title(title: String): Builder = apply { this.title = title }
        public fun subtitle(subtitle: String?): Builder = apply { this.subtitle = subtitle }
        public fun description(description: String?): Builder =
            apply { this.description = description }

        public fun authenticator(authenticator: AuthenticationLevel): Builder =
            apply { this.authenticator = authenticator }

        public fun enableDeviceCredentialFallback(enableDeviceCredentialFallback: Boolean): Builder =
            apply { this.enableDeviceCredentialFallback = enableDeviceCredentialFallback }

        public fun negativeButtonText(negativeButtonText: String): Builder =
            apply { this.negativeButtonText = negativeButtonText }

        public fun build(): LocalAuthenticationOptions = LocalAuthenticationOptions(
            title ?: throw IllegalArgumentException("Title must be provided"),
            subtitle,
            description,
            authenticator,
            enableDeviceCredentialFallback,
            negativeButtonText
        )
    }
}

public enum class AuthenticationLevel(public val value: Int) {
    STRONG(BiometricManager.Authenticators.BIOMETRIC_STRONG),
    WEAK(BiometricManager.Authenticators.BIOMETRIC_WEAK),
    DEVICE_CREDENTIAL(BiometricManager.Authenticators.DEVICE_CREDENTIAL);
}