package com.auth0.android.authentication.storage

import com.auth0.android.Auth0Exception
import com.auth0.android.result.Credentials

/**
 * Represents an error raised by the [CredentialsManager].
 */
public class CredentialsManagerException :
    Auth0Exception {

    internal enum class Code {
        INVALID_CREDENTIALS,
        NO_CREDENTIALS,
        NO_REFRESH_TOKEN,
        RENEW_FAILED,
        STORE_FAILED,
        BIOMETRICS_FAILED,
        REVOKE_FAILED,
        LARGE_MIN_TTL,
        INCOMPATIBLE_DEVICE,
        CRYPTO_EXCEPTION,
        BIOMETRICS_PACKAGE_NOT_FOUND,
        BIOMETRIC_STATUS_UNKNOWN,
        BIOMETRIC_AUTHENTICATION_CHECK_FAILED,
        BIOMETRIC_ERROR_UNSUPPORTED,
        BIOMETRIC_ERROR_HW_UNAVAILABLE,
        BIOMETRIC_ERROR_NONE_ENROLLED,
        BIOMETRIC_ERROR_NO_HARDWARE,
        BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED,
    }

    private var code: Code?


    internal constructor(code: Code, cause: Throwable? = null) : this(
        code,
        getMessage(code),
        cause
    )

    internal constructor(code: Code, message: String, cause: Throwable? = null) : super(
        message,
        cause
    ) {
        this.code = code
    }

    public companion object {

        public val INVALID_CREDENTIALS: CredentialsManagerException =
            CredentialsManagerException(Code.INVALID_CREDENTIALS)
        public val NO_CREDENTIALS: CredentialsManagerException =
            CredentialsManagerException(Code.NO_CREDENTIALS)
        public val NO_REFRESH_TOKEN: CredentialsManagerException =
            CredentialsManagerException(Code.NO_REFRESH_TOKEN)
        public val RENEW_FAILED: CredentialsManagerException =
            CredentialsManagerException(Code.RENEW_FAILED)
        public val STORE_FAILED: CredentialsManagerException =
            CredentialsManagerException(Code.STORE_FAILED)
        public val BIOMETRICS_FAILED: CredentialsManagerException =
            CredentialsManagerException(Code.BIOMETRICS_FAILED)
        public val REVOKE_FAILED: CredentialsManagerException =
            CredentialsManagerException(Code.REVOKE_FAILED)
        public val LARGE_MIN_TTL: CredentialsManagerException =
            CredentialsManagerException(Code.LARGE_MIN_TTL)
        public val INCOMPATIBLE_DEVICE: CredentialsManagerException =
            CredentialsManagerException(Code.INCOMPATIBLE_DEVICE)
        public val CRYPTO_EXCEPTION: CredentialsManagerException =
            CredentialsManagerException(Code.CRYPTO_EXCEPTION)
        public val BIOMETRICS_PACKAGE_NOT_FOUND: CredentialsManagerException =
            CredentialsManagerException(Code.BIOMETRICS_PACKAGE_NOT_FOUND)
        public val BIOMETRIC_STATUS_UNKNOWN: CredentialsManagerException =
            CredentialsManagerException(Code.BIOMETRIC_STATUS_UNKNOWN)
        public val BIOMETRIC_ERROR_UNSUPPORTED: CredentialsManagerException =
            CredentialsManagerException(Code.BIOMETRIC_ERROR_UNSUPPORTED)
        public val BIOMETRIC_ERROR_HW_UNAVAILABLE: CredentialsManagerException =
            CredentialsManagerException(Code.BIOMETRIC_ERROR_HW_UNAVAILABLE)
        public val BIOMETRIC_ERROR_NONE_ENROLLED: CredentialsManagerException =
            CredentialsManagerException(Code.BIOMETRIC_ERROR_NONE_ENROLLED)
        public val BIOMETRIC_ERROR_NO_HARDWARE: CredentialsManagerException =
            CredentialsManagerException(Code.BIOMETRIC_ERROR_NO_HARDWARE)
        public val BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED: CredentialsManagerException =
            CredentialsManagerException(Code.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED)
        public val BIOMETRIC_AUTHENTICATION_CHECK_FAILED: CredentialsManagerException =
            CredentialsManagerException(Code.BIOMETRIC_AUTHENTICATION_CHECK_FAILED)


        private fun getMessage(code: Code): String {
            return when (code) {
                Code.INVALID_CREDENTIALS -> "Credentials must have a valid access_token or id_token value."
                Code.NO_CREDENTIALS -> "No Credentials were previously set."
                Code.NO_REFRESH_TOKEN -> "Credentials need to be renewed but no Refresh Token is available to renew them."
                Code.RENEW_FAILED -> "An error occurred while trying to use the Refresh Token to renew the Credentials."
                Code.STORE_FAILED -> "An error occurred while saving the refreshed Credentials."
                Code.BIOMETRICS_FAILED -> "The user didn't pass the authentication challenge."
                Code.REVOKE_FAILED -> "The revocation of the refresh token failed."
                Code.LARGE_MIN_TTL -> "The minTTL requested is greater than the lifetime of the renewed access token. Request a lower minTTL or increase the 'Token Expiration' value in the settings page of your Auth0 API."
                Code.INCOMPATIBLE_DEVICE -> String.format(
                    "This device is not compatible with the %s class.",
                    SecureCredentialsManager::class.java.simpleName
                )

                Code.CRYPTO_EXCEPTION -> "A change on the Lock Screen security settings have deemed the encryption keys invalid and have been recreated. Please try saving the credentials again."
                Code.BIOMETRICS_PACKAGE_NOT_FOUND -> "Package androidx.biometric:biometric is not found. Please add it to your dependencies to enable authentication before retrieving credentials."
                Code.BIOMETRIC_STATUS_UNKNOWN -> "Unable to determine whether the user can authenticate."
                Code.BIOMETRIC_ERROR_UNSUPPORTED -> "Cannot authenticate because the specified options are incompatible with the current Android version."
                Code.BIOMETRIC_ERROR_HW_UNAVAILABLE -> "Cannot authenticate because the hardware is unavailable. Try again later."
                Code.BIOMETRIC_ERROR_NONE_ENROLLED -> "Cannot authenticate because no biometric or device credential is enrolled for the user."
                Code.BIOMETRIC_ERROR_NO_HARDWARE -> "Cannot authenticate because there is no suitable hardware (e.g. no biometric sensor or no keyguard)."
                Code.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> "Cannot authenticate because a security vulnerability has been discovered with one or more hardware sensors. The affected sensor(s) are unavailable until a security update has addressed the issue."
                Code.BIOMETRIC_AUTHENTICATION_CHECK_FAILED -> "Failed to determine if the user can authenticate with an authenticator that meets the given requirements"
            }
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CredentialsManagerException) return false
        return code == other.code
    }

    /**
     * Returns true when this Android device doesn't support the cryptographic algorithms used
     * to handle encryption and decryption, false otherwise.
     *
     * @return whether this device is compatible with [SecureCredentialsManager] or not.
     */
    public val isDeviceIncompatible: Boolean
        get() = cause is IncompatibleDeviceException

    /**
     * Returns the refreshed [Credentials] if exception is thrown right before saving them.
     * This will avoid users being logged out unnecessarily and allows to handle failure case as needed
     *
     * Set incase [IncompatibleDeviceException] or [CryptoException] is thrown while saving the refreshed [Credentials]
     */
    public var refreshedCredentials: Credentials? = null
        internal set
}