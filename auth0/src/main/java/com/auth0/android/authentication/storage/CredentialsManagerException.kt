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
        REVOKE_FAILED,
        LARGE_MIN_TTL,
        INCOMPATIBLE_DEVICE,
        CRYPTO_EXCEPTION,
        BIOMETRIC_NO_ACTIVITY,
        BIOMETRIC_ERROR_STATUS_UNKNOWN,
        BIOMETRIC_ERROR_UNSUPPORTED,
        BIOMETRIC_ERROR_HW_UNAVAILABLE,
        BIOMETRIC_ERROR_NONE_ENROLLED,
        BIOMETRIC_ERROR_NO_HARDWARE,
        BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED,
        BIOMETRIC_ERROR_DEVICE_CREDENTIAL_NOT_AVAILABLE,
        BIOMETRIC_ERROR_STRONG_AND_DEVICE_CREDENTIAL_NOT_AVAILABLE,
        BIOMETRIC_AUTHENTICATION_CHECK_FAILED,
        BIOMETRIC_ERROR_NO_DEVICE_CREDENTIAL,
        BIOMETRIC_ERROR_NEGATIVE_BUTTON,
        BIOMETRIC_ERROR_HW_NOT_PRESENT,
        BIOMETRIC_ERROR_NO_BIOMETRICS,
        BIOMETRIC_ERROR_USER_CANCELED,
        BIOMETRIC_ERROR_LOCKOUT_PERMANENT,
        BIOMETRIC_ERROR_VENDOR,
        BIOMETRIC_ERROR_LOCKOUT,
        BIOMETRIC_ERROR_CANCELED,
        BIOMETRIC_ERROR_NO_SPACE,
        BIOMETRIC_ERROR_TIMEOUT,
        BIOMETRIC_ERROR_UNABLE_TO_PROCESS,
        BIOMETRICS_INVALID_USER,
        BIOMETRIC_AUTHENTICATION_FAILED,
        NO_NETWORK,
        API_ERROR,
        SSO_EXCHANGE_FAILED,
        UNKNOWN_ERROR
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
        public val REVOKE_FAILED: CredentialsManagerException =
            CredentialsManagerException(Code.REVOKE_FAILED)
        public val LARGE_MIN_TTL: CredentialsManagerException =
            CredentialsManagerException(Code.LARGE_MIN_TTL)
        public val INCOMPATIBLE_DEVICE: CredentialsManagerException =
            CredentialsManagerException(Code.INCOMPATIBLE_DEVICE)
        public val CRYPTO_EXCEPTION: CredentialsManagerException =
            CredentialsManagerException(Code.CRYPTO_EXCEPTION)

        // Exceptions thrown when trying to check authentication is possible or not
        public val BIOMETRIC_ERROR_STATUS_UNKNOWN: CredentialsManagerException =
            CredentialsManagerException(Code.BIOMETRIC_ERROR_STATUS_UNKNOWN)
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
        public val BIOMETRIC_ERROR_DEVICE_CREDENTIAL_NOT_AVAILABLE: CredentialsManagerException =
            CredentialsManagerException(Code.BIOMETRIC_ERROR_DEVICE_CREDENTIAL_NOT_AVAILABLE)
        public val BIOMETRIC_ERROR_STRONG_AND_DEVICE_CREDENTIAL_NOT_AVAILABLE: CredentialsManagerException =
            CredentialsManagerException(Code.BIOMETRIC_ERROR_STRONG_AND_DEVICE_CREDENTIAL_NOT_AVAILABLE)
        public val BIOMETRIC_AUTHENTICATION_CHECK_FAILED: CredentialsManagerException =
            CredentialsManagerException(Code.BIOMETRIC_AUTHENTICATION_CHECK_FAILED)


        // Exceptions thrown when trying to authenticate with biometrics
        public val BIOMETRIC_ERROR_NO_ACTIVITY: CredentialsManagerException =
            CredentialsManagerException(Code.BIOMETRIC_NO_ACTIVITY)
        public val BIOMETRIC_ERROR_NO_DEVICE_CREDENTIAL: CredentialsManagerException =
            CredentialsManagerException(Code.BIOMETRIC_ERROR_NO_DEVICE_CREDENTIAL)
        public val BIOMETRIC_ERROR_NEGATIVE_BUTTON: CredentialsManagerException =
            CredentialsManagerException(Code.BIOMETRIC_ERROR_NEGATIVE_BUTTON)
        public val BIOMETRIC_ERROR_HW_NOT_PRESENT: CredentialsManagerException =
            CredentialsManagerException(Code.BIOMETRIC_ERROR_HW_NOT_PRESENT)
        public val BIOMETRIC_ERROR_NO_BIOMETRICS: CredentialsManagerException =
            CredentialsManagerException(Code.BIOMETRIC_ERROR_NO_BIOMETRICS)
        public val BIOMETRIC_ERROR_USER_CANCELED: CredentialsManagerException =
            CredentialsManagerException(Code.BIOMETRIC_ERROR_USER_CANCELED)
        public val BIOMETRIC_ERROR_LOCKOUT_PERMANENT: CredentialsManagerException =
            CredentialsManagerException(Code.BIOMETRIC_ERROR_LOCKOUT_PERMANENT)
        public val BIOMETRIC_ERROR_VENDOR: CredentialsManagerException =
            CredentialsManagerException(Code.BIOMETRIC_ERROR_VENDOR)
        public val BIOMETRIC_ERROR_LOCKOUT: CredentialsManagerException =
            CredentialsManagerException(Code.BIOMETRIC_ERROR_LOCKOUT)
        public val BIOMETRIC_ERROR_CANCELED: CredentialsManagerException =
            CredentialsManagerException(Code.BIOMETRIC_ERROR_CANCELED)
        public val BIOMETRIC_ERROR_NO_SPACE: CredentialsManagerException =
            CredentialsManagerException(Code.BIOMETRIC_ERROR_NO_SPACE)
        public val BIOMETRIC_ERROR_TIMEOUT: CredentialsManagerException =
            CredentialsManagerException(Code.BIOMETRIC_ERROR_TIMEOUT)
        public val BIOMETRIC_ERROR_UNABLE_TO_PROCESS: CredentialsManagerException =
            CredentialsManagerException(Code.BIOMETRIC_ERROR_UNABLE_TO_PROCESS)
        public val BIOMETRIC_AUTHENTICATION_FAILED: CredentialsManagerException =
            CredentialsManagerException(Code.BIOMETRIC_AUTHENTICATION_FAILED)
        public val BIOMETRICS_INVALID_USER: CredentialsManagerException =
            CredentialsManagerException(Code.BIOMETRICS_INVALID_USER)

        //Exceptions thrown when making api calls for access token renewal
        public val NO_NETWORK: CredentialsManagerException =
            CredentialsManagerException(Code.NO_NETWORK)
        public val API_ERROR: CredentialsManagerException =
            CredentialsManagerException(Code.API_ERROR)
        public val SSO_EXCHANGE_FAILED: CredentialsManagerException =
            CredentialsManagerException(Code.SSO_EXCHANGE_FAILED)

        public val UNKNOWN_ERROR: CredentialsManagerException = CredentialsManagerException(Code.UNKNOWN_ERROR)


        private fun getMessage(code: Code): String {
            return when (code) {
                Code.INVALID_CREDENTIALS -> "Credentials must have a valid access_token or id_token value."
                Code.NO_CREDENTIALS -> "No Credentials were previously set."
                Code.NO_REFRESH_TOKEN -> "Credentials need to be renewed but no Refresh Token is available to renew them."
                Code.RENEW_FAILED -> "An error occurred while trying to use the Refresh Token to renew the Credentials."
                Code.STORE_FAILED -> "An error occurred while saving the refreshed Credentials."
                Code.REVOKE_FAILED -> "The revocation of the refresh token failed."
                Code.LARGE_MIN_TTL -> "The minTTL requested is greater than the lifetime of the renewed access token. Request a lower minTTL or increase the 'Token Expiration' value in the settings page of your Auth0 API."
                Code.INCOMPATIBLE_DEVICE -> String.format(
                    "This device is not compatible with the %s class.",
                    SecureCredentialsManager::class.java.simpleName
                )

                Code.CRYPTO_EXCEPTION -> "A change on the Lock Screen security settings have deemed the encryption keys invalid and have been recreated. Any previously stored content is now lost. Please try saving the credentials again."

                Code.BIOMETRIC_NO_ACTIVITY -> "Cannot authenticate as the activity passed is null."
                Code.BIOMETRIC_ERROR_STATUS_UNKNOWN -> "Unable to determine whether the user can authenticate."
                Code.BIOMETRIC_ERROR_UNSUPPORTED -> "Cannot authenticate because the specified options are incompatible with the current Android version."
                Code.BIOMETRIC_ERROR_HW_UNAVAILABLE -> "Cannot authenticate because the hardware is unavailable. Try again later."
                Code.BIOMETRIC_ERROR_NONE_ENROLLED -> "Cannot authenticate because no biometric or device credential is enrolled for the user."
                Code.BIOMETRIC_ERROR_NO_HARDWARE -> "Cannot authenticate because there is no suitable hardware (e.g. no biometric sensor or no keyguard)."
                Code.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> "Cannot authenticate because a security vulnerability has been discovered with one or more hardware sensors. The affected sensor(s) are unavailable until a security update has addressed the issue."
                Code.BIOMETRIC_AUTHENTICATION_CHECK_FAILED -> "Cannot authenticate as failed to determine if the user can authenticate with an authenticator that meets the given requirements."
                Code.BIOMETRIC_ERROR_DEVICE_CREDENTIAL_NOT_AVAILABLE -> "Cannot authenticate as DEVICE_CREDENTIAL alone as a authentication level is not supported on Android API Level less than 30"
                Code.BIOMETRIC_ERROR_STRONG_AND_DEVICE_CREDENTIAL_NOT_AVAILABLE -> "Cannot authenticate as BIOMETRIC_STRONG authentication level along with device credential fallback being enabled is not supported on Android API Levels 28 & 29"

                Code.BIOMETRIC_ERROR_NO_DEVICE_CREDENTIAL -> "Failed to authenticate because the device does not have pin, pattern, or password setup."
                Code.BIOMETRIC_ERROR_NEGATIVE_BUTTON -> "Failed to authenticate as the user pressed the negative button."
                Code.BIOMETRIC_ERROR_HW_NOT_PRESENT -> "Failed to authenticate because the device does not have the required authentication hardware."
                Code.BIOMETRIC_ERROR_NO_BIOMETRICS -> "Failed to authenticate because the user does not have any biometrics enrolled."
                Code.BIOMETRIC_ERROR_USER_CANCELED -> "Failed to authenticate because the user canceled the operation."
                Code.BIOMETRIC_ERROR_LOCKOUT_PERMANENT -> "Failed to authenticate because the user has been permanently locked out."
                Code.BIOMETRIC_ERROR_VENDOR -> "Failed to authenticate because of a vendor-specific error."
                Code.BIOMETRIC_ERROR_LOCKOUT -> "Failed to authenticate because the user has been temporarily locked out, this occurs after 5 failed attempts and lasts for 30 seconds."
                Code.BIOMETRIC_ERROR_CANCELED -> "Failed to authenticate because the operation was canceled as the biometric sensor is unavailable, this may happen when the user is switched, the device is locked."
                Code.BIOMETRIC_ERROR_NO_SPACE -> "Failed to authenticate because there is not enough storage remaining on the device."
                Code.BIOMETRIC_ERROR_TIMEOUT -> "Failed to authenticate because the operation timed out."
                Code.BIOMETRIC_ERROR_UNABLE_TO_PROCESS -> "Failed to authenticate because the sensor was unable to process the current image."
                Code.BIOMETRICS_INVALID_USER -> "The user didn't pass the authentication challenge."
                Code.BIOMETRIC_AUTHENTICATION_FAILED -> "Biometric authentication failed."
                Code.NO_NETWORK -> "Failed to execute the network request."
                Code.API_ERROR -> "An error occurred while processing the request."
                Code.SSO_EXCHANGE_FAILED ->"The exchange of the refresh token for SSO credentials failed."
                Code.UNKNOWN_ERROR -> "An unknown error has occurred while fetching the token. Please check the error cause for more details."
            }
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CredentialsManagerException) return false
        return code == other.code
    }

    override fun hashCode(): Int {
        return code.hashCode()
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