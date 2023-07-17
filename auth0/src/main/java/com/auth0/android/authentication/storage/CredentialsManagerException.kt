package com.auth0.android.authentication.storage

import com.auth0.android.Auth0Exception
import com.auth0.android.result.Credentials

/**
 * Represents an error raised by the [CredentialsManager].
 */
public class CredentialsManagerException internal constructor(
    message: String,
    cause: Throwable? = null
) : Auth0Exception(message, cause) {

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