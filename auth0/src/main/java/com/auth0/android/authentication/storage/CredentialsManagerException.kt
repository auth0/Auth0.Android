package com.auth0.android.authentication.storage

import com.auth0.android.Auth0Exception

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
}