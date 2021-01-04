package com.auth0.android.authentication.storage;


import com.auth0.android.Auth0Exception;

/**
 * Represents an error raised by the {@link CredentialsManager}.
 */
@SuppressWarnings("WeakerAccess")
public class CredentialsManagerException extends Auth0Exception {
    CredentialsManagerException(String message, Throwable cause) {
        super(message, cause);
    }

    CredentialsManagerException(String message) {
        super(message);
    }

    /**
     * Returns true when this Android device doesn't support the cryptographic algorithms used
     * to handle encryption and decryption, false otherwise.
     *
     * @return whether this device is compatible with {@link SecureCredentialsManager} or not.
     */
    public boolean isDeviceIncompatible() {
        return (getCause() instanceof IncompatibleDeviceException);
    }
}
