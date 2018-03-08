package com.auth0.android.authentication.storage;


import com.auth0.android.Auth0Exception;

/**
 * Represents an error raised by the {@link CredentialsManager}.
 */
@SuppressWarnings("WeakerAccess")
public class CredentialsManagerException extends Auth0Exception {

    private CredentialsManagerException(String message, Throwable cause) {
        super(message, cause);
    }

    private CredentialsManagerException(String message) {
        super(message);

    }

    public static CredentialsManagerException create(CredentialsManagerError credentialsManagerError) {
        return new CredentialsManagerException(credentialsManagerError.getMessage());
    }

    public static CredentialsManagerException create(CredentialsManagerError credentialsManagerError, Throwable cause) {
        return new CredentialsManagerException(credentialsManagerError.getMessage(), cause);
    }
}
