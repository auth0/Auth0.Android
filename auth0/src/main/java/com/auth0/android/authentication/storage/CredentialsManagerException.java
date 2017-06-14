package com.auth0.android.authentication.storage;


import com.auth0.android.Auth0Exception;

public class CredentialsManagerException extends Auth0Exception {
    public CredentialsManagerException(String message, Throwable cause) {
        super(message, cause);
    }

    public CredentialsManagerException(String message) {
        super(message);
    }
}
