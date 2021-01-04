package com.auth0.android;

import androidx.annotation.NonNull;

/**
 * Exception that represents a failure caused when attempting to execute a network request
 */
public class NetworkErrorException extends Auth0Exception {

    public NetworkErrorException(@NonNull Throwable cause) {
        super("Failed to execute the network request", cause);
    }
}
