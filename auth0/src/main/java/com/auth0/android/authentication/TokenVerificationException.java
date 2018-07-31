package com.auth0.android.authentication;

import com.auth0.android.Auth0Exception;

public class TokenVerificationException extends Auth0Exception {

    TokenVerificationException(String message) {
        super(message);
    }

    TokenVerificationException(String message, Throwable cause) {
        super(message, cause);
    }
}
