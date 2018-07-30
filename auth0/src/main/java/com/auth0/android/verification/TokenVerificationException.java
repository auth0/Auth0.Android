package com.auth0.android.verification;

import com.auth0.android.Auth0Exception;

public class TokenVerificationException extends Auth0Exception {

    public TokenVerificationException(String message) {
        super(message);
    }

    public TokenVerificationException(String message, Throwable cause) {
        super(message, cause);
    }
}
