package com.auth0.android.provider;

import com.auth0.android.Auth0Exception;

class TokenValidationException extends Auth0Exception {

    TokenValidationException(String message) {
        super(message);
    }
}
