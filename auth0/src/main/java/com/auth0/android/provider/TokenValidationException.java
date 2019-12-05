package com.auth0.android.provider;

import com.auth0.android.authentication.AuthenticationException;

class TokenValidationException extends AuthenticationException {
    private static final String ERROR_CODE = "a0.sdk.internal_error.id_token_validation";

    TokenValidationException(String message) {
        super(ERROR_CODE, message);
    }
}
