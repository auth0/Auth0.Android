package com.auth0.android.jwt;

import com.auth0.android.authentication.AuthenticationException;

//TODO: Make pkg private
public class TokenValidationException extends AuthenticationException {
    private static final String ERROR_CODE = "a0.sdk.internal_error.id_token_validation";

    public TokenValidationException(String message) {
        super(ERROR_CODE, message);
    }
}
