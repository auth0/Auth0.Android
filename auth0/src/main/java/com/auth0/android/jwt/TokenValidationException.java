package com.auth0.android.jwt;

import com.auth0.android.authentication.AuthenticationException;

//TODO: Make pkg private
public class TokenValidationException extends AuthenticationException {
    public TokenValidationException(String message) {
        super(message);
    }
}
