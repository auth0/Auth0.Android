package com.auth0.android.auth0.lib.authentication;

import com.auth0.android.auth0.lib.Auth0Exception;
import com.auth0.android.auth0.lib.request.ErrorBuilder;

import java.util.Map;

public class AuthenticationErrorBuilder implements ErrorBuilder<AuthenticationException> {

    @Override
    public AuthenticationException from(String message) {
        return new AuthenticationException(message);
    }

    @Override
    public AuthenticationException from(String message, Auth0Exception exception) {
        return new AuthenticationException(message, exception);
    }

    @Override
    public AuthenticationException from(Map<String, Object> values) {
        return new AuthenticationException(values);
    }

    @Override
    public AuthenticationException from(String payload, int statusCode) {
        return new AuthenticationException(payload, statusCode);
    }
}
