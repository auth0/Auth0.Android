package com.auth0.android.request.internal;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import com.auth0.android.Auth0Exception;
import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.request.ErrorBuilder;

import java.util.Map;

public class AuthenticationErrorBuilder implements ErrorBuilder<AuthenticationException> {

    @NonNull
    @Override
    public AuthenticationException from(@NonNull String message) {
        return new AuthenticationException(message);
    }

    @NonNull
    @Override
    public AuthenticationException from(@NonNull String message, @NonNull Auth0Exception exception) {
        return new AuthenticationException(message, exception);
    }

    @NonNull
    @Override
    public AuthenticationException from(@NonNull Map<String, Object> values) {
        return new AuthenticationException(values);
    }

    @NonNull
    @Override
    public AuthenticationException from(@Nullable String payload, int statusCode) {
        return new AuthenticationException(payload, statusCode);
    }
}
