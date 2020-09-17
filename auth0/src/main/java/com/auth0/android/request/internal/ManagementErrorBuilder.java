package com.auth0.android.request.internal;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import com.auth0.android.Auth0Exception;
import com.auth0.android.management.ManagementException;
import com.auth0.android.request.ErrorBuilder;

import java.util.Map;

public class ManagementErrorBuilder implements ErrorBuilder<ManagementException> {

    @NonNull
    @Override
    public ManagementException from(@NonNull String message) {
        return new ManagementException(message);
    }

    @NonNull
    @Override
    public ManagementException from(@NonNull String message, @NonNull Auth0Exception exception) {
        return new ManagementException(message, exception);
    }

    @NonNull
    @Override
    public ManagementException from(@NonNull Map<String, Object> values) {
        return new ManagementException(values);
    }

    @NonNull
    @Override
    public ManagementException from(@Nullable String payload, int statusCode) {
        return new ManagementException(payload, statusCode);
    }
}
