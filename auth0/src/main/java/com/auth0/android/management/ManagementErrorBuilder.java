package com.auth0.android.management;

import com.auth0.android.Auth0Exception;
import com.auth0.android.request.ErrorBuilder;

import java.util.Map;

public class ManagementErrorBuilder implements ErrorBuilder<ManagementException> {

    @Override
    public ManagementException from(String message) {
        return new ManagementException(message);
    }

    @Override
    public ManagementException from(String message, Auth0Exception exception) {
        return new ManagementException(message, exception);
    }

    @Override
    public ManagementException from(Map<String, Object> values) {
        return new ManagementException(values);
    }

    @Override
    public ManagementException from(String payload, int statusCode) {
        return new ManagementException(payload, statusCode);
    }
}
