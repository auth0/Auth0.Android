package com.auth0.android.authentication.request;

import com.auth0.android.Auth0Exception;
import com.auth0.android.callback.BaseCallback;
import com.auth0.android.request.ParameterizableRequest;

import java.util.Map;

public class ParameterizableRequestMock<T, U extends Auth0Exception> implements ParameterizableRequest<T, U> {
    private T payload;
    private U error;
    private boolean started;

    public ParameterizableRequestMock(T payload, U error) {
        this.payload = payload;
        this.error = error;
    }

    public boolean isStarted() {
        return started;
    }

    @Override
    public ParameterizableRequest<T, U> addParameters(Map<String, Object> parameters) {
        return this;
    }

    @Override
    public ParameterizableRequest<T, U> addParameter(String name, Object value) {
        return this;
    }

    @Override
    public ParameterizableRequest<T, U> addHeader(String name, String value) {
        return this;
    }

    @Override
    public void start(BaseCallback<T, U> callback) {
        started = true;
        if (payload != null) {
            callback.onSuccess(payload);
        } else {
            callback.onFailure(error);
        }
    }

    @Override
    public T execute() throws Auth0Exception {
        return null;
    }
}
