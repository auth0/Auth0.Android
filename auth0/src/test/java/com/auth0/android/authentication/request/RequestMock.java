package com.auth0.android.authentication.request;

import androidx.annotation.NonNull;

import com.auth0.android.Auth0Exception;
import com.auth0.android.callback.BaseCallback;
import com.auth0.android.request.Request;

import java.util.Map;

public class RequestMock<T, U extends Auth0Exception> implements Request<T, U> {
    private T payload;
    private U error;
    private boolean started;

    public RequestMock(T payload, U error) {
        this.payload = payload;
        this.error = error;
    }

    public boolean isStarted() {
        return started;
    }

    @NonNull
    @Override
    public Request<T, U> addParameters(@NonNull Map<String, Object> parameters) {
        return this;
    }

    @NonNull
    @Override
    public Request<T, U> addParameter(@NonNull String name, @NonNull Object value) {
        return this;
    }

    @NonNull
    @Override
    public Request<T, U> addHeader(@NonNull String name, @NonNull String value) {
        return this;
    }

    @Override
    public void start(@NonNull BaseCallback<T, U> callback) {
        started = true;
        if (payload != null) {
            callback.onSuccess(payload);
        } else {
            callback.onFailure(error);
        }
    }

    @NonNull
    @Override
    public T execute() throws Auth0Exception {
        return null;
    }
}
