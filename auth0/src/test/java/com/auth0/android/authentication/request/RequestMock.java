package com.auth0.android.authentication.request;

import androidx.annotation.NonNull;

import com.auth0.android.Auth0Exception;
import com.auth0.android.callback.Callback;
import com.auth0.android.request.Request;
import com.auth0.android.request.RequestValidator;

import org.jetbrains.annotations.NotNull;

import java.util.Map;

public class RequestMock<T, U extends Auth0Exception> implements Request<T, U> {
    private final T result;
    private final U error;
    private boolean started;

    public RequestMock(T result, U error) {
        this.result = result;
        this.error = error;
    }

    public boolean isStarted() {
        return started;
    }

    @NonNull
    @Override
    public Request<T, U> addParameters(@NonNull Map<String, String> parameters) {
        return this;
    }

    @NonNull
    @Override
    public Request<T, U> addParameter(@NonNull String name, @NonNull String value) {
        return this;
    }

    @NonNull
    @Override
    public Request<T, U> addHeader(@NonNull String name, @NonNull String value) {
        return this;
    }

    @Override
    public void start(@NonNull Callback<T, U> callback) {
        started = true;
        if (result != null) {
            callback.onSuccess(result);
        } else {
            callback.onFailure(error);
        }
    }

    @NonNull
    @Override
    public T execute() throws Auth0Exception {
        return null;
    }

    @NonNull
    @Override
    public Request<T, U> addParameter(@NonNull String name, @NonNull Object value) {
        return this;
    }

    @Override
    public @NotNull Request<T, @NotNull U> addValidator(@NotNull RequestValidator validator) {
        return this;
    }
}
