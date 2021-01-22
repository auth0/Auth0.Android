package com.auth0.android.util;

import androidx.annotation.NonNull;

import com.auth0.android.Auth0Exception;
import com.auth0.android.callback.Callback;

import java.util.concurrent.Callable;

public class MockCallback<T, U extends Auth0Exception> implements Callback<T, U> {

    private T payload;
    private U error;

    @Override
    public void onSuccess(@NonNull T result) {
        this.payload = result;
    }

    @Override
    public void onFailure(@NonNull U error) {
        this.error = error;
    }

    public Callable<T> payload() {
        return () -> payload;
    }

    public Callable<U> error() {
        return () -> error;
    }

    public T getPayload() {
        return payload;
    }

    public U getError() {
        return error;
    }
}
