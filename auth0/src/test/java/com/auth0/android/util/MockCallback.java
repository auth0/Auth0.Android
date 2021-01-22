package com.auth0.android.util;

import androidx.annotation.NonNull;

import com.auth0.android.Auth0Exception;
import com.auth0.android.callback.Callback;

import java.util.concurrent.Callable;

public class MockCallback<T, U extends Auth0Exception> implements Callback<T, U> {

    private T payload;
    private U error;

    @Override
    public void onSuccess(@NonNull T payload) {
        this.payload = payload;
    }

    @Override
    public void onFailure(@NonNull U error) {
        this.error = error;
    }

    public Callable<T> payload() {
        return new Callable<T>() {
            @Override
            public T call() {
                return payload;
            }
        };
    }

    public Callable<U> error() {
        return new Callable<U>() {
            @Override
            public U call() {
                return error;
            }
        };
    }

    public T getPayload() {
        return payload;
    }

    public U getError() {
        return error;
    }
}
