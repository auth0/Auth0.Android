package com.auth0.android.util;

import androidx.annotation.NonNull;

import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.callback.AuthenticationCallback;

import java.util.concurrent.Callable;

public class MockAuthenticationCallback<T> implements AuthenticationCallback<T> {

    private AuthenticationException error;
    private T payload;

    @Override
    public void onFailure(@NonNull AuthenticationException error) {
        this.error = error;
    }

    @Override
    public void onSuccess(@NonNull T result) {
        this.payload = result;
    }

    public Callable<AuthenticationException> error() {
        return new Callable<AuthenticationException>() {
            @Override
            public AuthenticationException call() {
                return error;
            }
        };
    }

    public Callable<T> payload() {
        return new Callable<T>() {
            @Override
            public T call() {
                return payload;
            }
        };
    }

    public AuthenticationException getError() {
        return error;
    }

    public T getPayload() {
        return payload;
    }
}
