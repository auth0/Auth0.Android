package com.auth0.android.util;

import androidx.annotation.NonNull;

import com.auth0.android.callback.ManagementCallback;
import com.auth0.android.management.ManagementException;

import java.util.concurrent.Callable;

public class MockManagementCallback<T> implements ManagementCallback<T> {

    private ManagementException error;
    private T payload;

    @Override
    public void onFailure(@NonNull ManagementException error) {
        this.error = error;
    }

    @Override
    public void onSuccess(@NonNull T result) {
        this.payload = result;
    }

    public Callable<ManagementException> error() {
        return new Callable<ManagementException>() {
            @Override
            public ManagementException call() {
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

    public ManagementException getError() {
        return error;
    }

    public T getPayload() {
        return payload;
    }
}
