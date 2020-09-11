package com.auth0.android.authentication.request;

import android.support.annotation.NonNull;

import com.auth0.android.Auth0Exception;
import com.auth0.android.callback.BaseCallback;

public class DatabaseConnectionRequestMock<T, U extends Auth0Exception> extends DatabaseConnectionRequest<T, U> {
    private T payload;
    private U error;
    private boolean started;

    public DatabaseConnectionRequestMock(T user, U error) {
        super(null);
        this.payload = user;
        this.error = error;
    }

    @Override
    public void start(@NonNull BaseCallback callback) {
        this.started = true;
        if (payload != null) {
            callback.onSuccess(payload);
        } else {
            callback.onFailure(error);
        }
    }

    boolean isStarted() {
        return started;
    }
}
