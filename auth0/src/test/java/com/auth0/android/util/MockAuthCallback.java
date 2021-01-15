package com.auth0.android.util;

import android.app.Dialog;
import androidx.annotation.NonNull;

import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.provider.AuthCallback;
import com.auth0.android.result.Credentials;

import java.util.concurrent.Callable;

public class MockAuthCallback implements AuthCallback {

    private AuthenticationException error;
    private Credentials credentials;
    private Dialog dialog;


    public Callable<AuthenticationException> error() {
        return new Callable<AuthenticationException>() {
            @Override
            public AuthenticationException call() {
                return error;
            }
        };
    }

    public Callable<Dialog> dialog() {
        return new Callable<Dialog>() {
            @Override
            public Dialog call() {
                return dialog;
            }
        };
    }

    public Callable<Credentials> credentials() {
        return new Callable<Credentials>() {
            @Override
            public Credentials call() {
                return credentials;
            }
        };
    }

    public AuthenticationException getError() {
        return error;
    }

    public Dialog getErrorDialog() {
        //unused
        return dialog;
    }

    public Credentials getCredentials() {
        return credentials;
    }

    @Override
    public void onFailure(@NonNull Dialog dialog) {
        this.dialog = dialog;
    }

    @Override
    public void onFailure(@NonNull AuthenticationException exception) {
        this.error = exception;
    }

    @Override
    public void onSuccess(@NonNull Credentials credentials) {
        this.credentials = credentials;
    }
}
