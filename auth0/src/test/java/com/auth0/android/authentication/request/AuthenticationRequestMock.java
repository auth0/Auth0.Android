package com.auth0.android.authentication.request;

import androidx.annotation.NonNull;

import com.auth0.android.Auth0Exception;
import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.callback.BaseCallback;
import com.auth0.android.request.AuthenticationRequest;
import com.auth0.android.result.Credentials;

import java.util.Map;

public class AuthenticationRequestMock implements AuthenticationRequest {
    private Credentials credentials;
    private AuthenticationException error;
    private boolean started;

    public AuthenticationRequestMock(Credentials credentials, AuthenticationException error) {
        this.credentials = credentials;
        this.error = error;
    }

    @Override
    public void start(@NonNull BaseCallback<Credentials, AuthenticationException> callback) {
        started = true;
        if (credentials != null) {
            callback.onSuccess(credentials);
        } else {
            callback.onFailure(error);
        }
    }

    @NonNull
    @Override
    public Credentials execute() throws Auth0Exception {
        return credentials;
    }

    @NonNull
    @Override
    public AuthenticationRequest addParameters(@NonNull Map<String, Object> parameters) {
        return this;
    }

    @NonNull
    @Override
    public AuthenticationRequest addParameter(@NonNull String name, @NonNull Object value) {
        return this;
    }

    @NonNull
    @Override
    public AuthenticationRequest addHeader(@NonNull String name, @NonNull String value) {
        return this;
    }

    @NonNull
    @Override
    public AuthenticationRequest setGrantType(@NonNull String grantType) {
        return this;
    }

    @NonNull
    @Override
    public AuthenticationRequest setConnection(@NonNull String connection) {
        return this;
    }

    @NonNull
    @Override
    public AuthenticationRequest setRealm(@NonNull String realm) {
        return this;
    }

    @NonNull
    @Override
    public AuthenticationRequest setScope(@NonNull String scope) {
        return this;
    }

    @NonNull
    @Override
    public AuthenticationRequest setDevice(@NonNull String device) {
        return this;
    }

    @NonNull
    @Override
    public AuthenticationRequest setAudience(@NonNull String audience) {
        return this;
    }

    @NonNull
    @Override
    public AuthenticationRequest setAccessToken(@NonNull String accessToken) {
        return this;
    }

    @NonNull
    @Override
    public AuthenticationRequest addAuthenticationParameters(@NonNull Map<String, Object> parameters) {
        return this;
    }

    public boolean isStarted() {
        return started;
    }

}
