package com.auth0.android.authentication.request;

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
    public void start(BaseCallback<Credentials, AuthenticationException> callback) {
        started = true;
        if (credentials != null) {
            callback.onSuccess(credentials);
        } else {
            callback.onFailure(error);
        }
    }

    @Override
    public Credentials execute() throws Auth0Exception {
        return credentials;
    }

    @Override
    public AuthenticationRequest setGrantType(String grantType) {
        return this;
    }

    @Override
    public AuthenticationRequest setConnection(String connection) {
        return this;
    }

    @Override
    public AuthenticationRequest setRealm(String realm) {
        return this;
    }

    @Override
    public AuthenticationRequest setScope(String scope) {
        return this;
    }

    @Override
    public AuthenticationRequest setDevice(String device) {
        return this;
    }

    @Override
    public AuthenticationRequest setAudience(String audience) {
        return this;
    }

    @Override
    public AuthenticationRequest setAccessToken(String accessToken) {
        return this;
    }

    @Override
    public AuthenticationRequest addAuthenticationParameters(Map<String, Object> parameters) {
        return this;
    }

    public boolean isStarted() {
        return started;
    }

}
