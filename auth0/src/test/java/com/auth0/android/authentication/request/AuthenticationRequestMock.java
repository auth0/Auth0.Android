package com.auth0.android.authentication.request;

import androidx.annotation.NonNull;

import com.auth0.android.Auth0Exception;
import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.callback.Callback;
import com.auth0.android.request.AuthenticationRequest;
import com.auth0.android.request.Request;
import com.auth0.android.request.RequestValidator;
import com.auth0.android.result.Credentials;

import org.jetbrains.annotations.NotNull;

import java.util.Map;

public class AuthenticationRequestMock implements AuthenticationRequest {
    private final Credentials credentials;
    private final AuthenticationException error;
    private boolean started;

    public AuthenticationRequestMock(Credentials credentials, AuthenticationException error) {
        this.credentials = credentials;
        this.error = error;
    }

    @Override
    public void start(@NonNull Callback<Credentials, AuthenticationException> callback) {
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
    public AuthenticationRequest addParameters(@NonNull Map<String, String> parameters) {
        return this;
    }

    @NonNull
    @Override
    public AuthenticationRequest addParameter(@NonNull String name, @NonNull String value) {
        return this;
    }

    @NonNull
    @Override
    public Request<Credentials, AuthenticationException> addParameter(@NonNull String name, @NonNull Object value) {
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
    public AuthenticationRequest setAudience(@NonNull String audience) {
        return this;
    }

    public boolean isStarted() {
        return started;
    }

    @NonNull
    @Override
    public AuthenticationRequest validateClaims() {
        return this;
    }

    @NonNull
    @Override
    public AuthenticationRequest withIdTokenVerificationLeeway(int leeway) {
        return this;
    }

    @NonNull
    @Override
    public AuthenticationRequest withIdTokenVerificationIssuer(@NonNull String issuer) {
        return this;
    }

    @Override
    public @NotNull AuthenticationRequest addValidator(@NotNull RequestValidator validator) {
        return this;
    }
}
