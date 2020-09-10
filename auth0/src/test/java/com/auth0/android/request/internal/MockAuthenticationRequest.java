package com.auth0.android.request.internal;

import android.support.annotation.NonNull;

import com.auth0.android.Auth0Exception;
import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.callback.BaseCallback;
import com.auth0.android.request.ParameterizableRequest;
import com.auth0.android.result.Credentials;
import com.google.gson.Gson;
import com.squareup.okhttp.HttpUrl;
import com.squareup.okhttp.OkHttpClient;

import java.util.HashMap;
import java.util.Map;

public class MockAuthenticationRequest extends BaseAuthenticationRequest {

    HashMap<String, String> headers;
    HttpUrl url;
    OkHttpClient client;
    Gson gson;
    String method;

    public MockAuthenticationRequest(HttpUrl url, OkHttpClient client, Gson gson, String method) {
        super(url, client, gson, method);
        this.headers = new HashMap<>();
        this.url = url;
        this.client = client;
        this.gson = gson;
        this.method = method;
    }

    @NonNull
    @Override
    public ParameterizableRequest<Credentials, AuthenticationException> addParameters(@NonNull Map<String, Object> parameters) {
        return null;
    }

    @NonNull
    @Override
    public ParameterizableRequest<Credentials, AuthenticationException> addParameter(@NonNull String name, @NonNull Object value) {
        return null;
    }

    @NonNull
    @Override
    public MockAuthenticationRequest addHeader(@NonNull String name, @NonNull String value) {
        headers.put(name, value);
        return this;
    }

    @Override
    public void start(@NonNull BaseCallback<Credentials, AuthenticationException> callback) {

    }

    @NonNull
    @Override
    public Credentials execute() throws Auth0Exception {
        return null;
    }
}
