package com.auth0.android.request.internal;

import com.auth0.android.Auth0Exception;
import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.callback.BaseCallback;
import com.auth0.android.request.AuthenticationRequest;
import com.auth0.android.request.ParameterizableRequest;
import com.auth0.android.result.Credentials;
import com.google.gson.Gson;
import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;

import java.util.HashMap;
import java.util.Map;

public class MockAuthenticationRequest implements ParameterizableRequest<Credentials, AuthenticationException>, AuthenticationRequest {

    HashMap<String, String> headers;
    HttpUrl url;
    OkHttpClient client;
    Gson gson;
    String method;

    public MockAuthenticationRequest(HttpUrl url, OkHttpClient client, Gson gson, String method) {
        this.headers = new HashMap<>();
        this.url = url;
        this.client = client;
        this.gson = gson;
        this.method = method;
    }

    @Override
    public AuthenticationRequest setGrantType(String grantType) {
        return null;
    }

    @Override
    public AuthenticationRequest setConnection(String connection) {
        return null;
    }

    @Override
    public AuthenticationRequest setRealm(String realm) {
        return null;
    }

    @Override
    public AuthenticationRequest setScope(String scope) {
        return null;
    }

    @Override
    public AuthenticationRequest setDevice(String device) {
        return null;
    }

    @Override
    public AuthenticationRequest setAudience(String audience) {
        return null;
    }

    @Override
    public AuthenticationRequest setAccessToken(String accessToken) {
        return null;
    }

    @Override
    public AuthenticationRequest addAuthenticationParameters(Map<String, Object> parameters) {
        return null;
    }

    @Override
    public ParameterizableRequest<Credentials, AuthenticationException> addParameters(Map<String, Object> parameters) {
        return null;
    }

    @Override
    public ParameterizableRequest<Credentials, AuthenticationException> addParameter(String name, Object value) {
        return null;
    }

    @Override
    public ParameterizableRequest<Credentials, AuthenticationException> addHeader(String name, String value) {
        headers.put(name, value);
        return this;
    }

    @Override
    public void start(BaseCallback<Credentials, AuthenticationException> callback) {

    }

    @Override
    public Credentials execute() throws Auth0Exception {
        return null;
    }
}
