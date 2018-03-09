package com.auth0.android.request.internal;

import com.auth0.android.Auth0Exception;
import com.auth0.android.callback.BaseCallback;
import com.auth0.android.request.ErrorBuilder;
import com.auth0.android.request.ParameterizableRequest;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;

import java.util.HashMap;
import java.util.Map;


public class MockRequest<T, U extends Auth0Exception> implements ParameterizableRequest<T, U> {

    HttpUrl url;
    OkHttpClient client;
    Gson gson;
    String method;
    Class<T> clazz;
    TypeToken<T> typeToken;
    ErrorBuilder<U> builder;
    Map<String, String> headers;

    public MockRequest(HttpUrl url, OkHttpClient client, Gson gson, String method, TypeToken<T> typeToken, ErrorBuilder<U> builder) {
        this.headers = new HashMap<>();
        this.url = url;
        this.client = client;
        this.gson = gson;
        this.method = method;
        this.typeToken = typeToken;
        this.builder = builder;
    }

    public MockRequest(HttpUrl url, OkHttpClient client, Gson gson, String method, Class<T> clazz, ErrorBuilder<U> builder) {
        this.headers = new HashMap<>();
        this.url = url;
        this.client = client;
        this.gson = gson;
        this.method = method;
        this.clazz = clazz;
        this.builder = builder;
    }

    public MockRequest(HttpUrl url, OkHttpClient client, Gson gson, String method, ErrorBuilder<U> builder) {
        this.headers = new HashMap<>();
        this.url = url;
        this.client = client;
        this.gson = gson;
        this.method = method;
        this.builder = builder;
    }

    @Override
    public ParameterizableRequest<T, U> addParameters(Map<String, Object> parameters) {
        return this;
    }

    @Override
    public ParameterizableRequest<T, U> addParameter(String name, Object value) {
        return this;
    }

    @Override
    public ParameterizableRequest<T, U> addHeader(String name, String value) {
        headers.put(name, value);
        return this;
    }

    @Override
    public void start(BaseCallback<T, U> callback) {
    }

    @Override
    public T execute() throws Auth0Exception {
        return null;
    }
}
