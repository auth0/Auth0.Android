package com.auth0.android.request.internal;

import android.support.annotation.NonNull;

import com.auth0.android.Auth0Exception;
import com.auth0.android.callback.BaseCallback;
import com.auth0.android.request.ErrorBuilder;
import com.auth0.android.request.ParameterizableRequest;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.squareup.okhttp.HttpUrl;
import com.squareup.okhttp.OkHttpClient;

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

    @NonNull
    @Override
    public ParameterizableRequest<T, U> addParameters(@NonNull Map<String, Object> parameters) {
        return this;
    }

    @NonNull
    @Override
    public ParameterizableRequest<T, U> addParameter(@NonNull String name, @NonNull Object value) {
        return this;
    }

    @NonNull
    @Override
    public ParameterizableRequest<T, U> addHeader(@NonNull String name, @NonNull String value) {
        headers.put(name, value);
        return this;
    }

    @Override
    public void start(@NonNull BaseCallback<T, U> callback) {
    }

    @NonNull
    @Override
    public T execute() throws Auth0Exception {
        return null;
    }
}
