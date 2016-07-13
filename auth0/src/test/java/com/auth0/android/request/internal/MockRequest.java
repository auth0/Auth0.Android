package com.auth0.android.request.internal;

import com.auth0.android.Auth0Exception;
import com.auth0.android.request.ErrorBuilder;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.squareup.okhttp.HttpUrl;
import com.squareup.okhttp.OkHttpClient;

public class MockRequest<T, U extends Auth0Exception> extends SimpleRequest<T, U> {

    HttpUrl url;
    OkHttpClient client;
    Gson gson;
    String method;
    Class<T> clazz;
    TypeToken<T> typeToken;
    ErrorBuilder<U> builder;

    public MockRequest(HttpUrl url, OkHttpClient client, Gson gson, String method, TypeToken<T> typeToken, ErrorBuilder<U> builder) {
        super(url, client, gson, method, typeToken, builder);
        this.url = url;
        this.client = client;
        this.gson = gson;
        this.method = method;
        this.typeToken = typeToken;
        this.builder = builder;
    }

    public MockRequest(HttpUrl url, OkHttpClient client, Gson gson, String method, Class<T> clazz, ErrorBuilder<U> builder) {
        super(url, client, gson, method, clazz, builder);
        this.url = url;
        this.client = client;
        this.gson = gson;
        this.method = method;
        this.clazz = clazz;
        this.builder = builder;
    }

    public MockRequest(HttpUrl url, OkHttpClient client, Gson gson, String method, ErrorBuilder<U> builder) {
        super(url, client, gson, method, builder);
        this.url = url;
        this.client = client;
        this.gson = gson;
        this.method = method;
        this.builder = builder;
    }
}
