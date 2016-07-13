package com.auth0.android.request.internal;

import com.auth0.android.Auth0Exception;
import com.auth0.android.request.ErrorBuilder;
import com.auth0.android.request.ParameterizableRequest;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.squareup.okhttp.HttpUrl;
import com.squareup.okhttp.OkHttpClient;

public class MockRequestFactory extends RequestFactory {

    public MockRequestFactory() {
        super();
    }

    public MockRequestFactory(String token) {
        super(token);
    }

    @Override
    <T, U extends Auth0Exception> ParameterizableRequest<T, U> createSimpleRequest(HttpUrl url, OkHttpClient client, Gson gson, String method, Class<T> clazz, ErrorBuilder<U> errorBuilder) {
        return new MockRequest<>(url, client, gson, method, clazz, errorBuilder);
    }

    @Override
    <T, U extends Auth0Exception> ParameterizableRequest<T, U> createSimpleRequest(HttpUrl url, OkHttpClient client, Gson gson, String method, TypeToken<T> typeToken, ErrorBuilder<U> errorBuilder) {
        return new MockRequest<>(url, client, gson, method, typeToken, errorBuilder);
    }

    @Override
    <T, U extends Auth0Exception> ParameterizableRequest<T, U> createSimpleRequest(HttpUrl url, OkHttpClient client, Gson gson, String method, ErrorBuilder<U> errorBuilder) {
        return new MockRequest<>(url, client, gson, method, errorBuilder);
    }

    @Override
    BaseAuthenticationRequest createAuthenticationRequest(HttpUrl url, OkHttpClient client, Gson gson, String method) {
        return new MockAuthenticationRequest(url, client, gson, method);
    }

    @Override
    <U extends Auth0Exception> ParameterizableRequest<Void, U> createVoidRequest(HttpUrl url, OkHttpClient client, Gson gson, String method, ErrorBuilder<U> errorBuilder) {
        return new MockRequest<>(url, client, gson, method, errorBuilder);
    }
}
