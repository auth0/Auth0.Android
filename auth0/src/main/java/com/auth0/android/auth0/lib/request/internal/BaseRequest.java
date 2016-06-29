/*
 * BaseRequest.java
 *
 * Copyright (c) 2015 Auth0 (http://auth0.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package com.auth0.android.auth0.lib.request.internal;

import com.auth0.android.auth0.lib.Auth0Exception;
import com.auth0.android.auth0.lib.RequestBodyBuildException;
import com.auth0.android.auth0.lib.authentication.ParameterBuilder;
import com.auth0.android.auth0.lib.callback.BaseCallback;
import com.auth0.android.auth0.lib.request.AuthorizableRequest;
import com.auth0.android.auth0.lib.request.ErrorBuilder;
import com.auth0.android.auth0.lib.request.ParameterizableRequest;
import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import com.google.gson.TypeAdapter;
import com.google.gson.reflect.TypeToken;
import com.squareup.okhttp.Callback;
import com.squareup.okhttp.HttpUrl;
import com.squareup.okhttp.OkHttpClient;
import com.squareup.okhttp.Request;
import com.squareup.okhttp.RequestBody;
import com.squareup.okhttp.Response;

import java.io.IOException;
import java.io.Reader;
import java.lang.reflect.Type;
import java.util.HashMap;
import java.util.Map;

abstract class BaseRequest<T, U extends Auth0Exception> implements ParameterizableRequest<T, U>, AuthorizableRequest<T, U>, Callback {

    private final Map<String, String> headers;
    protected final HttpUrl url;
    protected final OkHttpClient client;
    private final TypeAdapter<T> adapter;
    private final Gson gson;
    private final ParameterBuilder builder;
    private final ErrorBuilder<U> errorBuilder;

    private BaseCallback<T, U> callback;

    protected BaseRequest(HttpUrl url, OkHttpClient client, Gson gson, TypeAdapter<T> adapter, ErrorBuilder<U> errorBuilder) {
        this(url, client, gson, adapter, errorBuilder, null);
    }

    public BaseRequest(HttpUrl url, OkHttpClient client, Gson gson, TypeAdapter<T> adapter, ErrorBuilder<U> errorBuilder, BaseCallback<T, U> callback) {
        this.url = url;
        this.client = client;
        this.gson = gson;
        this.adapter = adapter;
        this.callback = callback;
        this.headers = new HashMap<>();
        this.builder = ParameterBuilder.newBuilder();
        this.errorBuilder = errorBuilder;
    }

    protected void setCallback(BaseCallback<T, U> callback) {
        this.callback = callback;
    }

    protected void postOnSuccess(final T payload) {
        this.callback.onSuccess(payload);
    }

    protected final void postOnFailure(final U error) {
        this.callback.onFailure(error);
    }

    protected Request.Builder newBuilder() {
        final Request.Builder builder = new Request.Builder()
                .url(url);
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            builder.addHeader(entry.getKey(), entry.getValue());
        }
        return builder;
    }

    protected TypeAdapter<T> getAdapter() {
        return adapter;
    }

    protected ErrorBuilder<U> getErrorBuilder() {
        return errorBuilder;
    }

    protected RequestBody buildBody() throws RequestBodyBuildException {
        Map<String, Object> dictionary = builder.asDictionary();
        if (!dictionary.isEmpty()) {
            return JsonRequestBodyBuilder.createBody(dictionary, gson);
        }
        return null;
    }

    protected U parseUnsuccessfulResponse(Response response) {
        try {
            final Reader charStream = response.body().charStream();
            Type mapType = new TypeToken<Map<String, Object>>() {
            }.getType();
            Map<String, Object> mapPayload = gson.fromJson(charStream, mapType);
            return errorBuilder.from(mapPayload);
        } catch (JsonSyntaxException e) {
            try {
                String stringPayload = response.body().string();
                return errorBuilder.from(stringPayload, response.code());
            } catch (IOException e1) {
                final Auth0Exception auth0Exception = new Auth0Exception("Error parsing the server response", e);
                return errorBuilder.from("Request to " + url.toString() + " failed", auth0Exception);
            }
        } catch (IOException e) {
            final Auth0Exception auth0Exception = new Auth0Exception("Error parsing the server response", e);
            return errorBuilder.from("Request to " + url.toString() + " failed", auth0Exception);
        }
    }

    @Override
    public void onFailure(Request request, IOException e) {
        Auth0Exception exception = new Auth0Exception("Failed to execute request to " + url.toString(), e);
        postOnFailure(errorBuilder.from("Request failed", exception));
    }

    @Override
    public ParameterizableRequest<T, U> addHeader(String name, String value) {
        headers.put(name, value);
        return this;
    }

    @Override
    public AuthorizableRequest<T, U> setBearer(String jwt) {
        addHeader("Authorization", "Bearer " + jwt);
        return this;
    }

    @Override
    public ParameterizableRequest<T, U> addParameters(Map<String, Object> parameters) {
        builder.addAll(parameters);
        return this;
    }

    @Override
    public ParameterizableRequest<T, U> addParameter(String name, Object value) {
        builder.set(name, value);
        return this;
    }

    @Override
    public void start(BaseCallback<T, U> callback) {
        setCallback(callback);
        try {
            Request request = doBuildRequest(newBuilder());
            client.newCall(request).enqueue(this);
        } catch (RequestBodyBuildException e) {
            final U exception = errorBuilder.from("Error parsing the request body", e);
            callback.onFailure(exception);
        }
    }

    protected abstract Request doBuildRequest(Request.Builder builder);
}
