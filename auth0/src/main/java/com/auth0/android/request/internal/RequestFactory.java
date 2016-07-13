/*
 * RequestFactory.java
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

package com.auth0.android.request.internal;

import android.support.annotation.NonNull;

import com.auth0.android.Auth0Exception;
import com.auth0.android.request.AuthenticationRequest;
import com.auth0.android.request.ErrorBuilder;
import com.auth0.android.request.ParameterizableRequest;
import com.auth0.android.result.Credentials;
import com.auth0.android.util.Telemetry;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.squareup.okhttp.HttpUrl;
import com.squareup.okhttp.OkHttpClient;

import java.util.HashMap;
import java.util.Map;

public class RequestFactory {

    static final String AUTHORIZATION_HEADER = "Authorization";
    static final String USER_AGENT_HEADER = "User-Agent";
    static final String CLIENT_INFO_HEADER = Telemetry.HEADER_NAME;

    private final HashMap<String, String> headers;

    public RequestFactory() {
        headers = new HashMap<>();
    }

    public RequestFactory(@NonNull String bearerToken) {
        this();
        headers.put(AUTHORIZATION_HEADER, "Bearer " + bearerToken);
    }

    public void setClientInfo(String clientInfo) {
        headers.put(CLIENT_INFO_HEADER, clientInfo);
    }

    public void setUserAgent(String userAgent) {
        headers.put(USER_AGENT_HEADER, userAgent);
    }


    public AuthenticationRequest authenticationPOST(HttpUrl url, OkHttpClient client, Gson gson) {
        final BaseAuthenticationRequest request = createAuthenticationRequest(url, client, gson, "POST");
        addMetrics(request);
        return request;
    }

    public <T, U extends Auth0Exception> ParameterizableRequest<T, U> POST(HttpUrl url, OkHttpClient client, Gson gson, Class<T> clazz, ErrorBuilder<U> errorBuilder) {
        final ParameterizableRequest<T, U> request = createSimpleRequest(url, client, gson, "POST", clazz, errorBuilder);
        addMetrics(request);
        return request;
    }

    public <T, U extends Auth0Exception> ParameterizableRequest<T, U> POST(HttpUrl url, OkHttpClient client, Gson gson, TypeToken<T> typeToken, ErrorBuilder<U> errorBuilder) {
        final ParameterizableRequest<T, U> request = createSimpleRequest(url, client, gson, "POST", typeToken, errorBuilder);
        addMetrics(request);
        return request;
    }

    public <U extends Auth0Exception> ParameterizableRequest<Map<String, Object>, U> rawPOST(HttpUrl url, OkHttpClient client, Gson gson, ErrorBuilder<U> errorBuilder) {
        final ParameterizableRequest<Map<String, Object>, U> request = createSimpleRequest(url, client, gson, "POST", errorBuilder);
        addMetrics(request);
        return request;
    }

    public <U extends Auth0Exception> ParameterizableRequest<Void, U> POST(HttpUrl url, OkHttpClient client, Gson gson, ErrorBuilder<U> errorBuilder) {
        final ParameterizableRequest<Void, U> request = createVoidRequest(url, client, gson, "POST", errorBuilder);
        addMetrics(request);
        return request;
    }

    public <T, U extends Auth0Exception> ParameterizableRequest<T, U> PATCH(HttpUrl url, OkHttpClient client, Gson gson, Class<T> clazz, ErrorBuilder<U> errorBuilder) {
        final ParameterizableRequest<T, U> request = createSimpleRequest(url, client, gson, "PATCH", clazz, errorBuilder);
        addMetrics(request);
        return request;
    }

    public <T, U extends Auth0Exception> ParameterizableRequest<T, U> DELETE(HttpUrl url, OkHttpClient client, Gson gson, TypeToken<T> typeToken, ErrorBuilder<U> errorBuilder) {
        final ParameterizableRequest<T, U> request = createSimpleRequest(url, client, gson, "DELETE", typeToken, errorBuilder);
        addMetrics(request);
        return request;
    }

    private <T, U extends Auth0Exception> void addMetrics(ParameterizableRequest<T, U> request) {
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            request.addHeader(entry.getKey(), entry.getValue());
        }
    }

    <T, U extends Auth0Exception> ParameterizableRequest<T, U> createSimpleRequest(HttpUrl url, OkHttpClient client, Gson gson, String method, Class<T> clazz, ErrorBuilder<U> errorBuilder) {
        return new SimpleRequest<>(url, client, gson, method, clazz, errorBuilder);
    }

    <T, U extends Auth0Exception> ParameterizableRequest<T, U> createSimpleRequest(HttpUrl url, OkHttpClient client, Gson gson, String method, TypeToken<T> typeToken, ErrorBuilder<U> errorBuilder) {
        return new SimpleRequest<>(url, client, gson, method, typeToken, errorBuilder);
    }

    <T, U extends Auth0Exception> ParameterizableRequest<T, U> createSimpleRequest(HttpUrl url, OkHttpClient client, Gson gson, String method, ErrorBuilder<U> errorBuilder) {
        return new SimpleRequest<>(url, client, gson, method, errorBuilder);
    }

    BaseAuthenticationRequest createAuthenticationRequest(HttpUrl url, OkHttpClient client, Gson gson, String method) {
        return new BaseAuthenticationRequest(url, client, gson, method, Credentials.class);
    }

    <U extends Auth0Exception> ParameterizableRequest<Void, U> createVoidRequest(HttpUrl url, OkHttpClient client, Gson gson, String method, ErrorBuilder<U> errorBuilder) {
        return new VoidRequest<>(url, client, gson, method, errorBuilder);
    }

    Map<String, String> getHeaders() {
        return headers;
    }
}
