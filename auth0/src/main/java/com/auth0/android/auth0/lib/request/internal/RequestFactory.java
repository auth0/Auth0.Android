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

package com.auth0.android.auth0.lib.request.internal;

import com.auth0.android.auth0.lib.Auth0Exception;
import com.auth0.android.auth0.lib.authentication.result.Credentials;
import com.auth0.android.auth0.lib.request.AuthenticationRequest;
import com.auth0.android.auth0.lib.request.AuthorizableRequest;
import com.auth0.android.auth0.lib.request.ErrorBuilder;
import com.auth0.android.auth0.lib.request.ParameterizableRequest;
import com.auth0.android.auth0.lib.util.Telemetry;
import com.google.gson.Gson;
import com.squareup.okhttp.HttpUrl;
import com.squareup.okhttp.OkHttpClient;

import java.util.Map;

public class RequestFactory {

    private String clientInfo;
    private String userAgent;

    public void setClientInfo(String clientInfo) {
        this.clientInfo = clientInfo;
    }

    public void setUserAgent(String userAgent) {
        this.userAgent = userAgent;
    }

    public <T, U extends Auth0Exception> ParameterizableRequest<T, U> GET(HttpUrl url, OkHttpClient client, Gson gson, Class<T> clazz, ErrorBuilder<U> errorBuilder) {
        final SimpleRequest<T, U> request = new SimpleRequest<>(url, client, gson, "GET", clazz, errorBuilder);
        addMetrics(request);
        return request;
    }

    public AuthenticationRequest authenticationPOST(HttpUrl url, OkHttpClient client, Gson gson) {
        final BaseAuthenticationRequest request = new BaseAuthenticationRequest(url, client, gson, "POST", Credentials.class);
        addMetrics(request);
        return request;
    }

    public <T, U extends Auth0Exception> ParameterizableRequest<T, U> POST(HttpUrl url, OkHttpClient client, Gson gson, Class<T> clazz, ErrorBuilder<U> errorBuilder) {
        final SimpleRequest<T, U> request = new SimpleRequest<>(url, client, gson, "POST", clazz, errorBuilder);
        addMetrics(request);
        return request;
    }

    public <U extends Auth0Exception> ParameterizableRequest<Map<String, Object>, U> rawPOST(HttpUrl url, OkHttpClient client, Gson gson, ErrorBuilder<U> errorBuilder) {
        final SimpleRequest<Map<String, Object>, U> request = new SimpleRequest<>(url, client, gson, "POST", errorBuilder);
        addMetrics(request);
        return request;
    }

    public <U extends Auth0Exception> ParameterizableRequest<Void, U> POST(HttpUrl url, OkHttpClient client, Gson gson, ErrorBuilder<U> errorBuilder) {
        final VoidRequest<U> request = new VoidRequest<>(url, client, gson, "POST", errorBuilder);
        addMetrics(request);
        return request;
    }

    public <U extends Auth0Exception> ParameterizableRequest<Void, U> POST(HttpUrl url, OkHttpClient client, Gson gson, String jwt, ErrorBuilder<U> errorBuilder) {
        final AuthorizableRequest<Void, U> request = new VoidRequest<U>(url, client, gson, "POST", errorBuilder)
                .setBearer(jwt);
        addMetrics(request);
        return request;
    }

    public <T, U extends Auth0Exception> ParameterizableRequest<T, U> PUT(HttpUrl url, OkHttpClient client, Gson gson, Class<T> clazz, ErrorBuilder<U> errorBuilder) {
        final SimpleRequest<T, U> request = new SimpleRequest<>(url, client, gson, "PUT", clazz, errorBuilder);
        addMetrics(request);
        return request;
    }

    public <T, U extends Auth0Exception> ParameterizableRequest<T, U> PATCH(HttpUrl url, OkHttpClient client, Gson gson, Class<T> clazz, ErrorBuilder<U> errorBuilder) {
        final SimpleRequest<T, U> request = new SimpleRequest<>(url, client, gson, "GET", clazz, errorBuilder);
        addMetrics(request);
        return request;
    }

    public <T, U extends Auth0Exception> ParameterizableRequest<T, U> DELETE(HttpUrl url, OkHttpClient client, Gson gson, Class<T> clazz, ErrorBuilder<U> errorBuilder) {
        final SimpleRequest<T, U> request = new SimpleRequest<>(url, client, gson, "DELETE", clazz, errorBuilder);
        addMetrics(request);
        return request;
    }

    private <T, U extends Auth0Exception> void addMetrics(ParameterizableRequest<T, U> request) {
        if (this.clientInfo != null) {
            request.addHeader(Telemetry.HEADER_NAME, this.clientInfo);
        }
        if (this.userAgent != null) {
            request.addHeader("User-Agent", this.userAgent);
        }
    }
}
