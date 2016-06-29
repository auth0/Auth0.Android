/*
 * BaseRequestTest.java
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
import com.auth0.android.auth0.lib.authentication.AuthenticationException;
import com.auth0.android.auth0.lib.callback.BaseCallback;
import com.auth0.android.auth0.lib.request.ErrorBuilder;
import com.google.gson.Gson;
import com.google.gson.TypeAdapter;
import com.squareup.okhttp.HttpUrl;
import com.squareup.okhttp.OkHttpClient;
import com.squareup.okhttp.Request;
import com.squareup.okhttp.Response;

import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.io.IOException;
import java.util.Map;

import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

public class BaseRequestTest {

    private BaseRequest<String, Auth0Exception> baseRequest;

    @Mock
    private BaseCallback<String, Auth0Exception> callback;
    @Mock
    private Auth0Exception throwable;
    @Mock
    private ErrorBuilder<Auth0Exception> errorBuilder;
    @Mock
    private OkHttpClient client;
    @Mock
    private TypeAdapter<String> adapter;
    @Captor
    private ArgumentCaptor<Runnable> captor;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        HttpUrl url = HttpUrl.parse("https://auth0.com");
        errorBuilder = new ErrorBuilder<Auth0Exception>() {
            @Override
            public Auth0Exception from(String message) {
                return new Auth0Exception(message);
            }

            @Override
            public Auth0Exception from(String message, Auth0Exception exception) {
                return exception;
            }

            @Override
            public Auth0Exception from(Map<String, Object> values) {
                return new Auth0Exception("Error");
            }

            @Override
            public Auth0Exception from(String payload, int statusCode) {
                return new Auth0Exception(payload);
            }
        };

        baseRequest = new BaseRequest<String, Auth0Exception>(url, client, new Gson(), adapter, errorBuilder, callback) {
            @Override
            public String execute() throws Auth0Exception {
                return null;
            }

            @Override
            public void onResponse(Response response) throws IOException {

            }

            @Override
            protected Request doBuildRequest(Request.Builder builder) throws RequestBodyBuildException {
                return null;
            }
        };
    }

    @Test
    public void shouldPostOnSuccess() throws Exception {
        baseRequest.postOnSuccess("OK");
        verify(callback).onSuccess(eq("OK"));
        verifyNoMoreInteractions(callback);
    }

    @Test
    public void shouldPostOnFailure() throws Exception {
        baseRequest.postOnFailure(throwable);
        verify(callback).onFailure(eq(throwable));
        verifyNoMoreInteractions(callback);
    }
}