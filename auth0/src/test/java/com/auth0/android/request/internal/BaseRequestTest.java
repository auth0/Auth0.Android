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

package com.auth0.android.request.internal;


import androidx.annotation.NonNull;

import com.auth0.android.Auth0Exception;
import com.auth0.android.NetworkErrorException;
import com.auth0.android.RequestBodyBuildException;
import com.auth0.android.authentication.ParameterBuilder;
import com.auth0.android.callback.BaseCallback;
import com.auth0.android.request.ErrorBuilder;
import com.google.gson.Gson;
import com.google.gson.TypeAdapter;
import com.squareup.okhttp.HttpUrl;
import com.squareup.okhttp.MediaType;
import com.squareup.okhttp.OkHttpClient;
import com.squareup.okhttp.Protocol;
import com.squareup.okhttp.Request;
import com.squareup.okhttp.Response;
import com.squareup.okhttp.ResponseBody;

import org.hamcrest.CoreMatchers;
import org.hamcrest.collection.IsMapContaining;
import org.hamcrest.collection.IsMapWithSize;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
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
    @Mock
    private Map<String, String> headers;
    private ParameterBuilder parameterBuilder;

    @Captor
    private ArgumentCaptor<Map<String, Object>> mapCaptor;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        HttpUrl url = HttpUrl.parse("https://auth0.com");
        parameterBuilder = ParameterBuilder.newBuilder();

        baseRequest = new BaseRequest<String, Auth0Exception>(url, client, new Gson(), adapter, errorBuilder, callback, headers, parameterBuilder) {
            @NonNull
            @Override
            public String execute() throws Auth0Exception {
                return null;
            }

            @Override
            public void onResponse(Response response) {

            }

            @Override
            protected Request doBuildRequest() throws RequestBodyBuildException {
                return null;
            }
        };
    }

    @Test
    public void shouldUpdateTheCallback() {
        BaseCallback<String, Auth0Exception> diffCallback = mock(BaseCallback.class);
        baseRequest.setCallback(diffCallback);
        assertThat(baseRequest.getCallback(), CoreMatchers.equalTo(diffCallback));
    }

    @Test
    public void shouldGetTheCallback() {
        assertThat(baseRequest.getCallback(), CoreMatchers.equalTo(callback));
    }

    @Test
    public void shouldGetTheErrorBuilder() {
        assertThat(baseRequest.getErrorBuilder(), CoreMatchers.equalTo(errorBuilder));
    }

    @Test
    public void shouldGetTheAdapter() {
        assertThat(baseRequest.getAdapter(), CoreMatchers.equalTo(adapter));
    }

    @Test
    public void shouldAddHeaders() {
        baseRequest.addHeader("name", "value");
        verify(headers).put("name", "value");
    }

    @Test
    public void shouldAddASingleParameter() {
        baseRequest.addParameter("name", "value");

        final Map<String, Object> result = parameterBuilder.asDictionary();
        assertThat(result, IsMapWithSize.aMapWithSize(1));
        assertThat(result, IsMapContaining.hasEntry("name", (Object) "value"));
    }

    @Test
    public void shouldAddParameters() {
        Map<String, Object> params = new HashMap<>();
        params.put("name", "value");
        params.put("asd", "123");
        baseRequest.addParameters(params);

        final Map<String, Object> result = parameterBuilder.asDictionary();
        assertThat(result, IsMapWithSize.aMapWithSize(2));
        assertThat(result, IsMapContaining.hasEntry("name", (Object) "value"));
        assertThat(result, IsMapContaining.hasEntry("asd", (Object) "123"));
    }

    @Test
    public void shouldSetBearer() {
        baseRequest.setBearer("my-jwt-token");
        verify(headers).put("Authorization", "Bearer my-jwt-token");
    }

    @Test
    public void shouldPostOnSuccess() {
        baseRequest.postOnSuccess("OK");
        verify(callback).onSuccess(eq("OK"));
        verifyNoMoreInteractions(callback);
    }

    @Test
    public void shouldPostOnFailure() {
        baseRequest.postOnFailure(throwable);
        verify(callback).onFailure(eq(throwable));
        verifyNoMoreInteractions(callback);
    }

    @Test
    public void shouldBuildNetworkErrorException() {
        baseRequest.onFailure(null, mock(IOException.class));
        verify(errorBuilder).from(eq("Request failed"), any(NetworkErrorException.class));
    }

    @Test
    public void shouldParseUnsuccessfulJsonResponse() {
        String payload = "{key: \"value\", asd: \"123\"}";
        final Response response = createJsonResponse(payload, 401);
        baseRequest.parseUnsuccessfulResponse(response);

        verify(errorBuilder).from(mapCaptor.capture());
        assertThat(mapCaptor.getValue(), IsMapContaining.hasEntry("key", (Object) "value"));
        assertThat(mapCaptor.getValue(), IsMapContaining.hasEntry("asd", (Object) "123"));
    }

    @Test
    public void shouldParseUnsuccessfulNotJsonResponse() {
        String payload = "n=ot_a valid json {{]";
        final Response response = createJsonResponse(payload, 401);
        baseRequest.parseUnsuccessfulResponse(response);

        ArgumentCaptor<Integer> integerCaptor = ArgumentCaptor.forClass(Integer.class);
        verify(errorBuilder).from(eq("n=ot_a valid json {{]"), integerCaptor.capture());
        assertThat(integerCaptor.getValue(), is(401));
    }

    @Test
    public void shouldParseUnsuccessfulInvalidResponse() throws Exception {
        byte[] invalidBytes = new byte[]{12, 23, 2, 1, 23, 3, 21, 3, 12};
        final Response response = createBytesResponse(invalidBytes, 401);
        response.body().string();    //force a IOException the next time this gets called
        baseRequest.parseUnsuccessfulResponse(response);
        verify(errorBuilder).from(eq("Request to https://auth0.com/ failed"), any(Auth0Exception.class));
    }

    private Response createJsonResponse(String jsonPayload, int code) {
        Request request = new Request.Builder()
                .url("https://someurl.com")
                .build();

        final ResponseBody responseBody = ResponseBody.create(MediaType.parse("application/json; charset=utf-8"), jsonPayload);
        return new Response.Builder()
                .request(request)
                .protocol(Protocol.HTTP_1_1)
                .body(responseBody)
                .code(code)
                .build();
    }

    private Response createBytesResponse(byte[] content, int code) {
        Request request = new Request.Builder()
                .url("https://someurl.com")
                .build();

        final ResponseBody responseBody = ResponseBody.create(MediaType.parse("application/octet-stream; charset=utf-8"), content);
        return new Response.Builder()
                .request(request)
                .protocol(Protocol.HTTP_1_1)
                .body(responseBody)
                .code(code)
                .build();
    }
}
