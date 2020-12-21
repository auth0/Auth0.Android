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


import com.auth0.android.Auth0Exception;
import com.auth0.android.request.kt.ErrorAdapter;
import com.auth0.android.request.kt.GsonAdapter;
import com.auth0.android.request.kt.HttpMethod;
import com.auth0.android.request.kt.JsonAdapter;
import com.auth0.android.request.kt.NetworkingClient;
import com.auth0.android.request.kt.RequestOptions;
import com.auth0.android.request.kt.ServerResponse;
import com.google.gson.Gson;

import org.jetbrains.annotations.NotNull;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static java.util.Collections.singletonList;
import static java.util.Collections.singletonMap;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.collection.IsMapContaining.hasEntry;
import static org.hamcrest.collection.IsMapWithSize.aMapWithSize;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

public class BaseRequestTest {

    private static final String BASE_URL = "https://auth0.com";
    private BaseRequest<String, Auth0Exception> baseRequest;
    @Mock
    private NetworkingClient client;
    @Mock
    private JsonAdapter<String> resultAdapter;
    @Mock
    private ErrorAdapter<Auth0Exception> errorAdapter;
    @Captor
    private ArgumentCaptor<RequestOptions> optionsCaptor;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);

        baseRequest = new BaseRequest<>(
                HttpMethod.POST.INSTANCE,
                BASE_URL,
                client,
                resultAdapter,
                errorAdapter
        );
    }

    @Test
    public void shouldAddHeaders() throws Exception {
        mockSuccessfulServerResponse();

        baseRequest.addHeader("A", "1");
        baseRequest.execute();

        verify(client).load(eq(BASE_URL), optionsCaptor.capture());
        Map<String, String> values = optionsCaptor.getValue().getHeaders();
        assertThat(values, aMapWithSize(1));
        assertThat(values, hasEntry("A", "1"));
    }

    @Test
    public void shouldAddParameter() throws Exception {
        mockSuccessfulServerResponse();

        baseRequest.addParameter("A", "1");
        baseRequest.execute();

        verify(client).load(eq(BASE_URL), optionsCaptor.capture());
        Map<String, String> values = optionsCaptor.getValue().getParameters();
        assertThat(values, aMapWithSize(1));
        assertThat(values, hasEntry("A", "1"));
    }

    @Test
    public void shouldAddParameters() throws Exception {
        mockSuccessfulServerResponse();

        HashMap<String, String> parameters = new HashMap<>();
        parameters.put("A", "1");
        parameters.put("B", "2");

        baseRequest.addParameters(parameters);
        baseRequest.execute();

        verify(client).load(eq(BASE_URL), optionsCaptor.capture());
        Map<String, String> values = optionsCaptor.getValue().getParameters();
        assertThat(values, aMapWithSize(2));
        assertThat(values, hasEntry("A", "1"));
        assertThat(values, hasEntry("B", "2"));
    }

    @Test
    public void shouldBuildErrorFromException() throws Exception {
        IOException networkError = mock(IOException.class);
        Auth0Exception error = mock(Auth0Exception.class);
        when(client.load(eq(BASE_URL), any(RequestOptions.class))).thenThrow(networkError);
        when(errorAdapter.fromException(any(IOException.class))).thenReturn(error);

        Exception exception = null;
        String result = null;
        try {
            result = baseRequest.execute();
        } catch (Exception e) {
            exception = e;
        }

        assertThat(exception, is(error));
        assertThat(result, is(nullValue()));

        verifyNoInteractions(resultAdapter);
        verify(errorAdapter).fromException(eq(networkError));
    }

    @Test
    public void shouldBuildErrorFromUnsuccessfulJsonResponse() throws Exception {
        ErrorAdapter<FakeException> errorAdapter = getErrorAdapter();

        BaseRequest<String, FakeException> baseRequest = new BaseRequest<>(
                HttpMethod.POST.INSTANCE,
                BASE_URL,
                client,
                resultAdapter,
                errorAdapter
        );

        String errorResponse = "{\"error_code\":\"invalid_token\"}";
        InputStream inputStream = new ByteArrayInputStream(errorResponse.getBytes());
        Map<String, List<String>> headers = singletonMap("Content-Type", singletonList("application/json"));
        ServerResponse response = new ServerResponse(401, inputStream, headers);
        when(client.load(eq(BASE_URL), any(RequestOptions.class))).thenReturn(response);

        FakeException exception = null;
        String result = null;
        try {
            result = baseRequest.execute();
        } catch (FakeException e) {
            exception = e;
        }

        assertThat(result, is(nullValue()));
        assertThat(exception, is(notNullValue()));
        assertThat(exception.statusCode, is(401));
        assertThat(exception.values, is(aMapWithSize(1)));
        assertThat(exception.values, hasEntry("error_code", "invalid_token"));
        assertThat(exception.headers, is(nullValue()));

        verifyNoInteractions(resultAdapter);
    }

    @Test
    public void shouldBuildErrorFromUnsuccessfulRawResponse() throws Exception {
        ErrorAdapter<FakeException> errorAdapter = getErrorAdapter();

        BaseRequest<String, FakeException> baseRequest = new BaseRequest<>(
                HttpMethod.POST.INSTANCE,
                BASE_URL,
                client,
                resultAdapter,
                errorAdapter
        );

        String errorResponse = "Unauthorized";
        HashMap<String, List<String>> headers = new HashMap<>();
        InputStream inputStream = new ByteArrayInputStream(errorResponse.getBytes());
        ServerResponse response = new ServerResponse(401, inputStream, headers);
        when(client.load(eq(BASE_URL), any(RequestOptions.class))).thenReturn(response);

        FakeException exception = null;
        String result = null;
        try {
            result = baseRequest.execute();
        } catch (FakeException e) {
            exception = e;
        }

        assertThat(result, is(nullValue()));
        assertThat(exception, is(notNullValue()));
        assertThat(exception.statusCode, is(401));
        assertThat(exception.values, is(nullValue()));
        assertThat(exception.headers, is(headers));

        verifyNoInteractions(resultAdapter);
    }


    @Test
    public void shouldBuildResultFromSuccessfulResponse() throws Exception {
        BaseRequest<SimplePojo, Auth0Exception> baseRequest = new BaseRequest<>(
                HttpMethod.POST.INSTANCE,
                BASE_URL,
                client,
                new GsonAdapter<>(SimplePojo.class, new Gson()),
                errorAdapter
        );

        String jsonResponse = "{\"prop\":\"value\"}";
        InputStream inputStream = new ByteArrayInputStream(jsonResponse.getBytes());
        ServerResponse response = new ServerResponse(200, inputStream, Collections.emptyMap());
        when(client.load(eq(BASE_URL), any(RequestOptions.class))).thenReturn(response);

        Exception exception = null;
        SimplePojo result = null;
        try {
            result = baseRequest.execute();
        } catch (Exception e) {
            exception = e;
        }
        assertThat(exception, is(nullValue()));
        assertThat(result, is(notNullValue()));
        assertThat(result.prop, is("value"));

        verifyNoInteractions(errorAdapter);
    }

    //TODO: Add tests for the async scenario (using callbacks)

    static class SimplePojo {
        final String prop;

        SimplePojo(String prop) {
            this.prop = prop;
        }
    }

    static class FakeException extends Auth0Exception {
        final int statusCode;
        final Map<String, ? extends List<String>> headers;
        final Map<String, Object> values;

        FakeException(int statusCode, String message, Map<String, ? extends List<String>> headers) {
            super(message);
            this.statusCode = statusCode;
            this.values = null;
            this.headers = headers;
        }

        FakeException(int statusCode, Map<String, Object> values) {
            super("Something bad happened");
            this.statusCode = statusCode;
            this.values = new HashMap<>(values);
            this.headers = null;
        }

        FakeException(String message, Throwable t) {
            super(message, t);
            this.statusCode = 0;
            this.values = null;
            this.headers = null;
        }
    }

    private void mockSuccessfulServerResponse() throws Exception {
        InputStream inputStream = mock(InputStream.class);
        when(inputStream.read()).thenReturn(123);
        when(resultAdapter.fromJson(any(Reader.class))).thenReturn("woohoo");
        ServerResponse response = new ServerResponse(200, inputStream, Collections.emptyMap());
        when(client.load(eq(BASE_URL), any(RequestOptions.class))).thenReturn(response);
    }

    private ErrorAdapter<FakeException> getErrorAdapter() {
        GsonAdapter<Map<String, Object>> mapAdapter = GsonAdapter.Companion.forMap(new Gson());
        return new ErrorAdapter<FakeException>() {
            @Override
            public FakeException fromRawResponse(int statusCode, @NotNull String bodyText, @NotNull Map<String, ? extends List<String>> headers) {
                return new FakeException(statusCode, bodyText, headers);
            }

            @Override
            public FakeException fromJsonResponse(int statusCode, @NotNull Reader reader) throws IOException {
                Map<String, Object> values = mapAdapter.fromJson(reader);
                return new FakeException(statusCode, values);
            }

            @Override
            public FakeException fromException(@NotNull Throwable err) {
                return new FakeException("Something went wrong", err);
            }

        };
    }
}