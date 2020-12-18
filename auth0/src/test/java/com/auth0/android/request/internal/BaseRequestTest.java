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
import com.auth0.android.request.kt.HttpMethod;
import com.auth0.android.request.kt.JsonAdapter;
import com.auth0.android.request.kt.NetworkingClient;
import com.auth0.android.request.kt.RequestOptions;
import com.auth0.android.request.kt.ServerResponse;

import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
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

        // TODO consider using real mock adapter instead of mock
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
        // TODO consider using real input stream intead of mock, for this test and others
        InputStream inputStream = mock(InputStream.class);
        when(inputStream.read()).thenReturn(123);
        when(resultAdapter.fromJson(any(Reader.class))).thenReturn("woohoo");
        ServerResponse response = new ServerResponse(200, inputStream, Collections.emptyMap());
        when(client.load(eq(BASE_URL), any(RequestOptions.class))).thenReturn(response);

        baseRequest.addHeader("A", "1");
        baseRequest.execute();

        verify(client).load(eq(BASE_URL), optionsCaptor.capture());
        Map<String, String> values = optionsCaptor.getValue().getHeaders();
        assertThat(values, aMapWithSize(1));
        assertThat(values, hasEntry("A", "1"));
    }

    @Test
    public void shouldAddParameter() throws Exception {
        InputStream inputStream = mock(InputStream.class);
        when(inputStream.read()).thenReturn(123);
        when(resultAdapter.fromJson(any(Reader.class))).thenReturn("woohoo");
        ServerResponse response = new ServerResponse(200, inputStream, Collections.emptyMap());
        when(client.load(eq(BASE_URL), any(RequestOptions.class))).thenReturn(response);

        baseRequest.addParameter("A", "1");
        baseRequest.execute();

        verify(client).load(eq(BASE_URL), optionsCaptor.capture());
        Map<String, String> values = optionsCaptor.getValue().getParameters();
        assertThat(values, aMapWithSize(1));
        assertThat(values, hasEntry("A", "1"));
    }

    @Test
    public void shouldAddParameters() throws Exception {
        InputStream inputStream = mock(InputStream.class);
        when(inputStream.read()).thenReturn(123);
        when(resultAdapter.fromJson(any(Reader.class))).thenReturn("woohoo");
        ServerResponse response = new ServerResponse(200, inputStream, Collections.emptyMap());
        when(client.load(eq(BASE_URL), any(RequestOptions.class))).thenReturn(response);

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
    public void shouldSetBearer() throws Exception {
        InputStream inputStream = mock(InputStream.class);
        when(inputStream.read()).thenReturn(123);
        when(resultAdapter.fromJson(any(Reader.class))).thenReturn("woohoo");
        ServerResponse response = new ServerResponse(200, inputStream, Collections.emptyMap());
        when(client.load(eq(BASE_URL), any(RequestOptions.class))).thenReturn(response);

        baseRequest.setBearer("my-token");
        baseRequest.execute();

        verify(client).load(eq(BASE_URL), optionsCaptor.capture());
        Map<String, String> values = optionsCaptor.getValue().getHeaders();
        assertThat(values, aMapWithSize(1));
        assertThat(values, hasEntry("Authorization", "Bearer my-token"));
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
    public void shouldBuildErrorFromUnsuccessfulResponse() throws Exception {
        InputStream inputStream = mock(InputStream.class);
        when(inputStream.read()).thenReturn(123);
        Auth0Exception error = mock(Auth0Exception.class);
        when(errorAdapter.fromJson(any(Reader.class))).thenReturn(error);
        ServerResponse response = new ServerResponse(401, inputStream, Collections.emptyMap());
        when(client.load(eq(BASE_URL), any(RequestOptions.class))).thenReturn(response);

        ArgumentCaptor<Reader> readerCaptor = ArgumentCaptor.forClass(Reader.class);
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
        verify(errorAdapter).fromJson(readerCaptor.capture());

        // TODO what is the purpose of these verifications and why are they failing?
        Reader reader = readerCaptor.getValue();
        assertThat(reader.read(), is(123));
        verify(inputStream).read();
    }

    @Test
    public void shouldBuildResultFromSuccessfulResponse() throws Exception {
        InputStream inputStream = mock(InputStream.class);
        when(inputStream.read()).thenReturn(123);
        when(resultAdapter.fromJson(any(Reader.class))).thenReturn("woohoo");
        ServerResponse response = new ServerResponse(200, inputStream, Collections.emptyMap());
        when(client.load(eq(BASE_URL), any(RequestOptions.class))).thenReturn(response);

        ArgumentCaptor<Reader> readerCaptor = ArgumentCaptor.forClass(Reader.class);
        Exception exception = null;
        String result = null;
        try {
            result = baseRequest.execute();
        } catch (Exception e) {
            exception = e;
        }
        assertThat(exception, is(nullValue()));
        assertThat(result, is("woohoo"));

        verifyNoInteractions(errorAdapter);
        verify(resultAdapter).fromJson(readerCaptor.capture());

        // TODO What is the purpose of these verifications, and why are they failing?
        Reader reader = readerCaptor.getValue();
        assertThat(reader.read(), is(123));
        verify(inputStream).read();
    }

    //TODO: Add tests for the async scenario (using callbacks)
}