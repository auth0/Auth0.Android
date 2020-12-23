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
import com.auth0.android.callback.BaseCallback;
import com.auth0.android.request.ErrorAdapter;
import com.auth0.android.request.HttpMethod;
import com.auth0.android.request.JsonAdapter;
import com.auth0.android.request.NetworkingClient;
import com.auth0.android.request.RequestOptions;
import com.auth0.android.request.ServerResponse;
import com.google.gson.Gson;

import org.apache.tools.ant.filters.StringInputStream;
import org.hamcrest.collection.IsMapContaining;
import org.hamcrest.collection.IsMapWithSize;
import org.hamcrest.core.IsCollectionContaining;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.android.util.concurrent.PausedExecutorService;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static android.os.Looper.getMainLooper;
import static java.util.Collections.singletonList;
import static java.util.Collections.singletonMap;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.collection.IsMapContaining.hasEntry;
import static org.hamcrest.collection.IsMapWithSize.aMapWithSize;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.robolectric.shadows.ShadowLooper.shadowMainLooper;

@RunWith(RobolectricTestRunner.class)
public class BaseRequestTest {

    private static final String BASE_URL = "https://auth0.com";
    private BaseRequest<String, Auth0Exception> baseRequest;
    @Mock
    private NetworkingClient client;
    @Mock
    private JsonAdapter<String> resultAdapter;
    @Mock
    private ErrorAdapter<Auth0Exception> errorAdapter;
    @Mock
    private Auth0Exception auth0Exception;
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
        Auth0Exception uException = mock(Auth0Exception.class);
        ArgumentCaptor<Reader> readerCaptor = ArgumentCaptor.forClass(Reader.class);
        ErrorAdapter<Auth0Exception> errorAdapter = mock(ErrorAdapter.class);
        when(errorAdapter.fromJsonResponse(eq(401), readerCaptor.capture())).thenReturn(uException);

        BaseRequest<String, Auth0Exception> baseRequest = new BaseRequest<>(
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

        Auth0Exception exception = null;
        String result = null;
        try {
            result = baseRequest.execute();
        } catch (Auth0Exception e) {
            exception = e;
        }

        assertThat(result, is(nullValue()));
        assertThat(exception, is(notNullValue()));
        assertThat(exception, is(uException));
        verify(errorAdapter).fromJsonResponse(eq(401), any(Reader.class));
        Reader reader = readerCaptor.getValue();
        assertThat(reader, is(notNullValue()));
        assertThat(reader, is(instanceOf(AwareInputStreamReader.class)));
        AwareInputStreamReader awareReader = (AwareInputStreamReader) reader;
        assertThat(awareReader.isClosed(), is(true));

        verifyNoInteractions(resultAdapter);
    }

    @Test
    public void shouldBuildErrorFromUnsuccessfulRawResponse() throws Exception {
        Auth0Exception uException = mock(Auth0Exception.class);
        ArgumentCaptor<Map<String, List<String>>> headersMapCaptor = ArgumentCaptor.forClass(Map.class);
        ErrorAdapter<Auth0Exception> errorAdapter = mock(ErrorAdapter.class);
        when(errorAdapter.fromRawResponse(eq(401), eq("Unauthorized"), headersMapCaptor.capture())).thenReturn(uException);

        BaseRequest<String, Auth0Exception> baseRequest = new BaseRequest<>(
                HttpMethod.POST.INSTANCE,
                BASE_URL,
                client,
                resultAdapter,
                errorAdapter
        );

        String errorResponse = "Unauthorized";
        Map<String, List<String>> headers = singletonMap("Content-Type", singletonList("text/plain"));
        InputStream inputStream = new ByteArrayInputStream(errorResponse.getBytes());
        ServerResponse response = new ServerResponse(401, inputStream, headers);
        when(client.load(eq(BASE_URL), any(RequestOptions.class))).thenReturn(response);

        Auth0Exception exception = null;
        String result = null;
        try {
            result = baseRequest.execute();
        } catch (Auth0Exception e) {
            exception = e;
        }

        assertThat(result, is(nullValue()));
        assertThat(exception, is(notNullValue()));
        assertThat(exception, is(uException));
        verify(errorAdapter).fromRawResponse(eq(401), eq("Unauthorized"), any(Map.class));
        Map<String, List<String>> headersMap = headersMapCaptor.getValue();
        assertThat(headersMap, is(notNullValue()));
        assertThat(headersMap, IsMapWithSize.aMapWithSize(1));
        assertThat(headersMap, IsMapContaining.hasEntry(is("Content-Type"), IsCollectionContaining.hasItem("text/plain")));

        verifyNoInteractions(resultAdapter);
    }

    @Test
    public void shouldBuildResultFromSuccessfulResponse() throws Exception {
        JsonAdapter<SimplePojo> resultAdapter = spy(new GsonAdapter<>(SimplePojo.class, new Gson()));
        BaseRequest<SimplePojo, Auth0Exception> baseRequest = new BaseRequest<>(
                HttpMethod.POST.INSTANCE,
                BASE_URL,
                client,
                resultAdapter,
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
        ArgumentCaptor<Reader> readerCaptor = ArgumentCaptor.forClass(Reader.class);
        verify(resultAdapter).fromJson(readerCaptor.capture());
        Reader reader = readerCaptor.getValue();
        assertThat(reader, is(notNullValue()));
        assertThat(reader, is(instanceOf(AwareInputStreamReader.class)));
        AwareInputStreamReader awareReader = (AwareInputStreamReader) reader;
        assertThat(awareReader.isClosed(), is(true));

        verifyNoInteractions(errorAdapter);
    }

    @SuppressWarnings("UnstableApiUsage")
    @Test
    public void shouldExecuteRequestOnBackgroundThreadAndPostSuccessToMainThread() throws Exception {
        PausedExecutorService pausedExecutorService = new PausedExecutorService();
        ThreadSwitcher threadSwitcher = spy(new ThreadSwitcher(getMainLooper(), pausedExecutorService));
        BaseRequest<String, Auth0Exception> baseRequest = new BaseRequest<>(
                HttpMethod.POST.INSTANCE,
                BASE_URL,
                client,
                resultAdapter,
                errorAdapter,
                threadSwitcher
        );
        mockSuccessfulServerResponse();
        BaseCallback<String, Auth0Exception> callback = mock(BaseCallback.class);

        // verify background thread is queued
        baseRequest.start(callback);
        verify(threadSwitcher).backgroundThread(any(Runnable.class));
        verify(threadSwitcher, never()).mainThread(any(Runnable.class));

        // let the background thread run
        assertThat(pausedExecutorService.runNext(), is(true));
        verify(threadSwitcher).mainThread(any(Runnable.class));
        verify(callback, never()).onSuccess(anyString());

        // Release the main thread queue
        shadowMainLooper().idle();
        verify(callback).onSuccess(eq("woohoo"));

        verify(callback, never()).onFailure(any(Auth0Exception.class));
    }

    @SuppressWarnings("UnstableApiUsage")
    @Test
    public void shouldExecuteRequestOnBackgroundThreadAndPostFailureToMainThread() throws Exception {
        PausedExecutorService pausedExecutorService = new PausedExecutorService();
        ThreadSwitcher threadSwitcher = spy(new ThreadSwitcher(getMainLooper(), pausedExecutorService));
        BaseRequest<String, Auth0Exception> baseRequest = new BaseRequest<>(
                HttpMethod.POST.INSTANCE,
                BASE_URL,
                client,
                resultAdapter,
                errorAdapter,
                threadSwitcher
        );
        mockFailedServerResponse();
        BaseCallback<String, Auth0Exception> callback = mock(BaseCallback.class);

        // verify background thread is queued
        baseRequest.start(callback);
        verify(threadSwitcher).backgroundThread(any(Runnable.class));
        verify(threadSwitcher, never()).mainThread(any(Runnable.class));

        // let the background thread run
        assertThat(pausedExecutorService.runNext(), is(true));
        verify(threadSwitcher).mainThread(any(Runnable.class));
        verify(callback, never()).onFailure(any(Auth0Exception.class));

        // Release the main thread queue
        shadowMainLooper().idle();
        verify(callback).onFailure(any(Auth0Exception.class));

        verify(callback, never()).onSuccess(anyString());
    }

    private void mockSuccessfulServerResponse() throws Exception {
        InputStream inputStream = mock(InputStream.class);
        when(inputStream.read()).thenReturn(123);
        when(resultAdapter.fromJson(any(Reader.class))).thenReturn("woohoo");
        ServerResponse response = new ServerResponse(200, inputStream, Collections.emptyMap());
        when(client.load(eq(BASE_URL), any(RequestOptions.class))).thenReturn(response);
    }

    private void mockFailedServerResponse() throws Exception {
        InputStream inputStream = new StringInputStream("Failure");
        when(errorAdapter.fromRawResponse(eq(500), anyString(), anyMap())).thenReturn(auth0Exception);
        ServerResponse response = new ServerResponse(500, inputStream, Collections.emptyMap());
        when(client.load(eq(BASE_URL), any(RequestOptions.class))).thenReturn(response);
    }

    private static class SimplePojo {
        final String prop;

        SimplePojo(String prop) {
            this.prop = prop;
        }
    }

}