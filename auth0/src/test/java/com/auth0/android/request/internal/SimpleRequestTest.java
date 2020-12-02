package com.auth0.android.request.internal;

import com.auth0.android.Auth0Exception;
import com.auth0.android.callback.BaseCallback;
import com.auth0.android.request.ErrorBuilder;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonParseException;
import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import com.squareup.okhttp.Call;
import com.squareup.okhttp.Callback;
import com.squareup.okhttp.HttpUrl;
import com.squareup.okhttp.MediaType;
import com.squareup.okhttp.OkHttpClient;
import com.squareup.okhttp.Protocol;
import com.squareup.okhttp.Request;
import com.squareup.okhttp.Response;
import com.squareup.okhttp.ResponseBody;

import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.hamcrest.MockitoHamcrest;

import java.io.IOException;
import java.util.Collections;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

public class SimpleRequestTest {

    private static final MediaType JSON_MEDIATYPE = MediaType.parse("application/json; charset=utf-8");

    private Gson gson;
    private HttpUrl url;
    @Mock
    private OkHttpClient client;
    @Mock
    private ErrorBuilder<Auth0Exception> errorBuilder;
    @Mock
    private BaseCallback<TestPojo, Auth0Exception> callback;
    @Mock
    private TypeAdapter<TestPojo> brokenAdapter;
    @Captor
    ArgumentCaptor<Auth0Exception> exceptionMatcher;

    @Before
    public void setUp() throws IOException {
        MockitoAnnotations.initMocks(this);
        url = HttpUrl.parse("https://mycompany.com/");
        when(errorBuilder.from(anyString(), any(Auth0Exception.class))).thenReturn(mock(Auth0Exception.class));
        when(errorBuilder.from(anyString(), MockitoHamcrest.intThat(greaterThanOrEqualTo(400)))).thenReturn(mock(Auth0Exception.class));
        when(errorBuilder.from(anyMap())).thenReturn(mock(Auth0Exception.class));
//        TypeAdapter<TestPojo> adapter = new TypeAdapter<TestPojo>() {
//
//            @Override
//            public void write(JsonWriter out, TestPojo value) throws IOException {
//                out.beginObject().endObject();
//            }
//
//            @Override
//            public TestPojo read(JsonReader in) throws IOException {
//                return new TestPojo();
//            }
//        };
//        when(adapter.fromJson(anyString())).thenReturn(new TestPojo());
//        doReturn(new TestPojo()).when(adapter).fromJson(any(Reader.class));
//        when(adapter.fromJson(ArgumentMatchers.any(Reader.class))).thenReturn(new TestPojo());
        gson = GsonProvider.buildGson();
//        gson = new GsonBuilder().registerTypeAdapter(new TypeToken<TestPojo>() {
//        }.getType(), adapter).create();
    }

    @Test
    public void shouldSkipSettingBodyWithGETorHEAD() {
        SimpleRequest<TestPojo, Auth0Exception> get = new SimpleRequest<>(url, client, gson, "GET", errorBuilder);
        get.addParameter("name", "john");
        Request getRequest = get.doBuildRequest();
        assertThat(getRequest.body(), is(nullValue()));

        SimpleRequest<TestPojo, Auth0Exception> head = new SimpleRequest<>(url, client, gson, "HEAD", errorBuilder);
        head.addParameter("name", "john");
        Request headRequest = head.doBuildRequest();
        assertThat(headRequest.body(), is(nullValue()));
    }

    @Test
    public void shouldSetBodyWithPOSTorPATCH() {
        SimpleRequest<Object, Auth0Exception> post = new SimpleRequest<>(url, client, gson, "POST", errorBuilder);
        post.addParameter("name", "john");
        Request postRequest = post.doBuildRequest();
        assertThat(postRequest.body(), is(notNullValue()));
        assertThat(postRequest.body().contentType(), is(JSON_MEDIATYPE));

        SimpleRequest<Object, Auth0Exception> patch = new SimpleRequest<>(url, client, gson, "PATCH", errorBuilder);
        patch.addParameter("name", "john");
        Request patchRequest = patch.doBuildRequest();
        assertThat(patchRequest.body(), is(notNullValue()));
        assertThat(patchRequest.body().contentType(), is(JSON_MEDIATYPE));
    }

    @Test
    public void shouldSucceed() {
        SimpleRequest<TestPojo, Auth0Exception> get = new SimpleRequest<>(url, client, gson, "GET", errorBuilder);
        get.setCallback(callback);
        String validJson = "{}";
        ResponseBody resBody = ResponseBody.create(JSON_MEDIATYPE, validJson);

        Request request = new Request.Builder()
                .method("GET", null)
                .url(url)
                .build();
        Response response = new Response.Builder()
                .body(resBody)
                .protocol(Protocol.HTTP_2)
                .request(request)
                .code(200)
                .build();

        Call call = mock(Call.class);
        when(client.newCall(any(Request.class))).thenReturn(call);
        get.start(callback);
        verify(call).enqueue(any(Callback.class));

        get.onResponse(response);
        verify(callback).onSuccess(MockitoHamcrest.argThat(notNullValue(TestPojo.class)));
    }

    @Test
    public void shouldFailOnUnsuccessfulResponse() {
        SimpleRequest<TestPojo, Auth0Exception> get = new SimpleRequest<>(url, client, gson, "GET", errorBuilder);
        get.setCallback(callback);
        String validJson = "{}";
        ResponseBody resBody = ResponseBody.create(JSON_MEDIATYPE, validJson);

        Request request = new Request.Builder()
                .method("GET", null)
                .url(url)
                .build();
        Response response = new Response.Builder()
                .body(resBody)
                .protocol(Protocol.HTTP_2)
                .request(request)
                .code(422)
                .build();

        Call call = mock(Call.class);
        when(client.newCall(any(Request.class))).thenReturn(call);
        get.start(callback);
        verify(call).enqueue(any(Callback.class));

        get.onResponse(response);
        verify(callback).onFailure(any(Auth0Exception.class));
        verify(errorBuilder).from(Collections.<String, Object>emptyMap());
    }

    @Test
    public void shouldFailOnSuccessfulResponseWithIOException() throws IOException {
        TypeAdapter<TestPojo> brokenAdapter = new TypeAdapter<TestPojo>() {
            @Override
            public void write(JsonWriter out, TestPojo value) {
            }

            @Override
            public TestPojo read(JsonReader in) throws IOException {
                throw new IOException("err");
            }
        };
        Gson gson = new GsonBuilder().registerTypeAdapter(TestPojo.class, brokenAdapter).create();

        SimpleRequest<TestPojo, Auth0Exception> get = new SimpleRequest<>(url, client, gson, "GET", TestPojo.class, errorBuilder);
        get.setCallback(callback);
        String invalidJson = "{---}";
        ResponseBody resBody = ResponseBody.create(JSON_MEDIATYPE, invalidJson);

        Request request = new Request.Builder()
                .method("GET", null)
                .url(url)
                .build();
        Response response = new Response.Builder()
                .body(resBody)
                .protocol(Protocol.HTTP_2)
                .request(request)
                .code(200)
                .build();

        Call call = mock(Call.class);
        when(client.newCall(any(Request.class))).thenReturn(call);
        get.start(callback);
        verify(call).enqueue(any(Callback.class));

        get.onResponse(response);

        verify(callback).onFailure(any(Auth0Exception.class));
        verify(errorBuilder).from(eq("Failed to parse a successful response"), exceptionMatcher.capture());
        assertThat(exceptionMatcher.getValue(), is(notNullValue()));
        assertThat(exceptionMatcher.getValue().getMessage(), is("Failed to parse response to request to https://mycompany.com/"));
        assertThat(exceptionMatcher.getValue().getCause(), is(Matchers.<Throwable>instanceOf(IOException.class)));
    }

    @Test
    public void shouldFailOnSuccessfulResponseWithJsonParseException() throws IOException {
        when(brokenAdapter.read(any(JsonReader.class))).thenThrow(new JsonParseException("err"));
        Gson gson = new GsonBuilder().registerTypeAdapter(TestPojo.class, brokenAdapter).create();
        SimpleRequest<TestPojo, Auth0Exception> get = new SimpleRequest<>(url, client, gson, "GET", TestPojo.class, errorBuilder);
        get.setCallback(callback);
        String invalidJson = "{---}";
        ResponseBody resBody = ResponseBody.create(JSON_MEDIATYPE, invalidJson);

        Request request = new Request.Builder()
                .method("GET", null)
                .url(url)
                .build();
        Response response = new Response.Builder()
                .body(resBody)
                .protocol(Protocol.HTTP_2)
                .request(request)
                .code(200)
                .build();

        Call call = mock(Call.class);
        when(client.newCall(any(Request.class))).thenReturn(call);
        get.start(callback);
        verify(call).enqueue(any(Callback.class));

        get.onResponse(response);

        verify(callback).onFailure(any(Auth0Exception.class));
        verify(errorBuilder).from(eq("Failed to parse a successful response"), exceptionMatcher.capture());
        assertThat(exceptionMatcher.getValue(), is(notNullValue()));
        assertThat(exceptionMatcher.getValue().getMessage(), is("Failed to parse response to request to https://mycompany.com/"));
        assertThat(exceptionMatcher.getValue().getCause(), is(Matchers.<Throwable>instanceOf(JsonParseException.class)));
    }

    @Test
    public void shouldStart() {
        Call call = mock(Call.class);
        when(client.newCall(any(Request.class))).thenReturn(call);
        SimpleRequest<TestPojo, Auth0Exception> get = new SimpleRequest<>(url, client, gson, "GET", errorBuilder);
        get.start(callback);
    }

    @Test
    public void shouldExecuteSuccessfully() throws IOException {
        String validJson = "{}";
        ResponseBody resBody = ResponseBody.create(JSON_MEDIATYPE, validJson);

        Request request = new Request.Builder()
                .method("GET", null)
                .url(url)
                .build();
        Response response = new Response.Builder()
                .body(resBody)
                .protocol(Protocol.HTTP_2)
                .request(request)
                .code(200)
                .build();

        Call call = mock(Call.class);
        when(client.newCall(any(Request.class))).thenReturn(call);
        when(call.execute()).thenReturn(response);
        SimpleRequest<TestPojo, Auth0Exception> get = new SimpleRequest<>(url, client, gson, "GET", errorBuilder);


        Exception expectedException = null;
        Object result = null;
        try {
            result = get.execute();
        } catch (Exception e) {
            expectedException = e;
        }
        assertThat(result, Matchers.<Object>is(Collections.<String, Object>emptyMap()));
        verifyNoInteractions(errorBuilder);
        assertThat(expectedException, is(nullValue()));
    }

    @Test
    public void shouldExecuteSuccessfullyButReceiveFailedResponse() throws IOException {
        String validJson = "{}";
        ResponseBody resBody = ResponseBody.create(JSON_MEDIATYPE, validJson);

        Request request = new Request.Builder()
                .method("GET", null)
                .url(url)
                .build();
        Response response = new Response.Builder()
                .body(resBody)
                .protocol(Protocol.HTTP_2)
                .request(request)
                .code(422)
                .build();

        Call call = mock(Call.class);
        when(client.newCall(any(Request.class))).thenReturn(call);
        when(call.execute()).thenReturn(response);
        SimpleRequest<TestPojo, Auth0Exception> get = new SimpleRequest<>(url, client, gson, "GET", errorBuilder);


        Exception expectedException = null;
        Object result = null;
        try {
            result = get.execute();
        } catch (Exception e) {
            expectedException = e;
        }
        assertThat(result, is(nullValue()));
        assertThat(expectedException, is(notNullValue()));
        verify(errorBuilder).from(Collections.<String, Object>emptyMap());
    }

    @Test
    public void shouldFailToExecuteWithIOException() throws IOException {
        String invalidJson = "{---}";
        ResponseBody resBody = ResponseBody.create(JSON_MEDIATYPE, invalidJson);

        Request request = new Request.Builder()
                .method("GET", null)
                .url(url)
                .build();
        Response response = new Response.Builder()
                .body(resBody)
                .protocol(Protocol.HTTP_2)
                .request(request)
                .code(200)
                .build();

        Call call = mock(Call.class);
        when(client.newCall(any(Request.class))).thenReturn(call);
        when(call.execute()).thenThrow(IOException.class);
        SimpleRequest<TestPojo, Auth0Exception> get = new SimpleRequest<>(url, client, gson, "GET", errorBuilder);


        Exception expectedException = null;
        Object result = null;
        try {
            result = get.execute();
        } catch (Exception e) {
            expectedException = e;
        }
        assertThat(result, is(nullValue()));
        assertThat(expectedException, is(notNullValue()));
        verify(errorBuilder).from(eq("Request failed"), exceptionMatcher.capture());
        assertThat(exceptionMatcher.getValue(), is(notNullValue()));
        assertThat(exceptionMatcher.getValue().getMessage(), is("Failed to execute the network request"));
        assertThat(exceptionMatcher.getValue().getCause(), is(Matchers.<Throwable>instanceOf(IOException.class)));
    }

    @Test
    public void shouldFailToExecuteOnSuccessfulResponseWithIOException() throws IOException {
        when(brokenAdapter.read(any(JsonReader.class))).thenThrow(new IOException("err"));
        Gson gson = new GsonBuilder().registerTypeAdapter(TestPojo.class, brokenAdapter).create();
        String invalidJson = "{---}";
        ResponseBody resBody = ResponseBody.create(JSON_MEDIATYPE, invalidJson);

        Request request = new Request.Builder()
                .method("GET", null)
                .url(url)
                .build();
        Response response = new Response.Builder()
                .body(resBody)
                .protocol(Protocol.HTTP_2)
                .request(request)
                .code(200)
                .build();

        Call call = mock(Call.class);
        when(client.newCall(any(Request.class))).thenReturn(call);
        when(call.execute()).thenReturn(response);
        SimpleRequest<TestPojo, Auth0Exception> get = new SimpleRequest<>(url, client, gson, "GET", TestPojo.class, errorBuilder);


        Exception expectedException = null;
        Object result = null;
        try {
            result = get.execute();
        } catch (Exception e) {
            expectedException = e;
        }
        verifyNoInteractions(errorBuilder);
        assertThat(result, is(nullValue()));
        assertThat(expectedException, is(notNullValue()));
        assertThat(expectedException.getCause(), is(Matchers.<Throwable>instanceOf(IOException.class)));
        assertThat(expectedException.getMessage(), is("Failed to parse response to request to https://mycompany.com/"));
    }

    @Test
    public void shouldFailToExecuteOnSuccessfulResponseWithJsonParseException() throws IOException {
        when(brokenAdapter.read(any(JsonReader.class))).thenThrow(new JsonParseException("err"));
        Gson gson = new GsonBuilder().registerTypeAdapter(TestPojo.class, brokenAdapter).create();

        String invalidJson = "{}";
        ResponseBody resBody = ResponseBody.create(JSON_MEDIATYPE, invalidJson);

        Request request = new Request.Builder()
                .method("GET", null)
                .url(url)
                .build();
        Response response = new Response.Builder()
                .body(resBody)
                .protocol(Protocol.HTTP_2)
                .request(request)
                .code(200)
                .build();

        Call call = mock(Call.class);
        when(client.newCall(any(Request.class))).thenReturn(call);
        when(call.execute()).thenReturn(response);
        SimpleRequest<TestPojo, Auth0Exception> get = new SimpleRequest<>(url, client, gson, "GET", TestPojo.class, errorBuilder);

        Exception expectedException = null;
        TestPojo result = null;
        try {
            result = get.execute();
        } catch (Exception e) {
            expectedException = e;
        }
        verifyNoInteractions(errorBuilder);
        assertThat(result, is(nullValue()));
        assertThat(expectedException, is(notNullValue()));
        assertThat(expectedException.getCause(), is(Matchers.<Throwable>instanceOf(JsonParseException.class)));
        assertThat(expectedException.getMessage(), is("Failed to parse response to request to https://mycompany.com/"));
    }

    /**
     * Used for assigning an adapter to Gson.
     * Most Gson classes are final and hard if not impossible to mock.
     */
    private static class TestPojo {
    }

}