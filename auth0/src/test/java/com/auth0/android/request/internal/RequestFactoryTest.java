package com.auth0.android.request.internal;


import com.auth0.android.Auth0Exception;
import com.auth0.android.request.Request;
import com.auth0.android.request.kt.ErrorAdapter;
import com.auth0.android.request.kt.HttpMethod;
import com.auth0.android.request.kt.NetworkingClient;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.Locale;

import kotlin.Unit;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class RequestFactoryTest {

    private static final String CLIENT_INFO = "client_info";
    private static final String USER_AGENT = "user_agent";
    private static final String BASE_URL = "http://domain.auth0.com";

    @Mock
    private NetworkingClient client;
    @Mock
    private ErrorAdapter<Auth0Exception> errorAdapter;
    @Mock
    private ErrorAdapter<String> resultAdapter;
    @Mock
    private Request<String, Auth0Exception> postRequest;
    @Mock
    private Request<String, Auth0Exception> patchRequest;
    @Mock
    private Request<String, Auth0Exception> getRequest;
    @Mock
    private Request<String, Auth0Exception> deleteRequest;

    private RequestFactory<Auth0Exception> factory;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        factory = createRequestFactory();
    }

    @Test
    public void shouldHaveDefaultAcceptLanguageHeader() {
        final Locale locale = new Locale("");
        Locale.setDefault(locale);

        factory.get(BASE_URL, resultAdapter);
        verify(getRequest).addHeader("Accept-Language", "en_US");

        factory.post(BASE_URL, resultAdapter);
        verify(postRequest).addHeader("Accept-Language", "en_US");

        factory.delete(BASE_URL, resultAdapter);
        verify(deleteRequest).addHeader("Accept-Language", "en_US");

        factory.patch(BASE_URL, resultAdapter);
        verify(patchRequest).addHeader("Accept-Language", "en_US");
    }

    @Test
    public void shouldHaveAcceptLanguageHeader() {
        final Locale localeJP = new Locale("ja", "JP");
        Locale.setDefault(localeJP);

        factory.get(BASE_URL, resultAdapter);
        verify(getRequest).addHeader("Accept-Language", "ja_JP");

        factory.post(BASE_URL, resultAdapter);
        verify(postRequest).addHeader("Accept-Language", "ja_JP");

        factory.delete(BASE_URL, resultAdapter);
        verify(deleteRequest).addHeader("Accept-Language", "ja_JP");

        factory.patch(BASE_URL, resultAdapter);
        verify(patchRequest).addHeader("Accept-Language", "ja_JP");
    }

    @Test
    public void shouldHaveCustomHeader() {
        RequestFactory<Auth0Exception> factory = createRequestFactory();
        factory.setHeader("the-header", "the-value");

        factory.get(BASE_URL, resultAdapter);
        verify(getRequest).addHeader("the-header", "the-value");

        factory.post(BASE_URL, resultAdapter);
        verify(postRequest).addHeader("the-header", "the-value");

        factory.delete(BASE_URL, resultAdapter);
        verify(deleteRequest).addHeader("the-header", "the-value");

        factory.patch(BASE_URL, resultAdapter);
        verify(patchRequest).addHeader("the-header", "the-value");
    }

    @Test
    public void shouldHaveClientInfoHeader() {
        RequestFactory<Auth0Exception> factory = createRequestFactory();
        factory.setClientInfo(CLIENT_INFO);

        factory.get(BASE_URL, resultAdapter);
        verify(getRequest).addHeader("Auth0-Client", CLIENT_INFO);

        factory.post(BASE_URL, resultAdapter);
        verify(postRequest).addHeader("Auth0-Client", CLIENT_INFO);

        factory.delete(BASE_URL, resultAdapter);
        verify(deleteRequest).addHeader("Auth0-Client", CLIENT_INFO);

        factory.patch(BASE_URL, resultAdapter);
        verify(patchRequest).addHeader("Auth0-Client", CLIENT_INFO);
    }

    @Test
    public void shouldHaveUserAgentHeader() {
        RequestFactory<Auth0Exception> factory = createRequestFactory();
        factory.setUserAgent(USER_AGENT);

        factory.get(BASE_URL, resultAdapter);
        verify(getRequest).addHeader("User-Agent", USER_AGENT);

        factory.post(BASE_URL, resultAdapter);
        verify(postRequest).addHeader("User-Agent", USER_AGENT);

        factory.delete(BASE_URL, resultAdapter);
        verify(deleteRequest).addHeader("User-Agent", USER_AGENT);

        factory.patch(BASE_URL, resultAdapter);
        verify(patchRequest).addHeader("User-Agent", USER_AGENT);
    }

    @Test
    public void shouldCreatePostRequest() {
        Request<String, Auth0Exception> request = factory.post(BASE_URL, resultAdapter);

        assertThat(request, is(notNullValue()));
        assertThat(request, is(postRequest));
    }

    @Test
    public void shouldCreateVoidPostRequest() {
        Request<Unit, Auth0Exception> request = factory.post(BASE_URL);

        assertThat(request, is(notNullValue()));
        assertThat(request, is(postRequest));
    }

    @Test
    public void shouldCreatePatchRequest() {
        Request<String, Auth0Exception> request = factory.patch(BASE_URL, resultAdapter);

        assertThat(request, is(notNullValue()));
        assertThat(request, is(patchRequest));
    }

    @Test
    public void shouldCreateDeleteRequest() {
        Request<String, Auth0Exception> request = factory.delete(BASE_URL, resultAdapter);

        assertThat(request, is(notNullValue()));
        assertThat(request, is(deleteRequest));
    }

    @Test
    public void shouldCreateGetRequest() {
        Request<String, Auth0Exception> request = factory.get(BASE_URL, resultAdapter);

        assertThat(request, is(notNullValue()));
        assertThat(request, is(getRequest));
    }

    private RequestFactory<Auth0Exception> createRequestFactory() {
        RequestFactory<Auth0Exception> factory = spy(new RequestFactory<>(client, errorAdapter));
        when(factory.createRequest(eq(HttpMethod.POST.INSTANCE), eq(BASE_URL), eq(client), eq(resultAdapter), eq(errorAdapter)))
                .thenReturn(postRequest);
        when(factory.createRequest(eq(HttpMethod.DELETE.INSTANCE), eq(BASE_URL), eq(client), eq(resultAdapter), eq(errorAdapter)))
                .thenReturn(deleteRequest);
        when(factory.createRequest(eq(HttpMethod.PATCH.INSTANCE), eq(BASE_URL), eq(client), eq(resultAdapter), eq(errorAdapter)))
                .thenReturn(patchRequest);
        when(factory.createRequest(eq(HttpMethod.GET.INSTANCE), eq(BASE_URL), eq(client), eq(resultAdapter), eq(errorAdapter)))
                .thenReturn(getRequest);
        return factory;
    }
}