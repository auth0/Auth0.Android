package com.auth0.android.request.internal;


import com.auth0.android.Auth0Exception;
import com.auth0.android.request.ErrorAdapter;
import com.auth0.android.request.HttpMethod;
import com.auth0.android.request.JsonAdapter;
import com.auth0.android.request.NetworkingClient;
import com.auth0.android.request.Request;

import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.AdditionalMatchers;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.robolectric.RobolectricTestRunner;

import java.util.Locale;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

@Ignore
public class RequestFactoryTest {

    private static final String CLIENT_INFO = "client_info";
    private static final String BASE_URL = "http://domain.auth0.com";

    @Mock
    private NetworkingClient client;
    @Mock
    private ErrorAdapter<Auth0Exception> errorAdapter;
    @Mock
    private JsonAdapter<String> resultAdapter;
    @Mock
    private Request<String, Auth0Exception> postRequest;
    @Mock
    private Request<String, Auth0Exception> emptyPostRequest;
    @Mock
    private Request<String, Auth0Exception> patchRequest;
    @Mock
    private Request<String, Auth0Exception> getRequest;
    @Mock
    private Request<String, Auth0Exception> deleteRequest;

    private RequestFactory<Auth0Exception> factory;

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        factory = createRequestFactory();
    }

    @Test
    public void shouldHaveDefaultAcceptLanguageHeader() {
        final Locale locale = new Locale("");
        Locale.setDefault(locale);
        // recreate the factory to read the default again
        RequestFactory<Auth0Exception> factory = createRequestFactory();

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
        // recreate the factory to read the default again
        RequestFactory<Auth0Exception> factory = createRequestFactory();

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
        factory.setAuth0ClientInfo(CLIENT_INFO);

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
    public void shouldCreatePostRequest() {
        Request<String, Auth0Exception> request = factory.post(BASE_URL, resultAdapter);

        assertThat(request, is(notNullValue()));
        assertThat(request, is(postRequest));
    }

    @Test
    public void shouldCreateVoidPostRequest() {
        Request<Void, Auth0Exception> request = factory.post(BASE_URL);

        assertThat(request, is(notNullValue()));
        assertThat(request, is(emptyPostRequest));
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

    @SuppressWarnings("unchecked")
    private RequestFactory<Auth0Exception> createRequestFactory() {
        RequestFactory<Auth0Exception> factory = spy(new RequestFactory<>(client, errorAdapter));
        doReturn(postRequest).when(factory).createRequest(any(HttpMethod.POST.class), eq(BASE_URL), eq(client), eq(resultAdapter), eq(errorAdapter), any(ThreadSwitcher.class));
        doReturn(emptyPostRequest).when(factory).createRequest(any(HttpMethod.POST.class), eq(BASE_URL), eq(client), AdditionalMatchers.and(AdditionalMatchers.not(ArgumentMatchers.eq(resultAdapter)), ArgumentMatchers.isA(JsonAdapter.class)), eq(errorAdapter), any(ThreadSwitcher.class));
        doReturn(deleteRequest).when(factory).createRequest(any(HttpMethod.DELETE.class), eq(BASE_URL), eq(client), eq(resultAdapter), eq(errorAdapter), any(ThreadSwitcher.class));
        doReturn(patchRequest).when(factory).createRequest(any(HttpMethod.PATCH.class), eq(BASE_URL), eq(client), eq(resultAdapter), eq(errorAdapter), any(ThreadSwitcher.class));
        doReturn(getRequest).when(factory).createRequest(any(HttpMethod.GET.class), eq(BASE_URL), eq(client), eq(resultAdapter), eq(errorAdapter), any(ThreadSwitcher.class));
        return factory;
    }
}