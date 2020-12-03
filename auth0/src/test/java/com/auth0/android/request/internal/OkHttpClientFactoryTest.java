package com.auth0.android.request.internal;

import com.squareup.okhttp.ConnectionSpec;
import com.squareup.okhttp.Interceptor;
import com.squareup.okhttp.OkHttpClient;
import com.squareup.okhttp.Protocol;
import com.squareup.okhttp.TlsVersion;
import com.squareup.okhttp.logging.HttpLoggingInterceptor;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.util.List;

import javax.net.ssl.SSLSocketFactory;

import static junit.framework.Assert.assertTrue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(RobolectricTestRunner.class)
public class OkHttpClientFactoryTest {

    private OkHttpClientFactory factory;
    @Mock
    private OkHttpClient mockClient;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        factory = new OkHttpClientFactory();
    }

    @Test
    // Verify that there's no error when creating a new OkHttpClient instance
    public void shouldCreateNewClient() {
        factory.createClient(false, false, 0, 0, 0);
    }

    @Test
    public void shouldNotUseHttp2Protocol() {
        OkHttpClient client = factory.createClient(false, false, 0, 0, 0);
        //Doesn't use default protocols
        assertThat(client.getProtocols(), is(notNullValue()));
        assertThat(client.getProtocols().contains(Protocol.HTTP_1_1), is(true));
        assertThat(client.getProtocols().contains(Protocol.SPDY_3), is(true));
        assertThat(client.getProtocols().contains(Protocol.HTTP_2), is(false));
    }

    @Test
    public void shouldUseDefaultTimeoutWhenTimeoutZero() {
        OkHttpClient client = factory.createClient(false, false, 0, 0, 0);
        assertThat(client.getConnectTimeout(), is(10000));
        assertThat(client.getReadTimeout(), is(10000));
        assertThat(client.getWriteTimeout(), is(10000));
    }

    @Test
    public void shouldUsePassedInTimeout() {
        OkHttpClient client = factory.createClient(false, false, 5, 15, 20);
        assertThat(client.getConnectTimeout(), is(5000));
        assertThat(client.getReadTimeout(), is(15000));
        assertThat(client.getWriteTimeout(), is(20000));
    }

    @Test
    @Config(sdk = 21)
    public void shouldEnableLoggingTLS12Enforced() {
        List list = generateInterceptorsMockList(mockClient);
        OkHttpClient client = factory.modifyClient(mockClient, true, true, 0, 0, 0);
        verifyLoggingEnabled(client, list);
        verifyTLS12Enforced(client);
    }

    @Test
    @Config(sdk = 21)
    public void shouldEnableLoggingTLS12NotEnforced() {
        List list = generateInterceptorsMockList(mockClient);
        OkHttpClient client = factory.modifyClient(mockClient, true, false, 0, 0, 0);
        verifyLoggingEnabled(client, list);
        verifyTLS12NotEnforced(client);
    }

    @Test
    @Config(sdk = 21)
    public void shouldDisableLoggingTLS12Enforced() {
        List list = generateInterceptorsMockList(mockClient);
        OkHttpClient client = factory.modifyClient(mockClient, false, true, 0, 0, 0);
        verifyLoggingDisabled(client, list);
        verifyTLS12Enforced(client);
    }

    @Test
    @Config(sdk = 21)
    public void shouldDisableLoggingTLS12NotEnforced() {
        List list = generateInterceptorsMockList(mockClient);
        OkHttpClient client = factory.modifyClient(mockClient, false, false, 0, 0, 0);
        verifyLoggingDisabled(client, list);
        verifyTLS12NotEnforced(client);
    }

    @Test
    @Config(sdk = 22)
    public void shouldEnableLoggingTLS12Enforced_postLollipopTLS12NoEffect() {
        List list = generateInterceptorsMockList(mockClient);
        OkHttpClient client = factory.modifyClient(mockClient, true, true, 0, 0, 0);
        verifyLoggingEnabled(client, list);
        verifyTLS12NotEnforced(client);
    }

    @Test
    @Config(sdk = 22)
    public void shouldEnableLoggingTLS12NotEnforced_postLollipop() {
        List list = generateInterceptorsMockList(mockClient);
        OkHttpClient client = factory.modifyClient(mockClient, true, false, 0, 0, 0);
        verifyLoggingEnabled(client, list);
        verifyTLS12NotEnforced(client);
    }

    @Test
    @Config(sdk = 22)
    public void shouldDisableLoggingTLS12Enforced_postLollipopTLS12NoEffect() {
        List list = generateInterceptorsMockList(mockClient);
        OkHttpClient client = factory.modifyClient(mockClient, false, true, 0, 0, 0);
        verifyLoggingDisabled(client, list);
        verifyTLS12NotEnforced(client);
    }

    @Test
    @Config(sdk = 22)
    public void shouldDisableLoggingTLS12NotEnforced_postLollipop() {
        List list = generateInterceptorsMockList(mockClient);
        OkHttpClient client = factory.modifyClient(mockClient, false, false, 0, 0, 0);
        verifyLoggingDisabled(client, list);
        verifyTLS12NotEnforced(client);
    }

    private static List generateInterceptorsMockList(OkHttpClient client) {
        List list = mock(List.class);
        when(client.interceptors()).thenReturn(list);
        return list;
    }

    private static void verifyLoggingEnabled(OkHttpClient client, List list) {
        verify(client).interceptors();

        ArgumentCaptor<Interceptor> interceptorCaptor = ArgumentCaptor.forClass(Interceptor.class);
        verify(list).add(interceptorCaptor.capture());

        assertThat(interceptorCaptor.getValue(), is(notNullValue()));
        assertThat(interceptorCaptor.getValue(), is(instanceOf(HttpLoggingInterceptor.class)));
        assertThat(((HttpLoggingInterceptor) interceptorCaptor.getValue()).getLevel(), is(HttpLoggingInterceptor.Level.BODY));
    }

    private static void verifyLoggingDisabled(OkHttpClient client, List list) {
        verify(client, never()).interceptors();
        verify(list, never()).add(any(Interceptor.class));
    }

    private static void verifyTLS12NotEnforced(OkHttpClient client) {
        verify(client, never()).setSslSocketFactory(any(SSLSocketFactory.class));
    }

    private static void verifyTLS12Enforced(OkHttpClient client) {

        ArgumentCaptor<SSLSocketFactory> factoryCaptor = ArgumentCaptor.forClass(SSLSocketFactory.class);
        verify(client).setSslSocketFactory(factoryCaptor.capture());
        assertTrue(factoryCaptor.getValue() instanceof TLS12SocketFactory);

        ArgumentCaptor<List> specCaptor = ArgumentCaptor.forClass(List.class);
        verify(client).setConnectionSpecs(specCaptor.capture());
        boolean hasTls12 = false;
        for (Object item : specCaptor.getValue()) {
            assertTrue(item instanceof ConnectionSpec);
            ConnectionSpec spec = (ConnectionSpec) item;
            if (!spec.isTls()) {
                continue;
            }
            List<TlsVersion> versions = spec.tlsVersions();
            for (TlsVersion version : versions) {
                if ("TLSv1.2".equals(version.javaName())) {
                    hasTls12 = true;
                    break;
                }
            }
        }
        assertTrue(hasTls12);
    }
}
