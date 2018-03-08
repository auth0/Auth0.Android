package com.auth0.android.request.internal;

import android.app.Activity;

import okhttp3.ConnectionSpec;
import okhttp3.Interceptor;
import okhttp3.OkHttpClient;
import okhttp3.TlsVersion;
import okhttp3.logging.HttpLoggingInterceptor;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.util.List;

import static junit.framework.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

@RunWith(RobolectricTestRunner.class)
@Config(constants = com.auth0.android.auth0.BuildConfig.class, sdk = 21, manifest = Config.NONE)
public class OkHttpClientFactoryTest {

    private Activity activity;
    private OkHttpClientFactory factory;

    @Before
    public void setUp(){
        MockitoAnnotations.initMocks(this);
        factory = new OkHttpClientFactory();
        activity = Robolectric.setupActivity(Activity.class);
    }

    @Test
    // Verify that there's no error when creating a new OkHttpClient instance
    public void shouldCreateNewClient(){
        factory.createClient(false, false);
    }

    @Test
    @Config(sdk=21)
    public void shouldEnableLoggingTLS12Enforced() {
        OkHttpClient.Builder builder = new OkHttpClient.Builder();
        OkHttpClient okHttpClient = factory.modifyClient(builder, true, true);
        verifyLoggingEnabled(okHttpClient);
        verifyTLS12Enforced(okHttpClient);
    }

    @Test
    @Config(sdk=21)
    public void shouldEnableLoggingTLS12NotEnforced(){
        OkHttpClient.Builder builder = new OkHttpClient.Builder();
        OkHttpClient okHttpClient = factory.modifyClient(builder, true, false);
        verifyLoggingEnabled(okHttpClient);
        verifyTLS12NotEnforced(builder.build());
    }

    @Test
    @Config(sdk=21)
    public void shouldDisableLoggingTLS12Enforced(){
        OkHttpClient.Builder builder = new OkHttpClient.Builder();
        OkHttpClient okHttpClient = factory.modifyClient(builder, false, true);
        verifyLoggingDisabled(okHttpClient);
        verifyTLS12Enforced(builder.build());
    }
//
    @Test
    @Config(sdk=21)
    public void shouldDisableLoggingTLS12NotEnforced(){
        OkHttpClient.Builder builder = new OkHttpClient.Builder();
        OkHttpClient client = factory.modifyClient(builder, false, false);
        verifyLoggingDisabled(client);
        verifyTLS12NotEnforced(client);
    }

    @Test
    @Config(sdk=22)
    public void shouldEnableLoggingTLS12Enforced_postLollipopTLS12NoEffect() {
        OkHttpClient.Builder builder = new OkHttpClient.Builder();
        OkHttpClient client = factory.modifyClient(builder, true, true);
        verifyLoggingEnabled(client);
        verifyTLS12NotEnforced(client);
    }

    @Test
    @Config(sdk=22)
    public void shouldEnableLoggingTLS12NotEnforced_posLollipop(){
        OkHttpClient.Builder builder = new OkHttpClient.Builder();
        OkHttpClient client = factory.modifyClient(builder, true, false);
        verifyLoggingEnabled(client);
        verifyTLS12NotEnforced(client);
    }

    @Test
    @Config(sdk=22)
    public void shouldDisableLoggingTLS12Enforced_postLollipopTLS12NoEffect(){
        OkHttpClient.Builder builder = new OkHttpClient.Builder();
        OkHttpClient client = factory.modifyClient(builder, false, true);
        verifyLoggingDisabled(client);
        verifyTLS12NotEnforced(client);
    }

    @Test
    @Config(sdk=22)
    public void shouldDisableLoggingTLS12NotEnforced_postLollipop(){
        OkHttpClient.Builder builder = new OkHttpClient.Builder();
        OkHttpClient client = factory.modifyClient(builder, false, false);
        verifyLoggingDisabled(client);
        verifyTLS12NotEnforced(client);
    }

    private static boolean containsInterceptor(List<Interceptor> list) {
        for (Interceptor interceptor : list) {
            if (interceptor instanceof HttpLoggingInterceptor
                    && ((HttpLoggingInterceptor) interceptor).getLevel() == HttpLoggingInterceptor.Level.BODY) {
                return true;
            }
        }
        return false;
    }

    private static void verifyLoggingEnabled(OkHttpClient client) {
        assertTrue(containsInterceptor(client.interceptors()));
    }

    private static void verifyLoggingDisabled(OkHttpClient client) {
        assertFalse(containsInterceptor(client.interceptors()));
    }

    private static void verifyTLS12NotEnforced(OkHttpClient client) {
        assertFalse(client.sslSocketFactory() instanceof TLS12SocketFactory);
    }

    private static void verifyTLS12Enforced(OkHttpClient client) {
        assertTrue(client.sslSocketFactory() instanceof TLS12SocketFactory);

        boolean hasTls12 = false;
        for (ConnectionSpec item : client.connectionSpecs()) {
            if (!item.isTls()) {
                continue;
            }
            List<TlsVersion> versions = item.tlsVersions();
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
