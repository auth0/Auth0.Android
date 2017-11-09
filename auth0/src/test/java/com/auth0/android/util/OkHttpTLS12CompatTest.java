package com.auth0.android.util;

import android.app.Activity;

import com.squareup.okhttp.ConnectionSpec;
import com.squareup.okhttp.OkHttpClient;
import com.squareup.okhttp.TlsVersion;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.util.List;

import javax.net.ssl.SSLSocketFactory;

import static junit.framework.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

@RunWith(RobolectricTestRunner.class)
@Config(constants = com.auth0.android.auth0.BuildConfig.class, sdk = 21, manifest = Config.NONE)
public class OkHttpTLS12CompatTest {

    Activity activity;
    @Mock OkHttpClient client;

    @Before
    public void setUp(){
        MockitoAnnotations.initMocks(this);
        activity = Robolectric.setupActivity(Activity.class);
    }

    @Test
    @Config(sdk=22)
    public void shouldNotConfigTlsPostApi21() {
        OkHttpTLS12Compat.enableForClient(client);
        verify(client, never()).setSslSocketFactory((SSLSocketFactory) any());
    }

    @Test
    @Config(sdk=21)
    public void shouldConfigTlsOnOrPreApi21() {
        OkHttpTLS12Compat.enableForClient(client);

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
