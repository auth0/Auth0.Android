package com.auth0.android.request.internal;

import android.os.Build;
import android.support.annotation.VisibleForTesting;
import android.util.Log;

import com.squareup.okhttp.ConnectionSpec;
import com.squareup.okhttp.Interceptor;
import com.squareup.okhttp.OkHttpClient;
import com.squareup.okhttp.TlsVersion;
import com.squareup.okhttp.logging.HttpLoggingInterceptor;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.SSLContext;

public class OkHttpClientFactory {

    private static final String TAG = OkHttpClientFactory.class.getSimpleName();

    /**
     * This method creates an instance of OKHttpClient according to the provided parameters.
     * It is used internally and is not intended to be used directly.
     * @param loggingEnabled Enable logging in the created OkHttpClient.
     * @param tls12Enforced Enforce TLS 1.2 in the created OkHttpClient on devices with API 16-21
     * @return new OkHttpClient instance created according to the parameters.
     */
    public OkHttpClient createClient(boolean loggingEnabled, boolean tls12Enforced) {
        return modifyClient(new OkHttpClient(), loggingEnabled, tls12Enforced);
    }

    @VisibleForTesting
    OkHttpClient modifyClient(OkHttpClient client, boolean loggingEnabled, boolean tls12Enforced) {
        if (loggingEnabled) {
            enableLogging(client);
        }
        if (tls12Enforced) {
            enforceTls12(client);
        }
        return client;
    }

    private void enableLogging(OkHttpClient client) {
        Interceptor interceptor = new HttpLoggingInterceptor()
                .setLevel(HttpLoggingInterceptor.Level.BODY);
        client.interceptors().add(interceptor);
    }

    /**
     * Enable TLS 1.2 on the OkHttpClient on API 16-21, which is supported but not enabled by default.
     * @link https://github.com/square/okhttp/issues/2372
     * @see TLS12SocketFactory
     */
    private void enforceTls12(OkHttpClient client) {
        // No need to modify client as TLS 1.2 is enabled by default on API21+
        // Lollipop is included because some Samsung devices face the same problem on API 21.
        if (client == null || Build.VERSION.SDK_INT < Build.VERSION_CODES.JELLY_BEAN
                || Build.VERSION.SDK_INT > Build.VERSION_CODES.LOLLIPOP) {
            return;
        }
        try {
            SSLContext sc = SSLContext.getInstance("TLSv1.2");
            sc.init(null, null, null);
            client.setSslSocketFactory(new TLS12SocketFactory(sc.getSocketFactory()));

            ConnectionSpec cs = new ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
                    .tlsVersions(TlsVersion.TLS_1_2)
                    .build();

            List<ConnectionSpec> specs = new ArrayList<>();
            specs.add(cs);
            specs.add(ConnectionSpec.COMPATIBLE_TLS);
            specs.add(ConnectionSpec.CLEARTEXT);

            client.setConnectionSpecs(specs);
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            Log.e(TAG, "Error while setting TLS 1.2", e);
        }
    }
}
