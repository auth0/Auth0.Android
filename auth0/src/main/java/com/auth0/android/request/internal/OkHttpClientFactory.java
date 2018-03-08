package com.auth0.android.request.internal;

import android.os.Build;
import android.support.annotation.VisibleForTesting;
import android.util.Log;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.SSLContext;

import okhttp3.ConnectionSpec;
import okhttp3.Interceptor;
import okhttp3.OkHttpClient;
import okhttp3.TlsVersion;
import okhttp3.logging.HttpLoggingInterceptor;

/**
 * Factory class used to configure and obtain a new OkHttpClient instance.
 * This class is meant for internal use only,
 * breaking changes may appear at any time without backwards compatibility guarantee.
 */
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
        return modifyClient(new OkHttpClient.Builder(), loggingEnabled, tls12Enforced);
    }

    @VisibleForTesting
    OkHttpClient modifyClient(OkHttpClient.Builder clientBuilder, boolean loggingEnabled, boolean tls12Enforced) {
        if (loggingEnabled) {
            enableLogging(clientBuilder);
        }
        if (tls12Enforced) {
            enforceTls12(clientBuilder);
        }
        return clientBuilder.build();
    }

    private void enableLogging(OkHttpClient.Builder clientBuilder) {
        Interceptor interceptor = new HttpLoggingInterceptor()
                .setLevel(HttpLoggingInterceptor.Level.BODY);
        clientBuilder.addInterceptor(interceptor);
    }

    /**
     * Enable TLS 1.2 on the OkHttpClient on API 16-21, which is supported but not enabled by default.
     * @link https://github.com/square/okhttp/issues/2372
     * @see TLS12SocketFactory
     */
    private void enforceTls12(OkHttpClient.Builder clientBuilder) {
        // No need to modify client as TLS 1.2 is enabled by default on API21+
        // Lollipop is included because some Samsung devices face the same problem on API 21.
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.JELLY_BEAN
                || Build.VERSION.SDK_INT > Build.VERSION_CODES.LOLLIPOP) {
            return;
        }
        try {
            SSLContext sc = SSLContext.getInstance("TLSv1.2");
            sc.init(null, null, null);

            clientBuilder.sslSocketFactory(new TLS12SocketFactory(sc.getSocketFactory()));

            ConnectionSpec cs = new ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
                    .tlsVersions(TlsVersion.TLS_1_2)
                    .build();

            List<ConnectionSpec> specs = new ArrayList<>();
            specs.add(cs);
            specs.add(ConnectionSpec.COMPATIBLE_TLS);
            specs.add(ConnectionSpec.CLEARTEXT);

            clientBuilder.connectionSpecs(specs);

        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            Log.e(TAG, "Error while setting TLS 1.2", e);
        }
    }
}
