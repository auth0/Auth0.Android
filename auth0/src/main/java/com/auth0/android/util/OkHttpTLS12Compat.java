package com.auth0.android.util;

import android.os.Build;
import android.util.Log;

import com.squareup.okhttp.ConnectionSpec;
import com.squareup.okhttp.OkHttpClient;
import com.squareup.okhttp.TlsVersion;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.SSLContext;

public final class OkHttpTLS12Compat {

    private static final String TAG = OkHttpTLS12Compat.class.getSimpleName();

    private OkHttpTLS12Compat() {}

    /**
     * Enable TLS 1.2 on the OkHttpClient on API 16-21, which is supported but not enabled by default.
     * @link https://github.com/square/okhttp/issues/2372
     * @see TLS12SocketFactory
     * @param client OkHttpClient instance to be modified
     */
    public static void enableForClient(OkHttpClient client) {
        // No need to modify client as TLS 1.2 is enabled by default on API21+
        // Lollipop is included because some Samsung devices face the same problem on API 21.
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.JELLY_BEAN || Build.VERSION.SDK_INT > Build.VERSION_CODES.LOLLIPOP) {
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
