package com.auth0.android.verification;

import android.net.Uri;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.annotation.WorkerThread;
import android.util.Log;
import android.webkit.URLUtil;

import com.auth0.android.callback.BaseCallback;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Type;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.util.List;

public class JwkProvider implements KeyProvider {

    private static final String TAG = JwkProvider.class.getSimpleName();
    private final URL url;
    private List<Jwk> jwks;

    public JwkProvider(@NonNull String domain) {
        url = createUrl(domain);
    }

    private URL createUrl(String domain) {
        final Uri.Builder builder = Uri.parse(domain)
                .buildUpon()
                .appendPath(".well-known")
                .appendPath("jwks.json");
        if (!URLUtil.isHttpUrl(domain)) {
            builder.scheme("https");
        }
        try {
            return new URL(builder.build().toString());
        } catch (MalformedURLException e) {
            throw new TokenVerificationException("The domain provided is not a valid URL", e);
        }
    }

    @Override
    public void getPublicKey(@Nullable final String keyId, @NonNull final BaseCallback<PublicKey, KeyProviderException> callback) {
        Runnable task = new Runnable() {
            @Override
            public void run() {
                try {
                    if (jwks == null) {
                        jwks = fetchJwks();
                    }
                    if (keyId == null && jwks.size() == 1) {
                        callback.onSuccess(jwks.get(0).getPublicKey());
                        return;
                    }
                    if (keyId != null) {
                        for (Jwk jwk : jwks) {
                            if (keyId.equals(jwk.getKeyId())) {
                                callback.onSuccess(jwk.getPublicKey());
                            }
                        }
                    }
                } catch (IOException | InvalidKeyException e) {
                    callback.onFailure(new KeyProviderException(String.format("Could not obtain a JWK with key id %s", keyId), e));
                }
            }
        };
        new Thread(task).start();
    }

    @WorkerThread
    private List<Jwk> fetchJwks() throws IOException {
        Log.d(TAG, String.format("Trying to fetch JWKS from %s", url.toString()));
        HttpURLConnection urlConnection = null;
        try {
            urlConnection = (HttpURLConnection) url.openConnection();
            InputStream is = urlConnection.getInputStream();

            Type listType = new TypeToken<List<Jwk>>() {
            }.getType();
            InputStreamReader reader = new InputStreamReader(is, Charset.defaultCharset());
            Gson gson = new GsonBuilder()
                    .registerTypeAdapter(listType, new JwksDeserializer())
                    .create();
            return gson.fromJson(reader, listType);
        } finally {
            if (urlConnection != null) {
                urlConnection.disconnect();
            }
        }
    }
}