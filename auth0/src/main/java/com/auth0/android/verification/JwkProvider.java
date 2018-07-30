package com.auth0.android.verification;

import android.net.Uri;
import android.support.annotation.Nullable;
import android.support.annotation.WorkerThread;
import android.util.Log;
import android.webkit.URLUtil;

import com.google.gson.Gson;
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
import java.util.Collection;
import java.util.Collections;
import java.util.List;

public class JwkProvider implements KeyProvider {

    private static final String TAG = JwkProvider.class.getSimpleName();
    private final URL url;
    private List<Jwk> jwks;

    public JwkProvider(String domain) {
        url = createUrl(domain);
        fetchJwks(url);
    }

    @SuppressWarnings("unchecked")
    private List<Jwk> fetchJwks(URL url) {
        Log.d(TAG, String.format("Trying to fetch JWKS from %s", url.toString()));
        HttpURLConnection urlConnection = null;
        List<Jwk> jwks = Collections.emptyList();
        try {
            urlConnection = (HttpURLConnection) url.openConnection();
            InputStream is = urlConnection.getInputStream();

            Type listType = new TypeToken<List<Jwk>>() {
            }.getType();
            InputStreamReader reader = new InputStreamReader(is, Charset.defaultCharset());
            jwks.addAll((Collection<? extends Jwk>) new Gson().fromJson(reader, listType));
        } catch (IOException e) {
            //TODO: handle
            e.printStackTrace();
        } finally {
            if (urlConnection != null) {
                urlConnection.disconnect();
            }
        }
        return jwks;
    }

    private URL createUrl(String domain) {
        //TODO: Extract to constructor parameter
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
    @WorkerThread
    public PublicKey getPublicKey(@Nullable String keyId) throws KeyProviderException {
        if (jwks == null) {
            jwks = fetchJwks(url);
        }
        Throwable creationException = null;
        try {
            if (keyId == null && jwks.size() == 1) {
                return jwks.get(0).getPublicKey();
            }
            if (keyId != null) {
                for (Jwk jwk : jwks) {
                    if (keyId.equals(jwk.getKeyId())) {
                        return jwk.getPublicKey();
                    }
                }
            }
        } catch (InvalidKeyException e) {
            creationException = e;
        }
        throw new KeyProviderException(String.format("Could not obtain a Json Web Key with key id %s", keyId), creationException);
    }
}
