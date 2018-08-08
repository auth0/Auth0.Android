package com.auth0.android.authentication;

import android.net.Uri;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.annotation.VisibleForTesting;
import android.support.annotation.WorkerThread;
import android.util.Base64;
import android.util.Log;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonSyntaxException;
import com.google.gson.annotations.SerializedName;
import com.google.gson.reflect.TypeToken;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Type;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.List;

class JwkProvider implements KeyProvider {

    private static final String TAG = JwkProvider.class.getSimpleName();
    private final URL url;
    private List<Jwk> jwks;

    JwkProvider(@NonNull String domain) {
        this(createUrl(domain));
    }

    @SuppressWarnings("WeakerAccess")
    @VisibleForTesting
    JwkProvider(@NonNull URL url) {
        this.url = url;
    }

    @VisibleForTesting
    URL getURL() {
        return this.url;
    }

    private static URL createUrl(String domain) {
        String safeUrl = domain.startsWith("http") ? domain : "https://" + domain;
        try {
            final Uri.Builder builder = Uri.parse(safeUrl)
                    .buildUpon()
                    .appendPath(".well-known")
                    .appendPath("jwks.json");
            return new URL(builder.build().toString());
        } catch (MalformedURLException e) {
            throw new TokenVerificationException("The domain provided is not a valid URL", e);
        }
    }

    @Override
    public PublicKey getPublicKey(@Nullable String keyId) throws KeyProviderException {
        Exception exception = null;
        try {
            if (jwks == null) {
                jwks = fetchJwks();
            }
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
        } catch (IOException | InvalidKeyException | JsonParseException e) {
            exception = e;
        }
        throw new KeyProviderException(String.format("Could not obtain a JWK with key id %s", keyId), exception);
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


    @SuppressWarnings("unused")
    static class Jwk {

        private static final String RSA_ALGORITHM = "RSA";
        @SerializedName("kty")
        private String keyType;
        @SerializedName("kid")
        private String keyId;
        @SerializedName("n")
        private String n;
        @SerializedName("e")
        private String e;

        PublicKey getPublicKey() throws InvalidKeyException {
            if (!RSA_ALGORITHM.equalsIgnoreCase(keyType)) {
                throw new InvalidKeyException("The algorithm of this JWK is not supported");
            }
            try {
                KeyFactory kf = KeyFactory.getInstance(RSA_ALGORITHM);
                BigInteger modulus = new BigInteger(1, base64Decode(n));
                BigInteger exponent = new BigInteger(1, base64Decode(e));
                return kf.generatePublic(new RSAPublicKeySpec(modulus, exponent));
            } catch (InvalidKeySpecException e) {
                throw new InvalidKeyException("Invalid public key", e);
            } catch (NoSuchAlgorithmException e) {
                throw new InvalidKeyException("Invalid algorithm used to generate key", e);
            }
        }

        String getKeyId() {
            return keyId;
        }

        private byte[] base64Decode(String input) throws InvalidKeySpecException {
            try {
                return Base64.decode(input, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
            } catch (IllegalArgumentException e) {
                throw new InvalidKeySpecException("Could not base64 decode the given string.", e);
            }
        }
    }

    static class JwksDeserializer implements JsonDeserializer<List<Jwk>> {

        @Override
        public List<Jwk> deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
            if (!json.isJsonObject() || json.isJsonNull()) {
                throw new JsonParseException("JWKs JSON is not a valid json object");
            }

            List<Jwk> jwks = new ArrayList<>();
            JsonObject object = json.getAsJsonObject();
            JsonArray keys = object.getAsJsonArray("keys");
            for (JsonElement e : keys) {
                if (!e.getAsJsonObject().has("kty")) {
                    throw new JsonParseException(String.format("The JWK does not contain the required Key Type attribute. Values are: %s", e));
                }
                Jwk jwk = context.deserialize(e, Jwk.class);
                jwks.add(jwk);
            }
            return jwks;
        }
    }
}