package com.auth0.android.request.internal;

import android.util.Base64;
import android.util.Log;

import com.google.gson.JsonArray;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;

import java.lang.reflect.Type;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

class JwksDeserializer implements JsonDeserializer<Map<String, PublicKey>> {

    private static final String RSA_ALGORITHM = "RS256";
    private static final String USE_SIGNING = "sig";

    @Override
    public Map<String, PublicKey> deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
        if (!json.isJsonObject() || json.isJsonNull() || json.getAsJsonObject().entrySet().isEmpty()) {
            throw new JsonParseException("jwks json is not a valid json object");
        }

        HashMap<String, PublicKey> jwks = new HashMap<>();

        JsonObject object = json.getAsJsonObject();
        JsonArray keys = object.getAsJsonArray("keys");
        for (JsonElement k : keys) {
            JsonObject currentKey = k.getAsJsonObject();
            String keyAlg = context.deserialize(currentKey.remove("alg"), String.class);
            String keyUse = context.deserialize(currentKey.remove("use"), String.class);
            if (!RSA_ALGORITHM.equals(keyAlg) || !USE_SIGNING.equals(keyUse)) {
                //Key not supported at this time
                continue;
            }
            String keyType = context.deserialize(currentKey.remove("kty"), String.class);
            String keyId = context.deserialize(currentKey.remove("kid"), String.class);
            String keyModulus = context.deserialize(currentKey.remove("n"), String.class);
            String keyPublicExponent = context.deserialize(currentKey.remove("e"), String.class);

            try {
                KeyFactory kf = KeyFactory.getInstance(keyType);
                BigInteger modulus = new BigInteger(1, Base64.decode(keyModulus, Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP));
                BigInteger exponent = new BigInteger(1, Base64.decode(keyPublicExponent, Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP));
                PublicKey pub = kf.generatePublic(new RSAPublicKeySpec(modulus, exponent));
                jwks.put(keyId, pub);
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                Log.e(JwksDeserializer.class.getSimpleName(), "Could not parse the JWK with ID " + keyId, e);
                //Would result in an empty key set
            }
        }
        return Collections.unmodifiableMap(jwks);
    }

}
