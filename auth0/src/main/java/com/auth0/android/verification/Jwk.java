package com.auth0.android.verification;

import android.text.TextUtils;
import android.util.Base64;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Collections;
import java.util.Map;

class Jwk {

    private static final String RSA_ALGORITHM = "RSA";
    private final String keyType;
    private final String keyId;
    private final Map<String, Object> values;

    @SuppressWarnings("unchecked")
    Jwk(Map<String, Object> values) {
        this.keyType = (String) values.remove("kty");
        if (TextUtils.isEmpty(keyType)) {
            //TODO: Assert this constructor gets called when deserializing
            throw new TokenVerificationException(String.format("The Jwk does not contain the required Key Type attribute. Values are: %s", values));
        }
        this.keyId = (String) values.remove("kid");
        this.values = Collections.unmodifiableMap(values);
    }


    /**
     * Returns a {@link PublicKey} if the {@code 'alg'} is {@code 'RSA'}
     *
     * @return a public key
     */
    @SuppressWarnings("WeakerAccess")
    public PublicKey getPublicKey() throws InvalidKeyException {
        if (!RSA_ALGORITHM.equalsIgnoreCase(keyType)) {
            return null;
        }
        try {
            KeyFactory kf = KeyFactory.getInstance(RSA_ALGORITHM);
            BigInteger modulus = new BigInteger(1, base64Decode((String) values.get("n")));
            BigInteger exponent = new BigInteger(1, base64Decode((String) values.get("e")));
            return kf.generatePublic(new RSAPublicKeySpec(modulus, exponent));
        } catch (InvalidKeySpecException e) {
            throw new InvalidKeyException("Invalid public key", e);
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidKeyException("Invalid algorithm to generate key", e);
        }
    }

    public String getKeyId() {
        return keyId;
    }

    private byte[] base64Decode(String input) {
        try {
            return Base64.decode(input, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
        } catch (IllegalArgumentException e) {
            throw new TokenVerificationException("Could not base64 decode the given string.", e);
        }
    }
}
