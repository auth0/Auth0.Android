package com.auth0.android.provider;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.util.Base64;

import com.auth0.android.jwt.JWT;

import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;

/**
 * Token signature verifier for HS256 algorithms.
 */
class AsymmetricSignatureVerifier extends SignatureVerifier {

    private Signature publicSignature;

    /**
     * Creates a new instance of the verifier
     *
     * @param publicKey the public key to use for verification
     * @throws InvalidKeyException if the public key provided is null or not of type RSA
     */
    AsymmetricSignatureVerifier(@Nullable PublicKey publicKey) throws InvalidKeyException {
        try {
            publicSignature = Signature.getInstance("SHA256withRSA");
            publicSignature.initVerify(publicKey);
        } catch (NoSuchAlgorithmException ignored) {
            //Safe to ignore: "SHA256withRSA" is available since API 1
            //https://developer.android.com/reference/java/security/Signature.html
        }
    }

    @Override
    void verifySignature(@NonNull JWT token) throws TokenValidationException {
        String[] parts = token.toString().split("\\.");
        String content = parts[0] + "." + parts[1];
        byte[] contentBytes = content.getBytes(Charset.defaultCharset());
        byte[] signatureBytes = Base64.decode(parts[2], Base64.URL_SAFE | Base64.NO_WRAP);
        boolean valid = false;
        try {
            publicSignature.update(contentBytes);
            valid = publicSignature.verify(signatureBytes);
        } catch (Exception ignored) {
            //safe to ignore: throws when the Signature object is not properly initialized
        }
        if (!valid) {
            throw new TokenValidationException("Invalid ID token signature.");
        }
    }
}
