package com.auth0.android.provider;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import android.util.Base64;

import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Collections;

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
        super(Collections.singletonList("RS256"));
        try {
            publicSignature = Signature.getInstance("SHA256withRSA");
            publicSignature.initVerify(publicKey);
        } catch (NoSuchAlgorithmException ignored) {
            //Safe to ignore: "SHA256withRSA" is available since API 1
            //https://developer.android.com/reference/java/security/Signature.html
        }
    }

    @Override
    protected void checkSignature(@NonNull String[] tokenParts) throws TokenValidationException {
        String content = tokenParts[0] + "." + tokenParts[1];
        byte[] contentBytes = content.getBytes(Charset.defaultCharset());
        boolean valid = false;
        try {
            byte[] signatureBytes = Base64.decode(tokenParts[2], Base64.URL_SAFE | Base64.NO_WRAP);
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
