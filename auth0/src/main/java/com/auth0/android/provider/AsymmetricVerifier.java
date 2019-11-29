package com.auth0.android.provider;

import android.util.Base64;

import com.auth0.android.jwt.JWT;

import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

class AsymmetricVerifier extends SignatureVerifier {

    private static final String EXPECTED_ALGORITHM = "RS256";
    private Signature publicSignature;

    AsymmetricVerifier(PublicKey publicKey) throws InvalidKeyException {
        super(EXPECTED_ALGORITHM);
        try {
            publicSignature = Signature.getInstance("SHA256withRSA");
            publicSignature.initVerify(publicKey);
        } catch (NoSuchAlgorithmException ignored) {
            //Safe to ignore: "SHA256withRSA" is available since API 1
            //https://developer.android.com/reference/java/security/Signature.html
        }
    }


    @Override
    void verifySignature(JWT token) throws TokenValidationException {
        super.verifySignature(token);
        String[] parts = token.toString().split("\\.");
        String content = parts[0] + "." + parts[1];
        byte[] contentBytes = content.getBytes(Charset.defaultCharset());
        byte[] signatureBytes = Base64.decode(parts[2], Base64.URL_SAFE | Base64.NO_WRAP);
        performCheck(contentBytes, signatureBytes);
    }

    private void performCheck(byte[] content, byte[] signature) {
        boolean valid = false;
        try {
            publicSignature.update(content);
            valid = publicSignature.verify(signature);
        } catch (SignatureException ignored) {
        }
        if (!valid) {
            throw new TokenValidationException("Invalid token signature.");
        }
    }
}
