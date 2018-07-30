package com.auth0.android.verification;

import android.support.annotation.NonNull;
import android.text.TextUtils;
import android.util.Base64;

import com.auth0.android.callback.BaseCallback;
import com.auth0.android.jwt.JWT;

import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

public class JwtVerifier {

    private static final String RSA256_ALGORITHM = "SHA256withRSA";
    private final KeyProvider keyProvider;

    public JwtVerifier(@NonNull KeyProvider keyProvider) {
        this.keyProvider = keyProvider;
    }

    public void verify(String token, @NonNull final BaseCallback<Void, TokenVerificationException> callback) {
        final JWT jwt = new JWT(token);
        String kid = jwt.getHeader().get("kid");

        keyProvider.getPublicKey(kid, new BaseCallback<PublicKey, KeyProviderException>() {
            @Override
            public void onSuccess(PublicKey publicKey) {
                try {
                    runVerifications(jwt, publicKey);
                    callback.onSuccess(null);
                } catch (TokenVerificationException e) {
                    callback.onFailure(e);
                }
            }

            @Override
            public void onFailure(KeyProviderException error) {
                callback.onFailure(new TokenVerificationException("Could not obtain the Public Key", error));
            }
        });
    }

    private void runVerifications(JWT jwt, PublicKey publicKey) throws TokenVerificationException {
        //Step 1: Assert token contains signature and is of type RSA256
        String[] parts = jwt.toString().split("\\.");
        if (TextUtils.isEmpty(parts[2])) {
            throw new TokenVerificationException("The token is not signed");
        } else if (!"RS256".equalsIgnoreCase(jwt.getHeader().get("alg"))) {
            throw new TokenVerificationException("The token must be signed with RS256");
        }

        byte[] content = String.format("%s.%s", parts[0], parts[1]).getBytes(Charset.defaultCharset());
        byte[] signature = Base64.decode(parts[2], Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);

        //Step 2: Verify the signature using the Public Key
        try {
            if (!verifySignature(publicKey, content, signature)) {
                throw new SignatureException("The signature does not match");
            }
        } catch (Exception e) {
            throw new TokenVerificationException("Could not verify the token's signature", e);
        }

        //Step 3: Verify the claims
        //TODO: call verifyContents(). Assert exp, nbf, etc
        verifyContents();
    }

    private boolean verifySignature(PublicKey publicKey, byte[] contentBytes, byte[] signatureBytes) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        final Signature s = Signature.getInstance(RSA256_ALGORITHM);
        s.initVerify(publicKey);
        s.update(contentBytes);
        return s.verify(signatureBytes);
    }

    private void verifyContents() {
        //TODO
    }
}
