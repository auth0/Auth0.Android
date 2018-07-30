package com.auth0.android.verification;

import android.os.Handler;
import android.support.annotation.NonNull;
import android.text.TextUtils;
import android.util.Base64;

import com.auth0.android.jwt.JWT;

import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

public class JwtVerifier {

    private static final String RSA256_ALGORITHM = "SHA256withRSA";
    private final Handler handler;
    private final KeyProvider keyProvider;

    public JwtVerifier(@NonNull KeyProvider keyProvider) {
        this.handler = new Handler();
        this.keyProvider = keyProvider;
    }

    public void verify(String token, @NonNull JwtVerifierCallback callback) {
        VerificationTask task = new VerificationTask(new JWT(token), callback);
        handler.post(task);
    }

    private class VerificationTask implements Runnable {
        private final JWT jwt;
        private final JwtVerifierCallback callback;

        VerificationTask(JWT jwt, JwtVerifierCallback callback) {
            this.jwt = jwt;
            this.callback = callback;
        }

        @Override
        public void run() {
            String kid = jwt.getHeader().get("kid");
            PublicKey publicKey = keyProvider.getPublicKey(kid);

            String[] parts = jwt.toString().split("\\.");
            if (TextUtils.isEmpty(parts[3])) {
                callback.onFailure(new TokenVerificationException("The token is not signed"));
                return;
            } else if (!"RS256".equalsIgnoreCase(jwt.getHeader().get("alg"))) {
                callback.onFailure(new TokenVerificationException("The token must be signed with RS256"));
                return;
            }


            byte[] content = String.format("%s.%s", parts[0], parts[1]).getBytes(Charset.defaultCharset());
            byte[] signature = Base64.decode(parts[2], Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);

            try {
                if (verifySignatureFor(publicKey, content, signature)) {
                    //TODO: call verifyContents(). Assert exp, nbf, etc
                    callback.onSuccess(jwt);
                } else {
                    callback.onFailure(new TokenVerificationException("The token signature is invalid"));
                }
            } catch (Exception e) {
                callback.onFailure(new TokenVerificationException("Could not verify the token's signature", e));
            }
        }

        private boolean verifySignatureFor(PublicKey publicKey, byte[] contentBytes, byte[] signatureBytes) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
            final Signature s = Signature.getInstance(RSA256_ALGORITHM);
            s.initVerify(publicKey);
            s.update(contentBytes);
            return s.verify(signatureBytes);
        }

        private void verifyContents() {
            //TODO
        }
    }
}
