package com.auth0.android.authentication;

import android.support.annotation.NonNull;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;

import com.auth0.android.jwt.JWT;

import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Date;
import java.util.List;

public class JwtVerifier {

    private static final String TAG = JwtVerifier.class.getSimpleName();
    private static final String ALGORITHM_NAME = "RS256";
    private static final String ALGORITHM_DESCRIPTION = "SHA256withRSA";
    private final KeyProvider keyProvider;
    private String expectedIssuer;
    private String expectedAudience;

    JwtVerifier(@NonNull KeyProvider keyProvider) {
        this.keyProvider = keyProvider;
    }

    public void verify(String token) throws TokenVerificationException {
        Log.d(TAG, "Verifying received token");

        //Step 1: Assert token contains signature and is of type RS256
        String[] parts = token.split("\\.");
        if (parts.length != 3 || TextUtils.isEmpty(parts[2])) {
            throw new TokenVerificationException("The token is not signed");
        }
        JWT jwt = new JWT(token);
        if (!ALGORITHM_NAME.equalsIgnoreCase(jwt.getHeader().get("alg"))) {
            //Only tokens with RS256 are allowed. But let the remaining be "valid" for retro compatibility
            Log.w(TAG, "Skipping Token verification as it was not signed using the RS256 algorithm");
            //FIXME: This case should not be allowed in the new major
            return;
        }

        byte[] content = String.format("%s.%s", parts[0], parts[1]).getBytes(Charset.defaultCharset());
        byte[] signature = Base64.decode(parts[2], Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);

        //Step 2: Verify the signature using the Public Key
        try {
            String kid = jwt.getHeader().get("kid");
            PublicKey publicKey = keyProvider.getPublicKey(kid);
            if (!verifySignature(publicKey, content, signature)) {
                throw new SignatureException("The signature does not match");
            }
        } catch (Exception e) {
            throw new TokenVerificationException("Could not verify the token's signature", e);
        }

        //Step 3: Verify the claims - Following https://auth0.com/docs/tokens/id-token#validate-the-claims
        Date today = new Date();
        Date exp = jwt.getExpiresAt();
        if (exp != null && exp.before(today)) {
            throw new TokenVerificationException(String.format("The token has expired at %s", exp));
        }
        Date nbf = jwt.getNotBefore();
        if (nbf != null && today.before(nbf)) {
            throw new TokenVerificationException(String.format("The token cannot be used before %s", nbf));
        }
        String issuer = jwt.getIssuer();
        if (issuer != null && expectedIssuer != null && !issuer.equals(expectedIssuer)) {
            throw new TokenVerificationException("The token has an invalid issuer");
        }
        List<String> audience = jwt.getAudience();
        if (!audience.isEmpty() && expectedAudience != null && !audience.contains(expectedAudience)) {
            throw new TokenVerificationException("The token has an invalid audience");
        }
    }

    private boolean verifySignature(PublicKey publicKey, byte[] contentBytes, byte[] signatureBytes) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        final Signature s = Signature.getInstance(ALGORITHM_DESCRIPTION);
        s.initVerify(publicKey);
        s.update(contentBytes);
        return s.verify(signatureBytes);
    }

    void setExpectedValues(@NonNull String issuer, @NonNull String audience) {
        this.expectedIssuer = issuer;
        this.expectedAudience = audience;
    }
}
