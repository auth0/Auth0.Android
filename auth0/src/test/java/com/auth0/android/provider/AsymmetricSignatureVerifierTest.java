package com.auth0.android.provider;

import com.auth0.android.request.internal.Jwt;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;

import java.security.PublicKey;

import static com.auth0.android.provider.JwtTestUtils.createJWTBody;
import static com.auth0.android.provider.JwtTestUtils.createTestJWT;
import static com.auth0.android.provider.JwtTestUtils.getPublicKey;
import static org.junit.Assert.assertEquals;

@RunWith(RobolectricTestRunner.class)
public class AsymmetricSignatureVerifierTest {

    @Test
    public void sameInstanceCanVerifyMultipleTokens() throws Exception {
        PublicKey publicKey = getPublicKey();
        AsymmetricSignatureVerifier verifier = new AsymmetricSignatureVerifier(publicKey);

        String signedToken1 = createTestJWT("RS256", createJWTBody("iss"));
        String signedToken2 = createTestJWT("RS256", createJWTBody("sub"));
        String signedToken3 = createTestJWT("RS256", createJWTBody("aud"));

        verifier.verify(new Jwt(signedToken1));
        verifier.verify(new Jwt(signedToken2));
        verifier.verify(new Jwt(signedToken3));
    }

    @Test
    public void shouldThrowWhenSignatureIsInvalid() {
        String message = "Invalid ID token signature.";
        Exception e = Assert.assertThrows(message, InvalidIdTokenSignatureException.class, () -> {
            PublicKey publicKey = getPublicKey();
            AsymmetricSignatureVerifier verifier = new AsymmetricSignatureVerifier(publicKey);

            String signedToken = createTestJWT("RS256", createJWTBody());
            //remove signature
            String[] parts = signedToken.split("\\.");
            signedToken = parts[0] + "." + parts[1] + ".unexpected-signature";

            verifier.verify(new Jwt(signedToken));
        });
        assertEquals("com.auth0.android.provider.TokenValidationException: " + message, e.toString());
        assertEquals(message, e.getMessage());
    }

    @Test
    public void shouldThrowWhenAlgorithmIsNotSupported() {
        String message = "Signature algorithm of \"none\" is not supported. Expected the ID token to be signed with RS256.";
        Exception e = Assert.assertThrows(message, IdTokenAlgorithmNotSupportedException.class, () -> {
            PublicKey publicKey = getPublicKey();
            AsymmetricSignatureVerifier verifier = new AsymmetricSignatureVerifier(publicKey);

            String noneToken = createTestJWT("none", createJWTBody());

            verifier.verify(new Jwt(noneToken));
        });
        assertEquals("com.auth0.android.provider.TokenValidationException: " + message, e.toString());
        assertEquals(message, e.getMessage());
    }

    @Test
    public void shouldThrowWhenAlgorithmIsSymmetric() {
        String message = "Signature algorithm of \"HS256\" is not supported. Expected the ID token to be signed with RS256.";
        Exception e = Assert.assertThrows(message, IdTokenAlgorithmNotSupportedException.class, () -> {
            PublicKey publicKey = getPublicKey();
            AsymmetricSignatureVerifier verifier = new AsymmetricSignatureVerifier(publicKey);

            String hsToken = createTestJWT("HS256", createJWTBody());

            verifier.verify(new Jwt(hsToken));
        });
        assertEquals("com.auth0.android.provider.TokenValidationException: " + message, e.toString());
        assertEquals(message, e.getMessage());
    }
}