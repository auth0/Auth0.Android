package com.auth0.android.provider;

import com.auth0.android.request.internal.Jwt;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;

import java.security.PublicKey;

import static com.auth0.android.provider.JwtTestUtils.createJWTBody;
import static com.auth0.android.provider.JwtTestUtils.createTestJWT;
import static com.auth0.android.provider.JwtTestUtils.getPublicKey;

@RunWith(RobolectricTestRunner.class)
public class AsymmetricSignatureVerifierTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

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
    public void shouldThrowWhenSignatureIsInvalid() throws Exception {
        exception.expect(TokenValidationException.class);
        exception.expectMessage("Invalid ID token signature.");

        PublicKey publicKey = getPublicKey();
        AsymmetricSignatureVerifier verifier = new AsymmetricSignatureVerifier(publicKey);

        String signedToken = createTestJWT("RS256", createJWTBody());
        //remove signature
        String[] parts = signedToken.split("\\.");
        signedToken = parts[0] + "." + parts[1] + ".unexpected-signature";

        verifier.verify(new Jwt(signedToken));
    }

    @Test
    public void shouldThrowWhenAlgorithmIsNotSupported() throws Exception {
        exception.expect(TokenValidationException.class);
        exception.expectMessage("Signature algorithm of \"none\" is not supported. Expected the ID token to be signed with RS256.");

        PublicKey publicKey = getPublicKey();
        AsymmetricSignatureVerifier verifier = new AsymmetricSignatureVerifier(publicKey);

        String noneToken = createTestJWT("none", createJWTBody());

        verifier.verify(new Jwt(noneToken));
    }

    @Test
    public void shouldThrowWhenAlgorithmIsSymmetric() throws Exception {
        exception.expect(TokenValidationException.class);
        exception.expectMessage("Signature algorithm of \"HS256\" is not supported. Expected the ID token to be signed with RS256.");

        PublicKey publicKey = getPublicKey();
        AsymmetricSignatureVerifier verifier = new AsymmetricSignatureVerifier(publicKey);

        String hsToken = createTestJWT("HS256", createJWTBody());

        verifier.verify(new Jwt(hsToken));
    }
}