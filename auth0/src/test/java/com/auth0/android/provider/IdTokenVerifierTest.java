package com.auth0.android.provider;

import com.auth0.android.request.internal.Jwt;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;

import java.security.PublicKey;
import java.util.Date;
import java.util.Map;

import static com.auth0.android.provider.JwtTestUtils.EXPECTED_AUDIENCE;
import static com.auth0.android.provider.JwtTestUtils.EXPECTED_AUDIENCE_ARRAY;
import static com.auth0.android.provider.JwtTestUtils.EXPECTED_ISSUER;
import static com.auth0.android.provider.JwtTestUtils.EXPECTED_NONCE;
import static com.auth0.android.provider.JwtTestUtils.FIXED_CLOCK_CURRENT_TIME_MS;
import static com.auth0.android.provider.JwtTestUtils.createJWTBody;
import static com.auth0.android.provider.JwtTestUtils.createTestJWT;
import static com.auth0.android.provider.JwtTestUtils.getPublicKey;
import static org.mockito.Mockito.mock;

@RunWith(RobolectricTestRunner.class)
public class IdTokenVerifierTest {


    private IdTokenVerifier idTokenVerifier;
    private IdTokenVerificationOptions options;

    @Before
    public void setUp() {
        idTokenVerifier = new IdTokenVerifier();
        SignatureVerifier noSignatureVerifier = mock(SignatureVerifier.class);
        options = new IdTokenVerificationOptions(EXPECTED_ISSUER, EXPECTED_AUDIENCE, noSignatureVerifier);
        options.setClock(new Date(FIXED_CLOCK_CURRENT_TIME_MS));
    }

    @Test
    public void shouldPassAllClaimsVerification() throws Exception {
        long clock = FIXED_CLOCK_CURRENT_TIME_MS / 1000;
        long authTime = clock - 1;

        Map<String, Object> jwtBody = createJWTBody();
        //Overrides
        jwtBody.put("aud", EXPECTED_AUDIENCE_ARRAY);
        jwtBody.put("azp", EXPECTED_AUDIENCE);
        jwtBody.put("auth_time", authTime);
        jwtBody.put("nonce", EXPECTED_NONCE);

        String token = createTestJWT("none", jwtBody);
        Jwt jwt = new Jwt(token);
        options.setNonce(EXPECTED_NONCE);
        options.setMaxAge(60 * 2);
        idTokenVerifier.verify(jwt, options);
    }

    @Test
    public void shouldFailWhenSignatureIsInvalid() throws Exception {
        PublicKey pk = getPublicKey();
        SignatureVerifier signatureVerifier = new AsymmetricSignatureVerifier(pk);
        IdTokenVerificationOptions options = new IdTokenVerificationOptions(EXPECTED_ISSUER, EXPECTED_AUDIENCE, signatureVerifier);

        Assert.assertThrows("Invalid ID token signature.", TokenValidationException.class, () -> {
            String token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UifQ.FL7foy7kV9SVoC6GLEqwatuYz39BWoEUpZ9sv00zg2oJneJFkwPYYBCj92xu0Fry7zqLRkhFeveUKtSgZV6AinDvdWWH9Is8ku3l871ut-ECiR8-Co7qdIbQet3IhiLggHko4Z9Ez7F-pWmppV7BRJmYdFjbrurLfgN191VE9xC8AmnzSIPTFczg9g_aycqhea4ncd9YjiGV2QlmNB4q1aCZ3V7QyO4KwJnnLeI4tykXjNRVXfPuInaE_f0TpzpRbzJelAGhL5cmO_b0kJswCEqonYMvsVdGqM9jxWMebs7L2k2s2nZ3MQNo-gVIv3E2GfaBpCgGxO-8kyh8sBal3A";
            String[] parts = token.split("\\.");
            token = parts[0] + "." + parts[1] + ".no-signature";
            Jwt jwt = new Jwt(token);
            idTokenVerifier.verify(jwt, options);
        });
    }

    @Test
    public void shouldFailWhenIssuerClaimIsMissing() {
        Assert.assertThrows("Issuer (iss) claim must be a string present in the ID token", TokenValidationException.class, () -> {
            Map<String, Object> jwtBody = createJWTBody("iss");
            String token = createTestJWT("none", jwtBody);
            Jwt jwt = new Jwt(token);
            idTokenVerifier.verify(jwt, options);
        });
    }

    @Test
    public void shouldFailWhenIssuerClaimHasUnexpectedValue() {
        Assert.assertThrows("Issuer (iss) claim mismatch in the ID token, expected \"https://test.domain.com/\", found \"--invalid--\"", TokenValidationException.class, () -> {
            Map<String, Object> jwtBody = createJWTBody();
            jwtBody.put("iss", "--invalid--");
            String token = createTestJWT("none", jwtBody);
            Jwt jwt = new Jwt(token);
            idTokenVerifier.verify(jwt, options);
        });
    }

    @Test
    public void shouldFailWhenSubjectClaimIsMissing() {
        Assert.assertThrows("Subject (sub) claim must be a string present in the ID token", TokenValidationException.class, () -> {
            Map<String, Object> jwtBody = createJWTBody("sub");
            String token = createTestJWT("none", jwtBody);
            Jwt jwt = new Jwt(token);
            idTokenVerifier.verify(jwt, options);
        });
    }

    @Test
    public void shouldFailWhenAudienceClaimIsMissing() {
        Assert.assertThrows("Audience (aud) claim must be a string or array of strings present in the ID token", TokenValidationException.class, () -> {
            Map<String, Object> jwtBody = createJWTBody("aud");
            String token = createTestJWT("none", jwtBody);
            Jwt jwt = new Jwt(token);
            idTokenVerifier.verify(jwt, options);
        });
    }

    @Test
    public void shouldFailWhenAudienceClaimHasUnexpectedValue() {
        Assert.assertThrows("Audience (aud) claim mismatch in the ID token; expected \"__test_client_id__\" but was not one of \"[--invalid--]\"", TokenValidationException.class, () -> {
            Map<String, Object> jwtBody = createJWTBody();
            jwtBody.put("aud", "--invalid--");
            String token = createTestJWT("none", jwtBody);
            Jwt jwt = new Jwt(token);
            idTokenVerifier.verify(jwt, options);
        });
    }

    @Test
    public void shouldFailWhenAudienceClaimArrayDoesNotContainExpectedValue() {
        Assert.assertThrows("Audience (aud) claim mismatch in the ID token; expected \"__test_client_id__\" but was not one of \"[--invalid-1--, --invalid-2--]\"", TokenValidationException.class, () -> {
            Map<String, Object> jwtBody = createJWTBody();
            jwtBody.put("aud", new String[]{"--invalid-1--", "--invalid-2--"});
            String token = createTestJWT("none", jwtBody);
            Jwt jwt = new Jwt(token);
            idTokenVerifier.verify(jwt, options);
        });
    }

    @Test
    public void shouldFailWhenAudienceClaimIsMultipleElementsArrayAndAuthorizedPartyClaimIsMissing() {
        Assert.assertThrows("Authorized Party (azp) claim must be a string present in the ID token when Audience (aud) claim has multiple values", TokenValidationException.class, () -> {
            Map<String, Object> jwtBody = createJWTBody();
            jwtBody.put("aud", EXPECTED_AUDIENCE_ARRAY);
            String token = createTestJWT("none", jwtBody);
            Jwt jwt = new Jwt(token);
            idTokenVerifier.verify(jwt, options);
        });
    }

    @Test
    public void shouldFailWhenAudienceClaimIsMultipleElementsArrayAndAuthorizedPartyClaimHasUnexpectedValue() {
        Assert.assertThrows("Authorized Party (azp) claim mismatch in the ID token; expected \"__test_client_id__\", found \"--invalid--\"", TokenValidationException.class, () -> {
            Map<String, Object> jwtBody = createJWTBody();
            jwtBody.put("aud", EXPECTED_AUDIENCE_ARRAY);
            jwtBody.put("azp", "--invalid--");
            String token = createTestJWT("none", jwtBody);
            Jwt jwt = new Jwt(token);
            idTokenVerifier.verify(jwt, options);
        });
    }

    @Test
    public void shouldNotFailWhenNonceClaimIsMissingButNotRequired() throws Exception {
        Map<String, Object> jwtBody = createJWTBody("nonce");
        String token = createTestJWT("none", jwtBody);
        Jwt jwt = new Jwt(token);
        idTokenVerifier.verify(jwt, options);
    }

    @Test
    public void shouldFailWhenNonceClaimIsMissingAndRequired() {
        Assert.assertThrows("Nonce (nonce) claim must be a string present in the ID token", TokenValidationException.class, () -> {
            Map<String, Object> jwtBody = createJWTBody("nonce");
            String token = createTestJWT("none", jwtBody);
            Jwt jwt = new Jwt(token);
            options.setNonce(EXPECTED_NONCE);
            idTokenVerifier.verify(jwt, options);
        });
    }

    @Test
    public void shouldFailWhenNonceClaimIsRequiredAndHasUnexpectedValue() {
        Assert.assertThrows("Nonce (nonce) claim mismatch in the ID token; expected \"__test_nonce__\", found \"--invalid--\"", TokenValidationException.class, () -> {
            Map<String, Object> jwtBody = createJWTBody();
            jwtBody.put("nonce", "--invalid--");
            String token = createTestJWT("none", jwtBody);
            Jwt jwt = new Jwt(token);
            options.setNonce(EXPECTED_NONCE);
            idTokenVerifier.verify(jwt, options);
        });
    }

    @Test
    public void shouldFailWhenExpiresAtClaimIsMissing() {
        Assert.assertThrows("Expiration Time (exp) claim must be a number present in the ID token", TokenValidationException.class, () -> {
            Map<String, Object> jwtBody = createJWTBody("exp");
            String token = createTestJWT("none", jwtBody);
            Jwt jwt = new Jwt(token);
            idTokenVerifier.verify(jwt, options);
        });
    }

    @Test
    public void shouldFailWhenExpiresAtClaimHasUnexpectedValue() {
        Assert.assertThrows("Expiration Time (exp) claim error in the ID token; current time (1567314000) is after expiration time (1567313940)", TokenValidationException.class, () -> {
            Map<String, Object> jwtBody = createJWTBody();
            long clock = FIXED_CLOCK_CURRENT_TIME_MS / 1000;
            long pastExp = clock - 2 * 60; // 2 min
            jwtBody.put("exp", pastExp);
            String token = createTestJWT("none", jwtBody);
            Jwt jwt = new Jwt(token);
            idTokenVerifier.verify(jwt, options);
        });
    }

    @Test
    public void shouldFailWhenIssuedAtClaimIsMissing() {
        Assert.assertThrows("Issued At (iat) claim must be a number present in the ID token", TokenValidationException.class, () -> {
            Map<String, Object> jwtBody = createJWTBody("iat");
            String token = createTestJWT("none", jwtBody);
            Jwt jwt = new Jwt(token);
            idTokenVerifier.verify(jwt, options);
        });
    }

    @Test
    public void shouldFailWhenMaxAgeIsSetButAuthTimeClaimIsMissing() {
        Assert.assertThrows("Authentication Time (auth_time) claim must be a number present in the ID token when Max Age (max_age) is specified", TokenValidationException.class, () -> {
            Map<String, Object> jwtBody = createJWTBody("auth_time");
            String token = createTestJWT("none", jwtBody);
            Jwt jwt = new Jwt(token);
            options.setMaxAge(60 * 2);
            idTokenVerifier.verify(jwt, options);
        });
    }

    @Test
    public void shouldFailWhenMaxAgeIsSetAndAuthTimeClaimHasUnexpectedValue() {
        Assert.assertThrows("Authentication Time (auth_time) claim in the ID token indicates that too much time has passed since the last end-user authentication. Current time (1567314000) is after last auth at (1567310580)", TokenValidationException.class, () -> {
            Map<String, Object> jwtBody = createJWTBody();
            long clock = FIXED_CLOCK_CURRENT_TIME_MS / 1000;
            jwtBody.put("auth_time", clock - 3600);
            String token = createTestJWT("none", jwtBody);
            Jwt jwt = new Jwt(token);
            options.setMaxAge(2 * 60);
            idTokenVerifier.verify(jwt, options);
        });
    }

}