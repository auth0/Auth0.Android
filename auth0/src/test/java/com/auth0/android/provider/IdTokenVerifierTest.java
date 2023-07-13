package com.auth0.android.provider;

import com.auth0.android.request.internal.Jwt;

import org.hamcrest.MatcherAssert;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.robolectric.RobolectricTestRunner;

import java.security.PublicKey;
import java.util.Date;
import java.util.Map;

import static com.auth0.android.provider.JwtTestUtils.EXPECTED_AUDIENCE;
import static com.auth0.android.provider.JwtTestUtils.EXPECTED_AUDIENCE_ARRAY;
import static com.auth0.android.provider.JwtTestUtils.EXPECTED_ISSUER;
import static com.auth0.android.provider.JwtTestUtils.EXPECTED_NONCE;
import static com.auth0.android.provider.JwtTestUtils.EXPECTED_ORGANIZATION_ID;
import static com.auth0.android.provider.JwtTestUtils.EXPECTED_ORGANIZATION_NAME;
import static com.auth0.android.provider.JwtTestUtils.FIXED_CLOCK_CURRENT_TIME_MS;
import static com.auth0.android.provider.JwtTestUtils.createJWTBody;
import static com.auth0.android.provider.JwtTestUtils.createTestJWT;
import static com.auth0.android.provider.JwtTestUtils.getPublicKey;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@RunWith(RobolectricTestRunner.class)
public class IdTokenVerifierTest {


    private IdTokenVerifier idTokenVerifier;
    private IdTokenVerificationOptions options;

    @Mock
    private SignatureVerifier noSignatureVerifier;

    @Before
    public void setUp() {
        idTokenVerifier = new IdTokenVerifier();
        noSignatureVerifier = mock(SignatureVerifier.class);
        options = new IdTokenVerificationOptions(EXPECTED_ISSUER, EXPECTED_AUDIENCE, noSignatureVerifier);
        options.setClock(new Date(FIXED_CLOCK_CURRENT_TIME_MS));
    }

    @Test
    public void shouldPassAllClaimsVerificationWithOrgId() throws Exception {
        long clock = FIXED_CLOCK_CURRENT_TIME_MS / 1000;
        long authTime = clock - 1;

        Map<String, Object> jwtBody = createJWTBody();
        //Overrides
        jwtBody.put("aud", EXPECTED_AUDIENCE_ARRAY);
        jwtBody.put("azp", EXPECTED_AUDIENCE);
        jwtBody.put("auth_time", authTime);
        jwtBody.put("nonce", EXPECTED_NONCE);
        jwtBody.put("org_id", EXPECTED_ORGANIZATION_ID);

        String token = createTestJWT("none", jwtBody);
        Jwt jwt = new Jwt(token);
        options.setNonce(EXPECTED_NONCE);
        options.setOrganization(EXPECTED_ORGANIZATION_ID);
        options.setMaxAge(60 * 2);
        idTokenVerifier.verify(jwt, options, true);
    }

    @Test
    public void shouldPassAllClaimsVerificationWithOrgName() throws Exception {
        long clock = FIXED_CLOCK_CURRENT_TIME_MS / 1000;
        long authTime = clock - 1;

        Map<String, Object> jwtBody = createJWTBody();
        //Overrides
        jwtBody.put("aud", EXPECTED_AUDIENCE_ARRAY);
        jwtBody.put("azp", EXPECTED_AUDIENCE);
        jwtBody.put("auth_time", authTime);
        jwtBody.put("nonce", EXPECTED_NONCE);
        jwtBody.put("org_name", EXPECTED_ORGANIZATION_NAME);

        String token = createTestJWT("none", jwtBody);
        Jwt jwt = new Jwt(token);
        options.setNonce(EXPECTED_NONCE);
        options.setOrganization(EXPECTED_ORGANIZATION_NAME);
        options.setMaxAge(60 * 2);
        idTokenVerifier.verify(jwt, options, true);
    }

    @Test
    public void shouldFailWhenSignatureIsInvalid() throws Exception {
        PublicKey pk = getPublicKey();
        SignatureVerifier signatureVerifier = new AsymmetricSignatureVerifier(pk);
        IdTokenVerificationOptions options = new IdTokenVerificationOptions(EXPECTED_ISSUER, EXPECTED_AUDIENCE, signatureVerifier);
        String message = "Invalid ID token signature.";
        Exception e = Assert.assertThrows(message, InvalidIdTokenSignatureException.class, () -> {
            String token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UifQ.FL7foy7kV9SVoC6GLEqwatuYz39BWoEUpZ9sv00zg2oJneJFkwPYYBCj92xu0Fry7zqLRkhFeveUKtSgZV6AinDvdWWH9Is8ku3l871ut-ECiR8-Co7qdIbQet3IhiLggHko4Z9Ez7F-pWmppV7BRJmYdFjbrurLfgN191VE9xC8AmnzSIPTFczg9g_aycqhea4ncd9YjiGV2QlmNB4q1aCZ3V7QyO4KwJnnLeI4tykXjNRVXfPuInaE_f0TpzpRbzJelAGhL5cmO_b0kJswCEqonYMvsVdGqM9jxWMebs7L2k2s2nZ3MQNo-gVIv3E2GfaBpCgGxO-8kyh8sBal3A";
            String[] parts = token.split("\\.");
            token = parts[0] + "." + parts[1] + ".no-signature";
            Jwt jwt = new Jwt(token);
            idTokenVerifier.verify(jwt, options, true);
        });
        assertEquals("com.auth0.android.provider.TokenValidationException: " + message, e.toString());
        assertEquals(message, e.getMessage());
    }

    @Test
    public void shouldFailWhenIssuerClaimIsMissing() {
        String message = "Issuer (iss) claim must be a string present in the ID token";
        Exception e = Assert.assertThrows(message, IssClaimMissingException.class, () -> {
            Map<String, Object> jwtBody = createJWTBody("iss");
            String token = createTestJWT("none", jwtBody);
            Jwt jwt = new Jwt(token);
            idTokenVerifier.verify(jwt, options, true);
        });
        assertEquals("com.auth0.android.provider.TokenValidationException: " + message, e.toString());
        assertEquals(message, e.getMessage());
    }

    @Test
    public void shouldFailWhenIssuerClaimHasUnexpectedValue() {
        String message = "Issuer (iss) claim mismatch in the ID token, expected \"https://test.domain.com/\", found \"--invalid--\"";
        Exception e = Assert.assertThrows(message, IssClaimMismatchException.class, () -> {
            Map<String, Object> jwtBody = createJWTBody();
            jwtBody.put("iss", "--invalid--");
            String token = createTestJWT("none", jwtBody);
            Jwt jwt = new Jwt(token);
            idTokenVerifier.verify(jwt, options, true);
        });
        assertEquals("com.auth0.android.provider.TokenValidationException: " + message, e.toString());
        assertEquals(message, e.getMessage());
    }

    @Test
    public void shouldFailWhenSubjectClaimIsMissing() {
        String message = "Subject (sub) claim must be a string present in the ID token";
        Exception e = Assert.assertThrows(message, SubClaimMissingException.class, () -> {
            Map<String, Object> jwtBody = createJWTBody("sub");
            String token = createTestJWT("none", jwtBody);
            Jwt jwt = new Jwt(token);
            idTokenVerifier.verify(jwt, options, true);
        });
        assertEquals("com.auth0.android.provider.TokenValidationException: " + message, e.toString());
        assertEquals(message, e.getMessage());
    }

    @Test
    public void shouldFailWhenAudienceClaimIsMissing() {
        String message = "Audience (aud) claim must be a string or array of strings present in the ID token";
        Exception e = Assert.assertThrows(message, AudClaimMissingException.class, () -> {
            Map<String, Object> jwtBody = createJWTBody("aud");
            String token = createTestJWT("none", jwtBody);
            Jwt jwt = new Jwt(token);
            idTokenVerifier.verify(jwt, options, true);
        });
        assertEquals("com.auth0.android.provider.TokenValidationException: " + message, e.toString());
        assertEquals(message, e.getMessage());
    }

    @Test
    public void shouldFailWhenAudienceClaimHasUnexpectedValue() {
        String message = "Audience (aud) claim mismatch in the ID token; expected \"__test_client_id__\" but was not one of \"[--invalid--]\"";
        Exception e = Assert.assertThrows(message, AudClaimMismatchException.class, () -> {
            Map<String, Object> jwtBody = createJWTBody();
            jwtBody.put("aud", "--invalid--");
            String token = createTestJWT("none", jwtBody);
            Jwt jwt = new Jwt(token);
            idTokenVerifier.verify(jwt, options, true);
        });
        assertEquals("com.auth0.android.provider.TokenValidationException: " + message, e.toString());
        assertEquals(message, e.getMessage());
    }

    @Test
    public void shouldFailWhenAudienceClaimArrayDoesNotContainExpectedValue() {
        String message = "Audience (aud) claim mismatch in the ID token; expected \"__test_client_id__\" but was not one of \"[--invalid-1--, --invalid-2--]\"";
        Exception e = Assert.assertThrows(message, AudClaimMismatchException.class, () -> {
            Map<String, Object> jwtBody = createJWTBody();
            jwtBody.put("aud", new String[]{"--invalid-1--", "--invalid-2--"});
            String token = createTestJWT("none", jwtBody);
            Jwt jwt = new Jwt(token);
            idTokenVerifier.verify(jwt, options, true);
        });
        assertEquals("com.auth0.android.provider.TokenValidationException: " + message, e.toString());
        assertEquals(message, e.getMessage());
    }

    @Test
    public void shouldFailWhenAudienceClaimIsMultipleElementsArrayAndAuthorizedPartyClaimIsMissing() {
        String message = "Authorized Party (azp) claim must be a string present in the ID token when Audience (aud) claim has multiple values";
        Exception e = Assert.assertThrows(AzpClaimMissingException.class, () -> {
            Map<String, Object> jwtBody = createJWTBody();
            jwtBody.put("aud", EXPECTED_AUDIENCE_ARRAY);
            String token = createTestJWT("none", jwtBody);
            Jwt jwt = new Jwt(token);
            idTokenVerifier.verify(jwt, options, true);
        });
        assertEquals("com.auth0.android.provider.TokenValidationException: " + message, e.toString());
        assertEquals(message, e.getMessage());
    }

    @Test
    public void shouldFailWhenAudienceClaimIsMultipleElementsArrayAndAuthorizedPartyClaimHasUnexpectedValue() {
        String message = "Authorized Party (azp) claim mismatch in the ID token; expected \"__test_client_id__\", found \"--invalid--\"";
        Exception e = Assert.assertThrows(message, AzpClaimMismatchException.class, () -> {
            Map<String, Object> jwtBody = createJWTBody();
            jwtBody.put("aud", EXPECTED_AUDIENCE_ARRAY);
            jwtBody.put("azp", "--invalid--");
            String token = createTestJWT("none", jwtBody);
            Jwt jwt = new Jwt(token);
            idTokenVerifier.verify(jwt, options, true);
        });
        assertEquals("com.auth0.android.provider.TokenValidationException: " + message, e.toString());
        assertEquals(message, e.getMessage());
    }

    @Test
    public void shouldNotFailWhenNonceClaimIsMissingButNotRequired() throws Exception {
        Map<String, Object> jwtBody = createJWTBody("nonce");
        String token = createTestJWT("none", jwtBody);
        Jwt jwt = new Jwt(token);
        idTokenVerifier.verify(jwt, options, true);
    }

    @Test
    public void shouldFailWhenNonceClaimIsMissingAndRequired() {
        String message = "Nonce (nonce) claim must be a string present in the ID token";
        Exception e = Assert.assertThrows(message, NonceClaimMissingException.class, () -> {
            Map<String, Object> jwtBody = createJWTBody("nonce");
            String token = createTestJWT("none", jwtBody);
            Jwt jwt = new Jwt(token);
            options.setNonce(EXPECTED_NONCE);
            idTokenVerifier.verify(jwt, options, true);
        });
        assertEquals("com.auth0.android.provider.TokenValidationException: " + message, e.toString());
        assertEquals(message, e.getMessage());
    }

    @Test
    public void shouldFailWhenNonceClaimIsRequiredAndHasUnexpectedValue() {
        String message = "Nonce (nonce) claim mismatch in the ID token; expected \"__test_nonce__\", found \"--invalid--\"";
        Exception e = Assert.assertThrows(message, NonceClaimMismatchException.class, () -> {
            Map<String, Object> jwtBody = createJWTBody();
            jwtBody.put("nonce", "--invalid--");
            String token = createTestJWT("none", jwtBody);
            Jwt jwt = new Jwt(token);
            options.setNonce(EXPECTED_NONCE);
            idTokenVerifier.verify(jwt, options, true);
        });
        assertEquals("com.auth0.android.provider.TokenValidationException: " + message, e.toString());
        assertEquals(message, e.getMessage());
    }

    @Test
    public void shouldNotFailWhenOrganizationNameClaimIsMissingButNotRequired() throws Exception {
        Map<String, Object> jwtBody = createJWTBody("org_name");
        String token = createTestJWT("none", jwtBody);
        Jwt jwt = new Jwt(token);
        idTokenVerifier.verify(jwt, options, true);
    }

    @Test
    public void shouldFailWhenOrganizationNameClaimIsMissingAndRequired() {
        String message = "Organization Name (org_name) claim must be a string present in the ID token";
        Exception e = Assert.assertThrows(message, OrgNameClaimMissingException.class, () -> {
            Map<String, Object> jwtBody = createJWTBody("org_name");
            String token = createTestJWT("none", jwtBody);
            Jwt jwt = new Jwt(token);
            options.setOrganization(EXPECTED_ORGANIZATION_NAME);
            idTokenVerifier.verify(jwt, options, true);
        });
        assertEquals("com.auth0.android.provider.TokenValidationException: " + message, e.toString());
        assertEquals(message, e.getMessage());
    }

    @Test
    public void shouldFailWhenOrganizationNameClaimIsRequiredAndHasUnexpectedValue() {
        String message = "Organization Name (org_name) claim mismatch in the ID token; expected \"org___test_org_name__\", found \"--invalid--\"";
        Exception e = Assert.assertThrows(message, OrgNameClaimMismatchException.class, () -> {
            Map<String, Object> jwtBody = createJWTBody();
            jwtBody.put("org_name", "--invalid--");
            String token = createTestJWT("none", jwtBody);
            Jwt jwt = new Jwt(token);
            options.setOrganization(EXPECTED_ORGANIZATION_NAME);
            idTokenVerifier.verify(jwt, options, true);
        });
        assertEquals("com.auth0.android.provider.TokenValidationException: " + message, e.toString());
        assertEquals(message, e.getMessage());
    }

    @Test
    public void shouldNotFailWhenOrganizationIdClaimIsMissingButNotRequired() throws Exception {
        Map<String, Object> jwtBody = createJWTBody("org_id");
        String token = createTestJWT("none", jwtBody);
        Jwt jwt = new Jwt(token);
        idTokenVerifier.verify(jwt, options, true);
    }

    @Test
    public void shouldFailWhenOrganizationIdClaimIsMissingAndRequired() {
        String message = "Organization Id (org_id) claim must be a string present in the ID token";
        Exception e = Assert.assertThrows(message, OrgClaimMissingException.class, () -> {
            Map<String, Object> jwtBody = createJWTBody("org_id");
            String token = createTestJWT("none", jwtBody);
            Jwt jwt = new Jwt(token);
            options.setOrganization(EXPECTED_ORGANIZATION_ID);
            idTokenVerifier.verify(jwt, options, true);
        });
        assertEquals("com.auth0.android.provider.TokenValidationException: " + message, e.toString());
        assertEquals(message, e.getMessage());
    }

    @Test
    public void shouldFailWhenOrganizationIdClaimIsRequiredAndHasUnexpectedValue() {
        String message = "Organization Id (org_id) claim mismatch in the ID token; expected \"__test_org_id__\", found \"--invalid--\"";
        Exception e = Assert.assertThrows(message, OrgClaimMismatchException.class, () -> {
            Map<String, Object> jwtBody = createJWTBody();
            jwtBody.put("org_id", "--invalid--");
            String token = createTestJWT("none", jwtBody);
            Jwt jwt = new Jwt(token);
            options.setOrganization(EXPECTED_ORGANIZATION_ID);
            idTokenVerifier.verify(jwt, options, true);
        });
        assertEquals("com.auth0.android.provider.TokenValidationException: " + message, e.toString());
        assertEquals(message, e.getMessage());
    }

    @Test
    public void shouldFailWhenExpiresAtClaimIsMissing() {
        String message = "Expiration Time (exp) claim must be a number present in the ID token";
        Exception e = Assert.assertThrows(message, ExpClaimMissingException.class, () -> {
            Map<String, Object> jwtBody = createJWTBody("exp");
            String token = createTestJWT("none", jwtBody);
            Jwt jwt = new Jwt(token);
            idTokenVerifier.verify(jwt, options, true);
        });
        assertEquals("com.auth0.android.provider.TokenValidationException: " + message, e.toString());
        assertEquals(message, e.getMessage());
    }

    @Test
    public void shouldFailWhenExpiresAtClaimHasUnexpectedValue() {
        String message = "Expiration Time (exp) claim error in the ID token; current time (1567314000) is after expiration time (1567313940)";
        Exception e = Assert.assertThrows(message, IdTokenExpiredException.class, () -> {
            Map<String, Object> jwtBody = createJWTBody();
            long clock = FIXED_CLOCK_CURRENT_TIME_MS / 1000;
            long pastExp = clock - 2 * 60; // 2 min
            jwtBody.put("exp", pastExp);
            String token = createTestJWT("none", jwtBody);
            Jwt jwt = new Jwt(token);
            idTokenVerifier.verify(jwt, options, true);
        });
        assertEquals("com.auth0.android.provider.TokenValidationException: " + message, e.toString());
        assertEquals(message, e.getMessage());
    }

    @Test
    public void shouldFailWhenIssuedAtClaimIsMissing() {
        String message = "Issued At (iat) claim must be a number present in the ID token";
        Exception e = Assert.assertThrows(message, IatClaimMissingException.class, () -> {
            Map<String, Object> jwtBody = createJWTBody("iat");
            String token = createTestJWT("none", jwtBody);
            Jwt jwt = new Jwt(token);
            idTokenVerifier.verify(jwt, options, true);
        });
        assertEquals("com.auth0.android.provider.TokenValidationException: " + message, e.toString());
        assertEquals(message, e.getMessage());
    }

    @Test
    public void shouldFailWhenMaxAgeIsSetButAuthTimeClaimIsMissing() {
        String message = "Authentication Time (auth_time) claim must be a number present in the ID token when Max Age (max_age) is specified";
        Exception e = Assert.assertThrows(message, AuthTimeClaimMissingException.class, () -> {
            Map<String, Object> jwtBody = createJWTBody("auth_time");
            String token = createTestJWT("none", jwtBody);
            Jwt jwt = new Jwt(token);
            options.setMaxAge(60 * 2);
            idTokenVerifier.verify(jwt, options, true);
        });
        assertEquals("com.auth0.android.provider.TokenValidationException: " + message, e.toString());
        assertEquals(message, e.getMessage());
    }

    @Test
    public void shouldFailWhenMaxAgeIsSetAndAuthTimeClaimHasUnexpectedValue() {
        String message = "Authentication Time (auth_time) claim in the ID token indicates that too much time has passed since the last end-user authentication. Current time (1567314000) is after last auth at (1567310580)";
        Exception e = Assert.assertThrows(message, AuthTimeClaimMismatchException.class, () -> {
            Map<String, Object> jwtBody = createJWTBody();
            long clock = FIXED_CLOCK_CURRENT_TIME_MS / 1000;
            jwtBody.put("auth_time", clock - 3600);
            String token = createTestJWT("none", jwtBody);
            Jwt jwt = new Jwt(token);
            options.setMaxAge(2 * 60);
            idTokenVerifier.verify(jwt, options, true);
        });
        assertEquals("com.auth0.android.provider.TokenValidationException: " + message, e.toString());
        assertEquals(message, e.getMessage());
    }

    @Test
    public void shouldVerifySignatureIfTrueIsPassedInArgument() throws Exception {
        Map<String, Object> jwtBody = createJWTBody();
        String token = createTestJWT("none", jwtBody);
        Jwt jwt = new Jwt(token);
        idTokenVerifier.verify(jwt, options, true);
        verify(noSignatureVerifier, times(1)).verify(jwt);
    }

    @Test
    public void shouldNotVerifySignatureIfFalseIsPassedInArgument() throws Exception {
        Map<String, Object> jwtBody = createJWTBody();
        String token = createTestJWT("none", jwtBody);
        Jwt jwt = new Jwt(token);
        idTokenVerifier.verify(jwt, options, false);
        verify(noSignatureVerifier, times(0)).verify(jwt);
    }

    @Test
    public void shouldThrowExceptionIfSignatureVerifierIsNull() {
        String message = "Signature Verifier should not be null";
        Exception e = Assert.assertThrows(message, SignatureVerifierMissingException.class, () -> {
            idTokenVerifier = new IdTokenVerifier();
            options = new IdTokenVerificationOptions(EXPECTED_ISSUER, EXPECTED_AUDIENCE, null);
            Map<String, Object> jwtBody = createJWTBody();
            String token = createTestJWT("none", jwtBody);
            Jwt jwt = new Jwt(token);
            idTokenVerifier.verify(jwt, options, true);
        });
        assertEquals("com.auth0.android.provider.TokenValidationException: " + message, e.toString());
        assertEquals(message, e.getMessage());
    }
}