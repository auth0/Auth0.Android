package com.auth0.android.authentication;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.util.Base64;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.hamcrest.core.IsInstanceOf;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Calendar;
import java.util.Date;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;

@RunWith(RobolectricTestRunner.class)
@Config(constants = com.auth0.android.auth0.BuildConfig.class, sdk = 21, manifest = Config.NONE)
public class JwtVerifierTest {

    private static final String EXPECTED_ISSUER = "https://samples.auth0.com/";
    private static final String EXPECTED_AUDIENCE = "CLIENTID";

    @Rule
    public ExpectedException exception = ExpectedException.none();
    @Mock
    private KeyProvider keyProvider;
    private JwtVerifier verifier;
    private Date futureDate;
    private Date pastDate;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        verifier = new JwtVerifier(keyProvider);

        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DATE, 10);
        futureDate = calendar.getTime();
        calendar.add(Calendar.DATE, -20);
        pastDate = calendar.getTime();
    }

    @Test
    public void shouldCreateInstance() {
        JwtVerifier jwtVerifier = new JwtVerifier(keyProvider);
        assertThat(jwtVerifier, is(notNullValue()));
    }

    @Test
    public void shouldFailVerificationIfTokenIsNotSigned() {
        exception.expect(TokenVerificationException.class);
        exception.expectMessage("The token is not signed");
        verifier.verify("header.payload.");
    }

    @Test
    public void shouldFailVerificationIfTokenDoesNotHaveThreeParts() {
        exception.expect(TokenVerificationException.class);
        exception.expectMessage("The token is not signed");
        verifier.verify("header.payload");
    }

    @Test
    public void shouldNotSkipVerificationIfTokenIsSignedWithHS256() {
        exception.expect(TokenVerificationException.class);
        exception.expectMessage("The token must be signed using the RS256 algorithm");
        verifier.verify("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImFiYzEyMyJ9.eyJpc3MiOiJodHRwczovL3NhbXBsZXMuYXV0aDAuY29tLyIsImF1ZCI6IkNMSUVOVElEIn0.x-xM2TdAFzrdQ-n-Rc_lLyP0AIrY0VWuWQoD8bQF1LE");
    }

    @Test
    public void shouldVerifyRS256Token() throws Exception {
        when(keyProvider.getPublicKey("my-key-id")).thenReturn(readPublicKeyFromString(RS256_PUBLIC_KEY));
        verifier.setExpectedValues(EXPECTED_ISSUER, EXPECTED_AUDIENCE);
        String validJwt = createRSToken(true, true, futureDate, pastDate);
        verifier.verify(validJwt);
    }

    @Test
    public void shouldFailVerificationWhenSignatureIsInvalid() throws Exception {
        exception.expect(TokenVerificationException.class);
        exception.expectMessage(startsWith("Could not verify the token's signature"));
        String wrongSignatureToken = createRSToken(true, true, futureDate, pastDate).concat("123456");
        when(keyProvider.getPublicKey("my-key-id")).thenReturn(readPublicKeyFromString(RS256_PUBLIC_KEY));
        verifier.verify(wrongSignatureToken);
    }

    @Test
    public void shouldFailVerificationWhenTokenCannotBeUsedYet() throws Exception {
        exception.expect(TokenVerificationException.class);
        exception.expectMessage(startsWith("The token cannot be used before"));
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.MINUTE, 1);
        Date momentsFromNow = calendar.getTime();
        String nonUsableToken = createRSToken(true, true, futureDate, momentsFromNow);
        when(keyProvider.getPublicKey("my-key-id")).thenReturn(readPublicKeyFromString(RS256_PUBLIC_KEY));
        verifier.verify(nonUsableToken);
    }

    @Test
    public void shouldFailVerificationWhenTokenIsExpired() throws Exception {
        exception.expect(TokenVerificationException.class);
        exception.expectMessage("The token is either missing the 'exp' (expires in) claim or has already expired");
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.MINUTE, -1);
        Date momentsAgo = calendar.getTime();
        String expiredToken = createRSToken(true, true, momentsAgo, pastDate);
        when(keyProvider.getPublicKey("my-key-id")).thenReturn(readPublicKeyFromString(RS256_PUBLIC_KEY));
        verifier.verify(expiredToken);
    }

    @Test
    public void shouldFailVerificationWhenIssuerDoesNotMatch() throws Exception {
        exception.expect(TokenVerificationException.class);
        exception.expectMessage("The token is either missing the 'iss' (issuer) claim or has an invalid value");
        when(keyProvider.getPublicKey("my-key-id")).thenReturn(readPublicKeyFromString(RS256_PUBLIC_KEY));
        verifier.setExpectedValues("https://company.auth10.com/", EXPECTED_AUDIENCE);
        String validJwt = createRSToken(true, true, futureDate, pastDate);
        verifier.verify(validJwt);
    }

    @Test
    public void shouldFailVerificationWhenAudienceDoesNotMatch() throws Exception {
        exception.expect(TokenVerificationException.class);
        exception.expectMessage("The token is either missing the 'aud' (audience) claim or has an invalid value");
        when(keyProvider.getPublicKey("my-key-id")).thenReturn(readPublicKeyFromString(RS256_PUBLIC_KEY));
        verifier.setExpectedValues(EXPECTED_ISSUER, "COMPANYID");
        String validJwt = createRSToken(true, true, futureDate, pastDate);
        verifier.verify(validJwt);
    }

    @Test
    public void shouldFailVerificationWhenExpectedAudienceAndIssuerValuesAreNotGiven() throws Exception {
        exception.expect(TokenVerificationException.class);
        when(keyProvider.getPublicKey("my-key-id")).thenReturn(readPublicKeyFromString(RS256_PUBLIC_KEY));
        String validJwt = createRSToken(true, true, futureDate, pastDate);
        verifier.verify(validJwt);
    }

    @Test
    public void shouldFailVerificationWhenExpiresInIsNotPresent() throws Exception {
        exception.expect(TokenVerificationException.class);
        exception.expectMessage("The token is either missing the 'exp' (expires in) claim or has already expired");
        when(keyProvider.getPublicKey("my-key-id")).thenReturn(readPublicKeyFromString(RS256_PUBLIC_KEY));
        String validJwt = createRSToken(false, true, null, pastDate);
        verifier.verify(validJwt);
    }

    @Test
    public void shouldFailVerificationWhenIssuerIsNotPresent() throws Exception {
        exception.expect(TokenVerificationException.class);
        exception.expectMessage("The token is either missing the 'iss' (issuer) claim or has an invalid value");
        when(keyProvider.getPublicKey("my-key-id")).thenReturn(readPublicKeyFromString(RS256_PUBLIC_KEY));
        String validJwt = createRSToken(false, true, futureDate, pastDate);
        verifier.verify(validJwt);
    }

    @Test
    public void shouldFailVerificationWhenAudienceIsNotPresent() throws Exception {
        exception.expect(TokenVerificationException.class);
        exception.expectMessage("The token is either missing the 'iss' (issuer) claim or has an invalid value");
        when(keyProvider.getPublicKey("my-key-id")).thenReturn(readPublicKeyFromString(RS256_PUBLIC_KEY));
        String validJwt = createRSToken(true, false, futureDate, pastDate);
        verifier.verify(validJwt);
    }

    @Test
    public void shouldFailWhenPublicKeyCannotBeObtained() throws Exception {
        exception.expect(TokenVerificationException.class);
        exception.expectCause(IsInstanceOf.<Throwable>instanceOf(KeyProviderException.class));
        exception.expectMessage("Could not verify the token's signature");
        doThrow(KeyProviderException.class).when(keyProvider).getPublicKey("my-key-id");
        String validJwt = createRSToken(true, true, futureDate, pastDate);
        verifier.verify(validJwt);
    }


    // Crypto Helpers
    private static final String RS256_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\n" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuGbXWiK3dQTyCbX5xdE4\n" +
            "yCuYp0AF2d15Qq1JSXT/lx8CEcXb9RbDddl8jGDv+spi5qPa8qEHiK7FwV2KpRE9\n" +
            "83wGPnYsAm9BxLFb4YrLYcDFOIGULuk2FtrPS512Qea1bXASuvYXEpQNpGbnTGVs\n" +
            "WXI9C+yjHztqyL2h8P6mlThPY9E9ue2fCqdgixfTFIF9Dm4SLHbphUS2iw7w1JgT\n" +
            "69s7of9+I9l5lsJ9cozf1rxrXX4V1u/SotUuNB3Fp8oB4C1fLBEhSlMcUJirz1E8\n" +
            "AziMCxS+VrRPDM+zfvpIJg3JljAh3PJHDiLu902v9w+Iplu1WyoB2aPfitxEhRN0\n" +
            "YwIDAQAB\n" +
            "-----END PUBLIC KEY-----";

    private static final String RS256_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\n" +
            "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC4ZtdaIrd1BPIJ\n" +
            "tfnF0TjIK5inQAXZ3XlCrUlJdP+XHwIRxdv1FsN12XyMYO/6ymLmo9ryoQeIrsXB\n" +
            "XYqlET3zfAY+diwCb0HEsVvhisthwMU4gZQu6TYW2s9LnXZB5rVtcBK69hcSlA2k\n" +
            "ZudMZWxZcj0L7KMfO2rIvaHw/qaVOE9j0T257Z8Kp2CLF9MUgX0ObhIsdumFRLaL\n" +
            "DvDUmBPr2zuh/34j2XmWwn1yjN/WvGtdfhXW79Ki1S40HcWnygHgLV8sESFKUxxQ\n" +
            "mKvPUTwDOIwLFL5WtE8Mz7N++kgmDcmWMCHc8kcOIu73Ta/3D4imW7VbKgHZo9+K\n" +
            "3ESFE3RjAgMBAAECggEBAJTEIyjMqUT24G2FKiS1TiHvShBkTlQdoR5xvpZMlYbN\n" +
            "tVWxUmrAGqCQ/TIjYnfpnzCDMLhdwT48Ab6mQJw69MfiXwc1PvwX1e9hRscGul36\n" +
            "ryGPKIVQEBsQG/zc4/L2tZe8ut+qeaK7XuYrPp8bk/X1e9qK5m7j+JpKosNSLgJj\n" +
            "NIbYsBkG2Mlq671irKYj2hVZeaBQmWmZxK4fw0Istz2WfN5nUKUeJhTwpR+JLUg4\n" +
            "ELYYoB7EO0Cej9UBG30hbgu4RyXA+VbptJ+H042K5QJROUbtnLWuuWosZ5ATldwO\n" +
            "u03dIXL0SH0ao5NcWBzxU4F2sBXZRGP2x/jiSLHcqoECgYEA4qD7mXQpu1b8XO8U\n" +
            "6abpKloJCatSAHzjgdR2eRDRx5PMvloipfwqA77pnbjTUFajqWQgOXsDTCjcdQui\n" +
            "wf5XAaWu+TeAVTytLQbSiTsBhrnoqVrr3RoyDQmdnwHT8aCMouOgcC5thP9vQ8Us\n" +
            "rVdjvRRbnJpg3BeSNimH+u9AHgsCgYEA0EzcbOltCWPHRAY7B3Ge/AKBjBQr86Kv\n" +
            "TdpTlxePBDVIlH+BM6oct2gaSZZoHbqPjbq5v7yf0fKVcXE4bSVgqfDJ/sZQu9Lp\n" +
            "PTeV7wkk0OsAMKk7QukEpPno5q6tOTNnFecpUhVLLlqbfqkB2baYYwLJR3IRzboJ\n" +
            "FQbLY93E8gkCgYB+zlC5VlQbbNqcLXJoImqItgQkkuW5PCgYdwcrSov2ve5r/Acz\n" +
            "FNt1aRdSlx4176R3nXyibQA1Vw+ztiUFowiP9WLoM3PtPZwwe4bGHmwGNHPIfwVG\n" +
            "m+exf9XgKKespYbLhc45tuC08DATnXoYK7O1EnUINSFJRS8cezSI5eHcbQKBgQDC\n" +
            "PgqHXZ2aVftqCc1eAaxaIRQhRmY+CgUjumaczRFGwVFveP9I6Gdi+Kca3DE3F9Pq\n" +
            "PKgejo0SwP5vDT+rOGHN14bmGJUMsX9i4MTmZUZ5s8s3lXh3ysfT+GAhTd6nKrIE\n" +
            "kM3Nh6HWFhROptfc6BNusRh1kX/cspDplK5x8EpJ0QKBgQDWFg6S2je0KtbV5PYe\n" +
            "RultUEe2C0jYMDQx+JYxbPmtcopvZQrFEur3WKVuLy5UAy7EBvwMnZwIG7OOohJb\n" +
            "vkSpADK6VPn9lbqq7O8cTedEHttm6otmLt8ZyEl3hZMaL3hbuRj6ysjmoFKx6CrX\n" +
            "rK0/Ikt5ybqUzKCMJZg2VKGTxg==\n" +
            "-----END PRIVATE KEY-----`";

    private String createRSToken(boolean hasIssuer, boolean hasAudience, @Nullable Date expiresAt, @NonNull Date notBefore) throws Exception {
        String header = "{\"alg\": \"RS256\", \"kid\": \"my-key-id\"}";
        StringBuilder payloadBuilder = new StringBuilder("{");
        if (hasIssuer) {
            payloadBuilder.append("\"iss\": \"").append(EXPECTED_ISSUER).append("\",");
        }
        if (hasAudience) {
            payloadBuilder.append("\"aud\": \"").append(EXPECTED_AUDIENCE).append("\",");
        }
        if (expiresAt!=null){
            long expSeconds = expiresAt.getTime() / 1000;
            payloadBuilder.append("\"exp\": ").append(expSeconds).append(",");
        }
        long nbfSeconds = notBefore.getTime() / 1000;
        payloadBuilder.append("\"nbf\": ").append(nbfSeconds).append("}");
        String payload = payloadBuilder.toString();
        PrivateKey privateKey = readPrivateKeyFromString(RS256_PRIVATE_KEY);
        String content = String.format("%s.%s", base64Encode(header.getBytes(StandardCharsets.UTF_8)), base64Encode(payload.getBytes(StandardCharsets.UTF_8)));
        byte[] signatureBytes = createSignature(privateKey, content.getBytes(StandardCharsets.UTF_8));
        String signature = base64Encode(signatureBytes);
        return String.format("%s.%s", content, signature);
    }

    private static PublicKey readPublicKeyFromString(String input) throws IOException {
        byte[] bytes = parsePEMKey(input);
        return getPublicKey(bytes);
    }

    public static PrivateKey readPrivateKeyFromString(String input) throws IOException {
        byte[] bytes = parsePEMKey(input);
        return getPrivateKey(bytes);
    }

    private static byte[] parsePEMKey(String input) throws IOException {
        PemReader reader = new PemReader(new StringReader(input));
        PemObject pemObject = reader.readPemObject();
        byte[] content = pemObject.getContent();
        reader.close();
        return content;
    }

    private static PublicKey getPublicKey(byte[] keyBytes) {
        PublicKey publicKey = null;
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            publicKey = kf.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Could not reconstruct the public key, the given algorithm could not be found.");
        } catch (InvalidKeySpecException e) {
            System.out.println("Could not reconstruct the public key");
        }

        return publicKey;
    }

    private static PrivateKey getPrivateKey(byte[] keyBytes) {
        PrivateKey privateKey = null;
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            privateKey = kf.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Could not reconstruct the private key, the given algorithm could not be found.");
        } catch (InvalidKeySpecException e) {
            System.out.println("Could not reconstruct the private key");
        }

        return privateKey;
    }

    private String base64Encode(byte[] input) {
        return Base64.encodeToString(input, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
    }

    private byte[] createSignature(PrivateKey key, byte[] contentBytes) throws Exception {
        final Signature s = Signature.getInstance("SHA256withRSA");
        s.initSign(key);
        s.update(contentBytes);
        return s.sign();
    }
}