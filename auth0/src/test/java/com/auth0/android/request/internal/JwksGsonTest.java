package com.auth0.android.request.internal;

import com.google.gson.JsonParseException;
import com.google.gson.reflect.TypeToken;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;

import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 21)
public class JwksGsonTest extends GsonBaseTest {
    private static final String VALID_RSA_JWKS = "src/test/resources/jwks_rsa.json";
    private static final String EXPECTED_KEY_ID = "RUVBOTVEMEZBMTA5NDAzNEQzNTZGNzMyMTI4MzU1RkNFQzhCQTM0Mg";
    private static final String EXPECTED_RSA_EXPONENT = "65537";
    private static final String EXPECTED_RSA_MODULUS = "2621148833618669851632627030508577941932991104442742159327628027691656119517675178227503934" +
            "50126026383571140309353586180428305357637026071474336890156009441229041656542271917477199336983077844706495725045832557637658494403826" +
            "343064304897328574182258821353161480771090757577522755330350956839942443917109665602066633259326057104246834759269337437620283600011255" +
            "336891753201992873507788546321379785324808697815139356191481700515096717744643081207558743005545844515461091232322385145532862505800570" +
            "17053908908888974416937916517307412534155165744508160026990874221314025481541880285443289277406354687335857437573080004037";

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Before
    public void setUp() {
        gson = GsonProvider.buildGson();
    }

    @Test
    public void shouldFailWithInvalidJson() throws Exception {
        expectedException.expect(JsonParseException.class);
        buildJwksFrom(json(INVALID));
    }

    @Test
    public void shouldFailWithEmptyJson() throws Exception {
        expectedException.expect(JsonParseException.class);
        buildJwksFrom(json(EMPTY_OBJECT));
    }

    @Test
    public void shouldReturnValid() throws Exception {
        Map<String, PublicKey> jwks = buildJwksFrom(json(VALID_RSA_JWKS));
        assertThat(jwks, is(notNullValue()));
        assertThat(jwks.size(), is(1));
        assertTrue(jwks.containsKey(EXPECTED_KEY_ID));
        PublicKey pub = jwks.get(EXPECTED_KEY_ID);
        assertThat(pub, instanceOf(RSAPublicKey.class));

        RSAPublicKey rsaPub = (RSAPublicKey) pub;
        assertThat(rsaPub.getPublicExponent(), is(new BigInteger(EXPECTED_RSA_EXPONENT)));
        assertThat(rsaPub.getModulus(), is(new BigInteger(EXPECTED_RSA_MODULUS)));
    }

    @Test
    public void shouldReturnEmptyWhenKeysAreEmpty() throws Exception {
        Map<String, PublicKey> jwks = buildJwksFrom(new StringReader("{\"keys\": []}"));
        assertThat(jwks, is(notNullValue()));
        assertTrue(jwks.isEmpty());
    }

    @Test
    public void shouldReturnEmptyWhenKeysAreFromDifferentAlgorithm() throws Exception {
        Map<String, PublicKey> jwks = buildJwksFrom(new StringReader("{\"keys\": [{\"alg\": \"RS512\", \"use\": \"sig\"}]}"));
        assertThat(jwks, is(notNullValue()));
        assertTrue(jwks.isEmpty());
    }

    @Test
    public void shouldReturnEmptyWhenKeysAreNotForSignatureChecking() throws Exception {
        Map<String, PublicKey> jwks = buildJwksFrom(new StringReader("{\"keys\": [{\"alg\": \"RS256\", \"use\": \"enc\"}]}"));
        assertThat(jwks, is(notNullValue()));
        assertTrue(jwks.isEmpty());
    }

    @Test
    public void shouldReturnEmptyWhenKeysCannotBeCreatedBecauseOfNotSupportedKeyType() throws Exception {
        Map<String, PublicKey> jwks = buildJwksFrom(new StringReader("{\"keys\": [{\"alg\": \"RS256\", \"use\": \"sig\", \"kty\": \"INVALID_VALUE\"}]}"));
        assertThat(jwks, is(notNullValue()));
        assertTrue(jwks.isEmpty());
    }

    private Map<String, PublicKey> buildJwksFrom(Reader json) throws IOException {
        TypeToken<Map<String, PublicKey>> jwksType = new TypeToken<Map<String, PublicKey>>() {
        };
        return pojoFrom(json, jwksType);
    }

}
