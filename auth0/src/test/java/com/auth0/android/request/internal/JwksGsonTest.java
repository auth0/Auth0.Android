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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertTrue;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 21)
public class JwksGsonTest extends GsonBaseTest {
    private static final String VALID_RSA_JWKS = "src/test/resources/rsa_jwks.json";
    private static final String EXPECTED_KEY_ID = "key123";
    private static final String EXPECTED_RSA_EXPONENT = "65537";
    private static final String EXPECTED_RSA_MODULUS = "2327856100899355911632462598898247024131242" +
            "69568893466584055046785206443536944170967694954399904576260402148130300731927741648861" +
            "77036082957412916823253078715836599659671998742580694113788009114660385412566349874736" +
            "27869308481943996880794168096537223920950531497564162778062893250580915368070350845084" +
            "20860279004024750131874921675175697075713453754160892451823567877023128161490580261931" +
            "58312146038158019813447205810433184619008248223295213470806341823186239417071266118809" +
            "63334488448657815599232564013868981211014327205461460864291477265210472076542261630382" +
            "8138891725285516030216809064067106806135514473091101324387";

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
