package com.auth0.android.request.internal

import com.google.gson.JsonParseException
import com.google.gson.reflect.TypeToken
import org.hamcrest.MatcherAssert
import org.hamcrest.Matchers
import org.junit.Assert
import org.junit.Before
import org.junit.Ignore
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.IOException
import java.io.Reader
import java.io.StringReader
import java.math.BigInteger
import java.security.PublicKey
import java.security.interfaces.RSAPublicKey

@Ignore
public class JwksGsonTest : GsonBaseTest() {
    @Before
    public fun setUp() {
        gson = GsonProvider.gson
    }

    @Test
    @Throws(Exception::class)
    public fun shouldFailWithInvalidJson() {
        Assert.assertThrows(JsonParseException::class.java) {
            buildJwksFrom(json(INVALID))
        }
    }

    @Test
    @Throws(Exception::class)
    public fun shouldFailWithEmptyJson() {
        Assert.assertThrows(JsonParseException::class.java) {
            buildJwksFrom(json(EMPTY_OBJECT))
        }
    }

    @Test
    @Throws(Exception::class)
    public fun shouldReturnValid() {
        val jwks = buildJwksFrom(json(VALID_RSA_JWKS))
        MatcherAssert.assertThat(jwks, Matchers.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(jwks.size, Matchers.`is`(1))
        Assert.assertTrue(jwks.containsKey(EXPECTED_KEY_ID))
        val pub = jwks[EXPECTED_KEY_ID]
        MatcherAssert.assertThat(
            pub, Matchers.instanceOf(
                RSAPublicKey::class.java
            )
        )
        val rsaPub = pub as RSAPublicKey?
        MatcherAssert.assertThat(
            rsaPub!!.publicExponent, Matchers.`is`(
                BigInteger(
                    EXPECTED_RSA_EXPONENT
                )
            )
        )
        MatcherAssert.assertThat(rsaPub.modulus, Matchers.`is`(BigInteger(EXPECTED_RSA_MODULUS)))
    }

    @Test
    @Throws(Exception::class)
    public fun shouldReturnEmptyWhenKeysAreEmpty() {
        val jwks = buildJwksFrom(StringReader("{\"keys\": []}"))
        MatcherAssert.assertThat(jwks, Matchers.`is`(Matchers.notNullValue()))
        Assert.assertTrue(jwks.isEmpty())
    }

    @Test
    @Throws(Exception::class)
    public fun shouldReturnEmptyWhenKeysAreFromDifferentAlgorithm() {
        val jwks =
            buildJwksFrom(StringReader("{\"keys\": [{\"alg\": \"RS512\", \"use\": \"sig\"}]}"))
        MatcherAssert.assertThat(jwks, Matchers.`is`(Matchers.notNullValue()))
        Assert.assertTrue(jwks.isEmpty())
    }

    @Test
    @Throws(Exception::class)
    public fun shouldReturnEmptyWhenKeysAreNotForSignatureChecking() {
        val jwks =
            buildJwksFrom(StringReader("{\"keys\": [{\"alg\": \"RS256\", \"use\": \"enc\"}]}"))
        MatcherAssert.assertThat(jwks, Matchers.`is`(Matchers.notNullValue()))
        Assert.assertTrue(jwks.isEmpty())
    }

    @Test
    @Throws(Exception::class)
    public fun shouldReturnEmptyWhenKeysCannotBeCreatedBecauseOfNotSupportedKeyType() {
        val jwks =
            buildJwksFrom(StringReader("{\"keys\": [{\"alg\": \"RS256\", \"use\": \"sig\", \"kty\": \"INVALID_VALUE\"}]}"))
        MatcherAssert.assertThat(jwks, Matchers.`is`(Matchers.notNullValue()))
        Assert.assertTrue(jwks.isEmpty())
    }

    @Throws(IOException::class)
    private fun buildJwksFrom(json: Reader): Map<String, PublicKey> {
        @Suppress("UNCHECKED_CAST") val jwksType: TypeToken<Map<String, PublicKey>> =
            TypeToken.getParameterized(
                Map::class.java,
                String::class.java,
                PublicKey::class.java
            ) as TypeToken<Map<String, PublicKey>>
        return pojoFrom(json, jwksType)
    }

    private companion object {
        private const val VALID_RSA_JWKS = "src/test/resources/rsa_jwks.json"
        private const val EXPECTED_KEY_ID = "key123"
        private const val EXPECTED_RSA_EXPONENT = "65537"
        private const val EXPECTED_RSA_MODULUS = "2327856100899355911632462598898247024131242" +
                "69568893466584055046785206443536944170967694954399904576260402148130300731927741648861" +
                "77036082957412916823253078715836599659671998742580694113788009114660385412566349874736" +
                "27869308481943996880794168096537223920950531497564162778062893250580915368070350845084" +
                "20860279004024750131874921675175697075713453754160892451823567877023128161490580261931" +
                "58312146038158019813447205810433184619008248223295213470806341823186239417071266118809" +
                "63334488448657815599232564013868981211014327205461460864291477265210472076542261630382" +
                "8138891725285516030216809064067106806135514473091101324387"
    }
}