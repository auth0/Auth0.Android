package com.auth0.android.request.internal

import com.auth0.android.result.Credentials
import com.auth0.android.result.CredentialsMock
import com.google.gson.JsonParseException
import org.hamcrest.CoreMatchers
import org.hamcrest.MatcherAssert
import org.hamcrest.Matchers
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import java.io.IOException
import java.io.Reader
import java.io.StringReader
import java.util.*

public class CredentialsGsonTest : GsonBaseTest() {
    @Before
    public fun setUp() {
        gson = GsonProvider.credentialsGson
    }

    @Test
    @Throws(Exception::class)
    public fun shouldFailWithInvalidJson() {
        Assert.assertThrows(JsonParseException::class.java) {
            buildCredentialsFrom(json(INVALID))
        }
    }

    @Test
    @Throws(Exception::class)
    public fun shouldFailWithEmptyJson() {
        Assert.assertThrows(JsonParseException::class.java) {
            buildCredentialsFrom(json(EMPTY_OBJECT))
        }
    }

    @Test
    @Throws(Exception::class)
    public fun shouldNotRequireRefreshToken() {
        buildCredentialsFrom(
            StringReader(
                """{
                "access_token": "s6GS5FGJN2jfd4l6",
                "id_token": "s6GS5FGJN2jfd4l6",
                "token_type": "bearer",
                "expires_in": 86000,
                "scope": "openid"
            }""".trimIndent()
            )
        )
    }

    @Test
    @Throws(Exception::class)
    public fun shouldNotRequireScope() {
        buildCredentialsFrom(
            StringReader(
                """{
                "access_token": "s6GS5FGJN2jfd4l6",
                "id_token": "s6GS5FGJN2jfd4l6",
                "token_type": "bearer",
                "expires_in": 86000,
                "refresh_token": "openid"
            }""".trimIndent()
            )
        )
    }

    @Test
    @Throws(Exception::class)
    public fun shouldReturnBasic() {
        val credentials = buildCredentialsFrom(json(OPENID_CREDENTIALS))
        MatcherAssert.assertThat(credentials, Matchers.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(credentials.accessToken, Matchers.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(credentials.idToken, Matchers.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(credentials.type, Matchers.equalTo("bearer"))
        MatcherAssert.assertThat(credentials.refreshToken, Matchers.`is`(Matchers.nullValue()))
        MatcherAssert.assertThat(credentials.expiresAt, Matchers.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(credentials.scope, Matchers.`is`(Matchers.nullValue()))
    }

    @Test
    @Throws(Exception::class)
    public fun shouldReturnWithExpiresAt() {
        val cal = Calendar.getInstance()
        cal.add(Calendar.DAY_OF_YEAR, 1)
        val exp = cal.time
        val credentialsJSON = generateJSONWithExpiresAt(exp)
        val credentials = buildCredentialsFrom(StringReader(credentialsJSON))
        MatcherAssert.assertThat(credentials, Matchers.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(credentials.accessToken, Matchers.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(credentials.type, Matchers.equalTo("bearer"))
        //The hardcoded value comes from the JSON file
        MatcherAssert.assertThat(credentials.expiresAt, Matchers.`is`(Matchers.notNullValue()))
        val expiresAt = credentials.expiresAt.time.toDouble()
        MatcherAssert.assertThat(
            expiresAt,
            Matchers.`is`(Matchers.closeTo(exp.time.toDouble(), 1.0))
        )
    }

    @Test
    @Throws(Exception::class)
    public fun shouldReturnWithRefreshToken() {
        val credentials = buildCredentialsFrom(json(OPENID_OFFLINE_ACCESS_CREDENTIALS))
        MatcherAssert.assertThat(credentials, Matchers.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(credentials.accessToken, Matchers.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(credentials.idToken, Matchers.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(credentials.type, Matchers.equalTo("bearer"))
        MatcherAssert.assertThat(credentials.refreshToken, Matchers.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(credentials.expiresAt, Matchers.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(credentials.scope, Matchers.`is`("openid profile"))
    }

    @Test
    public fun shouldSerializeCredentials() {
        val expiresAt = Date(CredentialsMock.CURRENT_TIME_MS + 123456 * 1000)
        val expectedExpiresAt = gson.toJsonTree(expiresAt).getAsString()
        val expiresInCredentials: Credentials =
            CredentialsMock("id", "access", "ty", "refresh", expiresAt, null)
        val expiresInJson = gson.toJson(expiresInCredentials)
        MatcherAssert.assertThat(expiresInJson, CoreMatchers.containsString("\"id_token\":\"id\""))
        MatcherAssert.assertThat(
            expiresInJson,
            CoreMatchers.containsString("\"access_token\":\"access\"")
        )
        MatcherAssert.assertThat(
            expiresInJson,
            CoreMatchers.containsString("\"token_type\":\"ty\"")
        )
        MatcherAssert.assertThat(
            expiresInJson,
            CoreMatchers.containsString("\"refresh_token\":\"refresh\"")
        )
        MatcherAssert.assertThat(
            expiresInJson,
            CoreMatchers.not(CoreMatchers.containsString("\"expires_in\""))
        )
        MatcherAssert.assertThat(
            expiresInJson, CoreMatchers.containsString(
                "\"expires_at\":\"$expectedExpiresAt\""
            )
        )
        MatcherAssert.assertThat(
            expiresInJson,
            CoreMatchers.not(CoreMatchers.containsString("\"scope\""))
        )
        val expiresAtCredentials: Credentials =
            CredentialsMock("id", "access", "ty", "refresh", expiresAt, "openid")
        val expiresAtJson = gson.toJson(expiresAtCredentials)
        MatcherAssert.assertThat(expiresAtJson, CoreMatchers.containsString("\"id_token\":\"id\""))
        MatcherAssert.assertThat(
            expiresAtJson,
            CoreMatchers.containsString("\"access_token\":\"access\"")
        )
        MatcherAssert.assertThat(
            expiresAtJson,
            CoreMatchers.containsString("\"token_type\":\"ty\"")
        )
        MatcherAssert.assertThat(
            expiresAtJson,
            CoreMatchers.containsString("\"refresh_token\":\"refresh\"")
        )
        MatcherAssert.assertThat(
            expiresAtJson,
            CoreMatchers.not(CoreMatchers.containsString("\"expires_in\""))
        )
        MatcherAssert.assertThat(
            expiresInJson, CoreMatchers.containsString(
                "\"expires_at\":\"$expectedExpiresAt\""
            )
        )
        MatcherAssert.assertThat(expiresAtJson, CoreMatchers.containsString("\"scope\":\"openid\""))
    }

    @Throws(IOException::class)
    private fun buildCredentialsFrom(json: Reader): Credentials {
        return pojoFrom(json, Credentials::class.java)
    }

    private fun generateJSONWithExpiresAt(expiresAt: Date): String {
        return """
            {
            "access_token": "s6GS5FGJN2jfd4l6",
            "id_token": "s6GS5FGJN2jfd4l6",
            "token_type": "bearer",
            "expires_in": 86000,
            "expires_at": ${gson.toJson(expiresAt)}
            }
            """.trimIndent()
    }

    private companion object {
        private const val OPENID_OFFLINE_ACCESS_CREDENTIALS =
            "src/test/resources/credentials_openid_refresh_token.json"
        private const val OPENID_CREDENTIALS = "src/test/resources/credentials_openid.json"
    }
}