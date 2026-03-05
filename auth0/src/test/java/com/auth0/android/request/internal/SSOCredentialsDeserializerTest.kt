package com.auth0.android.request.internal

import com.auth0.android.result.CredentialsMock
import com.auth0.android.result.SSOCredentials
import com.google.gson.Gson
import com.google.gson.JsonParseException
import org.hamcrest.CoreMatchers
import org.hamcrest.MatcherAssert
import org.hamcrest.Matchers
import org.hamcrest.core.Is
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test

public class SSOCredentialsDeserializerTest {
    private lateinit var gson: Gson

    @Before
    public fun setUp() {
        val deserializer = SSOCredentialsDeserializerMock()
        gson = GsonProvider.gson.newBuilder()
            .registerTypeAdapter(SSOCredentials::class.java, deserializer)
            .create()
    }

    @Test
    @Throws(Exception::class)
    public fun shouldSetExpiresInFromExpiresInSeconds() {
        val json = generateSSOCredentialsJSON()
        val credentials = gson.getAdapter(SSOCredentials::class.java).fromJson(json)
        MatcherAssert.assertThat(credentials.expiresIn, Is.`is`(CoreMatchers.notNullValue()))
        val expiresAt = credentials.expiresIn.time.toDouble()
        val expectedExpiresAt = (CredentialsMock.CURRENT_TIME_MS + 300 * 1000).toDouble()
        MatcherAssert.assertThat(expiresAt, Is.`is`(Matchers.closeTo(expectedExpiresAt, 1.0)))
    }

    @Test
    @Throws(Exception::class)
    public fun shouldDeserializeAllFields() {
        val json = generateSSOCredentialsJSON()
        val credentials = gson.getAdapter(SSOCredentials::class.java).fromJson(json)
        MatcherAssert.assertThat(
            credentials.sessionTransferToken,
            Is.`is`("session-transfer-token")
        )
        MatcherAssert.assertThat(credentials.idToken, Is.`is`("id-token-value"))
        MatcherAssert.assertThat(
            credentials.issuedTokenType,
            Is.`is`("urn:auth0:params:oauth:token-type:session-transfer-token")
        )
        MatcherAssert.assertThat(credentials.tokenType, Is.`is`("N_A"))
        MatcherAssert.assertThat(credentials.refreshToken, Is.`is`("refresh-token-value"))
    }

    @Test
    @Throws(Exception::class)
    public fun shouldDeserializeWithNullRefreshToken() {
        val json = generateSSOCredentialsJSONWithoutRefreshToken()
        val credentials = gson.getAdapter(SSOCredentials::class.java).fromJson(json)
        MatcherAssert.assertThat(
            credentials.sessionTransferToken,
            Is.`is`("session-transfer-token")
        )
        MatcherAssert.assertThat(credentials.idToken, Is.`is`("id-token-value"))
        MatcherAssert.assertThat(credentials.refreshToken, Is.`is`(CoreMatchers.nullValue()))
    }

    private fun generateSSOCredentialsJSON(): String {
        return """
            {
                "access_token": "session-transfer-token",
                "id_token": "id-token-value",
                "issued_token_type": "urn:auth0:params:oauth:token-type:session-transfer-token",
                "token_type": "N_A",
                "expires_in": 300,
                "refresh_token": "refresh-token-value"
            }
            """.trimIndent()
    }

    private fun generateSSOCredentialsJSONWithoutRefreshToken(): String {
        return """
            {
                "access_token": "session-transfer-token",
                "id_token": "id-token-value",
                "issued_token_type": "urn:auth0:params:oauth:token-type:session-transfer-token",
                "token_type": "N_A",
                "expires_in": 300
            }
            """.trimIndent()
    }
}
