package com.auth0.android.request.internal

import com.auth0.android.result.Credentials
import com.auth0.android.result.CredentialsMock
import com.google.gson.Gson
import org.hamcrest.CoreMatchers
import org.hamcrest.MatcherAssert
import org.hamcrest.Matchers
import org.hamcrest.core.Is
import org.junit.Before
import org.junit.Test
import java.io.FileReader
import java.util.*

public class CredentialsDeserializerTest {
    private lateinit var gson: Gson

    @Before
    public fun setUp() {
        val deserializer = CredentialsDeserializerMock()
        gson = GsonProvider.credentialsGson.newBuilder()
            .registerTypeAdapter(Credentials::class.java, deserializer)
            .create()
    }

    @Test
    @Throws(Exception::class)
    public fun shouldSetExpiresAtFromExpiresIn() {
        val credentials = gson.getAdapter(
            Credentials::class.java
        ).fromJson(FileReader(OPENID_CREDENTIALS))
        MatcherAssert.assertThat(credentials.expiresAt, Is.`is`(CoreMatchers.notNullValue()))
        val expiresAt = credentials.expiresAt.time.toDouble()
        val expectedExpiresAt = (CredentialsMock.CURRENT_TIME_MS + 86000 * 1000).toDouble()
        MatcherAssert.assertThat(expiresAt, Is.`is`(Matchers.closeTo(expectedExpiresAt, 1.0)))
    }

    @Test
    @Throws(Exception::class)
    public fun shouldSetExpiresInFromExpiresAt() {
        val cal = Calendar.getInstance()
        cal.add(Calendar.DAY_OF_YEAR, 7)
        val exp = cal.time
        val credentials = gson.getAdapter(
            Credentials::class.java
        ).fromJson(generateExpiresAtCredentialsJSON(exp))
        //The hardcoded value comes from the JSON file
        MatcherAssert.assertThat(credentials.expiresAt, Is.`is`(CoreMatchers.notNullValue()))
        val expiresAt = credentials.expiresAt.time.toDouble()
        val expectedExpiresAt = exp.time.toDouble()
        MatcherAssert.assertThat(expiresAt, Is.`is`(Matchers.closeTo(expectedExpiresAt, 1.0)))
    }

    private fun generateExpiresAtCredentialsJSON(expiresAt: Date): String {
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
        private const val OPENID_CREDENTIALS = "src/test/resources/credentials_openid.json"
    }
}