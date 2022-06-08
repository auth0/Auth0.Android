package com.auth0.android.request.internal

import com.auth0.android.result.OptionalCredentials
import com.google.gson.JsonParseException
import org.hamcrest.MatcherAssert
import org.hamcrest.Matchers
import org.junit.Assert
import org.junit.Before
import org.junit.Ignore
import org.junit.Test
import java.io.IOException
import java.io.Reader
import java.io.StringReader

@Ignore
public class OptionalCredentialsGsonTest : GsonBaseTest() {
    @Before
    public fun setUp() {
        gson = GsonProvider.gson
    }

    @Test
    @Throws(Exception::class)
    public fun shouldFailWithInvalidJson() {
        Assert.assertThrows(JsonParseException::class.java) {
            buildCredentialsFrom(json(INVALID))
        }
    }

    @Test
    public fun shouldNotFailWithEmptyJson() {
        buildCredentialsFrom(json(EMPTY_OBJECT))
    }

    @Test
    public fun shouldNotRequireAnyProperty() {
        buildCredentialsFrom(StringReader("{\"scope\": \"openid profile\"}"))
    }

    @Test
    @Throws(Exception::class)
    public fun shouldReturnLegacy() {
        val credentials = buildCredentialsFrom(json(LEGACY_CREDENTIALS))
        MatcherAssert.assertThat(credentials, Matchers.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(credentials.accessToken, Matchers.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(credentials.idToken, Matchers.`is`(Matchers.nullValue()))
        MatcherAssert.assertThat(credentials.type, Matchers.equalTo("bearer"))
        MatcherAssert.assertThat(credentials.refreshToken, Matchers.`is`(Matchers.nullValue()))
        MatcherAssert.assertThat(credentials.expiresAt, Matchers.`is`(Matchers.nullValue()))
        MatcherAssert.assertThat(credentials.scope, Matchers.`is`(Matchers.nullValue()))
    }

    @Test
    @Throws(Exception::class)
    public fun shouldReturnBasic() {
        val credentials = buildCredentialsFrom(json(OPENID_OFFLINE_ACCESS_CREDENTIALS))
        MatcherAssert.assertThat(credentials, Matchers.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(credentials.accessToken, Matchers.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(credentials.idToken, Matchers.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(credentials.type, Matchers.equalTo("bearer"))
        MatcherAssert.assertThat(credentials.refreshToken, Matchers.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(credentials.expiresAt, Matchers.`is`(Matchers.nullValue()))
        MatcherAssert.assertThat(credentials.scope, Matchers.`is`(Matchers.notNullValue()))
    }

    @Throws(IOException::class)
    private fun buildCredentialsFrom(json: Reader): OptionalCredentials {
        return pojoFrom(json, OptionalCredentials::class.java)
    }

    private companion object {
        private const val OPENID_OFFLINE_ACCESS_CREDENTIALS =
            "src/test/resources/credentials_openid_refresh_token.json"
        private const val LEGACY_CREDENTIALS = "src/test/resources/credentials_legacy.json"
    }
}