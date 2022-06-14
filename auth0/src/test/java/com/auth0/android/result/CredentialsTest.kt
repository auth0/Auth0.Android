package com.auth0.android.result

import com.auth0.android.request.internal.GsonProvider.credentialsGson
import org.hamcrest.MatcherAssert
import org.hamcrest.Matchers
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.util.*

private val idToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwOi8vbXktZG9tYWluLmF1dGgwLmNvbSIsInN1YiI6ImF1dGgwfDEyMzQ1NiIsImF1ZCI6Im15X2NsaWVudF9pZCIsImV4cCI6MTMxMTI4MTk3MCwiaWF0IjoxMzExMjgwOTcwLCJuYW1lIjoiSmFuZSBEb2UiLCJnaXZlbl9uYW1lIjoiSmFuZSIsImZhbWlseV9uYW1lIjoiRG9lIiwiZ2VuZGVyIjoiZmVtYWxlIiwiYmlydGhkYXRlIjoiMDAwMC0xMC0zMSIsImVtYWlsIjoiamFuZWRvZUBleGFtcGxlLmNvbSIsInBpY3R1cmUiOiJodHRwOi8vZXhhbXBsZS5jb20vamFuZWRvZS9tZS5qcGcifQ.FKw0UVWANEqibD9VTC9WLzstlyc_IRnyPSpUMDP3hKc"

@RunWith(RobolectricTestRunner::class)
public class CredentialsTest {
    @Test
    public fun shouldCreate() {
        val date = Date()
        val credentials: Credentials =
            CredentialsMock("idToken", "accessToken", "type", "refreshToken", date, "scope")
        MatcherAssert.assertThat(credentials.idToken, Matchers.`is`("idToken"))
        MatcherAssert.assertThat(credentials.accessToken, Matchers.`is`("accessToken"))
        MatcherAssert.assertThat(credentials.type, Matchers.`is`("type"))
        MatcherAssert.assertThat(credentials.refreshToken, Matchers.`is`("refreshToken"))
        MatcherAssert.assertThat(credentials.expiresAt, Matchers.`is`(date))
        MatcherAssert.assertThat(credentials.scope, Matchers.`is`("scope"))
        MatcherAssert.assertThat(credentials.recoveryCode, Matchers.`is`(Matchers.nullValue()))
    }

    @Test
    public fun shouldGetScope() {
        val credentials =
            Credentials("idToken", "accessToken", "type", "refreshToken", Date(), "openid profile")
        MatcherAssert.assertThat(credentials.scope, Matchers.`is`("openid profile"))
    }

    @Test
    public fun shouldGetRecoveryCode() {
        val date = Date()
        val credentials: Credentials =
            CredentialsMock("idToken", "accessToken", "type", "refreshToken", date, "scope")
        credentials.recoveryCode = "recoveryCode"
        MatcherAssert.assertThat(credentials.recoveryCode, Matchers.`is`("recoveryCode"))
    }

    @Test
    public fun shouldGetUser() {
        val date = Date()
        val credentials: Credentials =
            CredentialsMock(idToken, "accessToken", "type", "refreshToken", date, "scope")
        MatcherAssert.assertThat(credentials.user.getId(), Matchers.`is`("auth0|123456"))
    }

    @Test
    public fun shouldNotSerializeUser() {
        val date = Date()
        val credentials: Credentials =
            CredentialsMock(idToken, "accessToken", "type", "refreshToken", date, "scope")
        MatcherAssert.assertThat(credentials.user.getId(), Matchers.`is`("auth0|123456"))
        val json = credentialsGson.toJson(credentials, Credentials::class.java)
        MatcherAssert.assertThat(json, Matchers.not(Matchers.containsString("auth0|123456")))
    }
}