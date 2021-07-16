package com.auth0.android.result

import org.hamcrest.MatcherAssert
import org.hamcrest.Matchers
import org.junit.Test
import java.util.*

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
}