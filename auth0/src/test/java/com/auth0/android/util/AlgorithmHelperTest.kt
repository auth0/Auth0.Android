package com.auth0.android.util

import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.Matchers.`is`
import org.hamcrest.Matchers.not
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.security.MessageDigest
import java.util.Base64

@RunWith(RobolectricTestRunner::class)
public class AlgorithmHelperTest {

    private val helper = AlgorithmHelper()

    @Test
    public fun `generates a 43-character base64url code verifier`() {
        val verifier = helper.generateCodeVerifier()

        assertThat(verifier.length, `is`(43))
        assertThat(Regex("^[A-Za-z0-9_-]+$").matches(verifier), `is`(true))
    }

    @Test
    public fun `generates a different code verifier each time`() {
        assertThat(helper.generateCodeVerifier(), not(helper.generateCodeVerifier()))
    }

    @Test
    public fun `generates the S256 code challenge of the verifier`() {
        val verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

        val challenge = helper.generateCodeChallenge(verifier)

        assertThat(challenge, `is`("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"))
        val expected = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray(Charsets.US_ASCII)))
        assertThat(challenge, `is`(expected))
    }
}
