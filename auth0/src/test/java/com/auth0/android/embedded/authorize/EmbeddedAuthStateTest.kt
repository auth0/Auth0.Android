package com.auth0.android.embedded.authorize

import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.Matchers.containsString
import org.hamcrest.Matchers.not
import org.junit.Test

public class EmbeddedAuthStateTest {

    @Test
    public fun `toString hides the verifier and the session`() {
        val text = EmbeddedAuthState("the-verifier", "the-session").toString()

        assertThat(text, not(containsString("the-verifier")))
        assertThat(text, not(containsString("the-session")))
    }
}
