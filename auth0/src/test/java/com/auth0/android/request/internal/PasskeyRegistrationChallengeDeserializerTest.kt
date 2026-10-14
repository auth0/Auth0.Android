package com.auth0.android.request.internal

import com.auth0.android.result.PasskeyRegistrationChallenge
import com.auth0.android.result.PasskeyVerificationMethod
import com.google.gson.JsonParseException
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.Matchers
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
public class PasskeyRegistrationChallengeDeserializerTest {

    private val publicKey = """{
        "authenticatorSelection": {"residentKey": "required", "userVerification": "preferred"},
        "challenge": "challenge",
        "pubKeyCredParams": [{"alg": -7, "type": "public-key"}],
        "rp": {"id": "example.com", "name": "example.com"},
        "timeout": 60000,
        "user": {"displayName": "name", "id": "id", "name": "name"}
    }"""

    private fun parse(json: String): PasskeyRegistrationChallenge =
        GsonProvider.gson.fromJson(json, PasskeyRegistrationChallenge::class.java)

    @Test
    public fun shouldDefaultVerificationRequiredToEmptyList() {
        val challenge = parse("""{"auth_session": "session", "authn_params_public_key": $publicKey}""")
        assertThat(challenge.authSession, Matchers.`is`("session"))
        assertThat(challenge.verificationRequired, Matchers.empty())
    }

    @Test
    public fun shouldParseVerificationRequired() {
        val challenge = parse(
            """{"auth_session": "session", "authn_params_public_key": $publicKey,
                "verification_required": ["email", "phone"]}"""
        )
        assertThat(
            challenge.verificationRequired,
            Matchers.contains(PasskeyVerificationMethod.EMAIL, PasskeyVerificationMethod.PHONE)
        )
    }

    @Test
    public fun shouldFailWhenAuthSessionIsMissing() {
        assertThrows(JsonParseException::class.java) {
            parse("""{"authn_params_public_key": $publicKey}""")
        }
    }

    @Test
    public fun shouldFailWhenPublicKeyParamsAreMissing() {
        assertThrows(JsonParseException::class.java) {
            parse("""{"auth_session": "session"}""")
        }
    }

    @Test
    public fun shouldFailWhenJsonIsNotAnObject() {
        assertThrows(JsonParseException::class.java) { parse("[]") }
    }
}
