package com.auth0.android.embedded.passkey

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.Matchers.containsString
import org.hamcrest.Matchers.`is`
import org.hamcrest.Matchers.not
import org.junit.Assert.fail
import org.junit.Test

public class PasskeyAssertionTest {

    private val validAssertion = """
        {
          "id": "credential-id",
          "rawId": "credential-raw-id",
          "type": "public-key",
          "authenticatorAttachment": "platform",
          "clientExtensionResults": {},
          "response": {
            "clientDataJSON": "client-data",
            "authenticatorData": "authenticator-data",
            "signature": "the-signature",
            "userHandle": "user-handle"
          }
        }
    """.trimIndent()

    @Test
    public fun `builds authn_response with exactly the allowed fields`() {
        val result = passkeyAuthnResponse(validAssertion)

        assertThat(
            result.keys,
            `is`(setOf("id", "rawId", "type", "response", "authenticatorAttachment", "clientExtensionResults"))
        )
        assertThat(result["id"], `is`("credential-id"))
        assertThat(result["rawId"], `is`("credential-raw-id"))
        assertThat(result["type"], `is`("public-key"))
        @Suppress("UNCHECKED_CAST")
        val response = result["response"] as Map<String, Any>
        assertThat(response.keys, `is`(setOf("clientDataJSON", "authenticatorData", "signature", "userHandle")))
        assertThat(response["clientDataJSON"], `is`("client-data"))
        assertThat(response["authenticatorData"], `is`("authenticator-data"))
        assertThat(response["signature"], `is`("the-signature"))
        assertThat(response["userHandle"], `is`("user-handle"))
    }

    @Test
    public fun `drops fields the schema does not allow`() {
        val input = edit {
            addProperty("unexpected", "value")
            getAsJsonObject("response").apply {
                addProperty("attestationObject", "attestation")
                add("transports", JsonParser.parseString("""["internal"]"""))
                addProperty("other", "value")
            }
        }

        val result = passkeyAuthnResponse(input)

        assertThat(result.containsKey("unexpected"), `is`(false))
        @Suppress("UNCHECKED_CAST")
        val response = result["response"] as Map<String, Any>
        assertThat(response.keys, `is`(setOf("clientDataJSON", "authenticatorData", "signature", "userHandle")))
    }

    @Test
    public fun `keeps platform and cross-platform authenticatorAttachment`() {
        for (attachment in listOf("platform", "cross-platform")) {
            val result = passkeyAuthnResponse(edit { addProperty("authenticatorAttachment", attachment) })
            assertThat(result["authenticatorAttachment"], `is`(attachment))
        }
    }

    @Test
    public fun `leaves out authenticatorAttachment when missing, unknown, null or not a string`() {
        val variants = listOf<JsonObject.() -> Unit>(
            { remove("authenticatorAttachment") },
            { addProperty("authenticatorAttachment", "hybrid") },
            { add("authenticatorAttachment", com.google.gson.JsonNull.INSTANCE) },
            { addProperty("authenticatorAttachment", 1) }
        )
        for (variant in variants) {
            val result = passkeyAuthnResponse(edit(variant))
            assertThat(result.containsKey("authenticatorAttachment"), `is`(false))
        }
    }

    @Test
    public fun `keeps clientExtensionResults when it is an object`() {
        val result = passkeyAuthnResponse(
            edit { add("clientExtensionResults", JsonParser.parseString("""{"credProps":{"rk":true}}""")) }
        )

        assertThat(result["clientExtensionResults"].toString(), `is`("""{"credProps":{"rk":true}}"""))
    }

    @Test
    public fun `leaves out clientExtensionResults when missing or not an object`() {
        val variants = listOf<JsonObject.() -> Unit>(
            { remove("clientExtensionResults") },
            { add("clientExtensionResults", com.google.gson.JsonNull.INSTANCE) },
            { add("clientExtensionResults", JsonParser.parseString("[1]")) },
            { addProperty("clientExtensionResults", "x") }
        )
        for (variant in variants) {
            val result = passkeyAuthnResponse(edit(variant))
            assertThat(result.containsKey("clientExtensionResults"), `is`(false))
        }
    }

    @Test
    public fun `rejects input that is not a JSON object`() {
        for (input in listOf("", "   ", "null", "[1]", "\"text\"", "not json", """{"id":"a"} trailing""")) {
            assertRejected(input)
        }
    }

    @Test
    public fun `rejects a missing or non-object response`() {
        assertRejected(edit { remove("response") }, "response")
        assertRejected(edit { addProperty("response", "x") }, "response")
        assertRejected(edit { add("response", JsonParser.parseString("[]")) }, "response")
    }

    @Test
    public fun `rejects each required field that is missing, empty, not a string or null`() {
        val topLevel = listOf("id", "rawId", "type")
        for (field in topLevel) {
            assertRejected(edit { remove(field) }, field)
            assertRejected(edit { addProperty(field, "") }, field)
            assertRejected(edit { addProperty(field, 1) }, field)
            assertRejected(edit { add(field, com.google.gson.JsonNull.INSTANCE) }, field)
        }
        for (field in RESPONSE_LIMITS.keys) {
            assertRejected(edit { getAsJsonObject("response").remove(field) }, "response.$field")
            assertRejected(edit { getAsJsonObject("response").addProperty(field, "") }, "response.$field")
            assertRejected(edit { getAsJsonObject("response").addProperty(field, 1) }, "response.$field")
            assertRejected(
                edit { getAsJsonObject("response").add(field, com.google.gson.JsonNull.INSTANCE) },
                "response.$field"
            )
        }
    }

    @Test
    public fun `rejects a type other than public-key`() {
        assertRejected(edit { addProperty("type", "other") }, "type")
    }

    @Test
    public fun `accepts every field at its maximum length`() {
        for (field in listOf("id", "rawId")) {
            passkeyAuthnResponse(edit { addProperty(field, "a".repeat(1364)) })
        }
        for ((field, max) in RESPONSE_LIMITS) {
            passkeyAuthnResponse(edit { getAsJsonObject("response").addProperty(field, "a".repeat(max)) })
        }
    }

    @Test
    public fun `rejects every field one character over its maximum length`() {
        for (field in listOf("id", "rawId")) {
            assertRejected(edit { addProperty(field, "a".repeat(1365)) }, field)
        }
        for ((field, max) in RESPONSE_LIMITS) {
            assertRejected(
                edit { getAsJsonObject("response").addProperty(field, "a".repeat(max + 1)) },
                "response.$field"
            )
        }
    }

    @Test
    public fun `error messages never include the rejected value`() {
        val secret = "SECRET-VALUE-" + "a".repeat(1400)

        val tooLong = assertRejected(edit { addProperty("id", secret) }, "id")
        val wrongType = assertRejected(edit { addProperty("type", "SECRET-TYPE") }, "type")

        assertThat(tooLong.message, not(containsString("SECRET-VALUE")))
        assertThat(wrongType.message, not(containsString("SECRET-TYPE")))
    }

    private fun edit(change: JsonObject.() -> Unit): String =
        JsonParser.parseString(validAssertion).asJsonObject.apply(change).toString()

    private fun assertRejected(input: String, field: String? = null): InvalidPasskeyResponseException {
        try {
            passkeyAuthnResponse(input)
        } catch (e: InvalidPasskeyResponseException) {
            if (field != null) {
                assertThat(e.message, containsString("\"$field\""))
            }
            return e
        }
        fail("expected InvalidPasskeyResponseException")
        throw AssertionError()
    }

    private companion object {
        private val RESPONSE_LIMITS = mapOf(
            "clientDataJSON" to 1000,
            "authenticatorData" to 750,
            "signature" to 750,
            "userHandle" to 100
        )
    }
}
