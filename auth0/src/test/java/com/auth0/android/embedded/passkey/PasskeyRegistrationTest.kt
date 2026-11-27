package com.auth0.android.embedded.passkey

import com.google.gson.JsonArray
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.Matchers.containsString
import org.hamcrest.Matchers.`is`
import org.hamcrest.Matchers.not
import org.junit.Assert.fail
import org.junit.Test

public class PasskeyRegistrationTest {

    private val validRegistration = """
        {
          "id": "credential-id",
          "rawId": "credential-raw-id",
          "type": "public-key",
          "authenticatorAttachment": "platform",
          "clientExtensionResults": {"credProps": {"rk": true}},
          "response": {
            "clientDataJSON": "client-data",
            "attestationObject": "attestation",
            "transports": ["internal", "hybrid"],
            "authenticatorData": "authenticator-data",
            "publicKeyAlgorithm": -7,
            "publicKey": "public-key-bytes"
          }
        }
    """.trimIndent()

    @Test
    public fun `builds the passkey with exactly the allowed fields`() {
        val result = passkeyRegistrationResponse(validRegistration)

        assertThat(
            result.keys,
            `is`(setOf("id", "rawId", "type", "response", "authenticatorAttachment", "clientExtensionResults"))
        )
        assertThat(result["id"], `is`("credential-id"))
        assertThat(result["rawId"], `is`("credential-raw-id"))
        assertThat(result["type"], `is`("public-key"))
        assertThat(response(result).keys, `is`(setOf("clientDataJSON", "attestationObject", "transports", "authenticatorData", "publicKeyAlgorithm", "publicKey")))
        assertThat(response(result)["clientDataJSON"], `is`("client-data"))
        assertThat(response(result)["attestationObject"], `is`("attestation"))
        assertThat(response(result)["transports"], `is`(listOf("internal", "hybrid")))
        assertThat(response(result)["authenticatorData"], `is`("authenticator-data"))
        assertThat(response(result)["publicKey"], `is`("public-key-bytes"))
    }

    @Test
    public fun `keeps only the required fields when the optional ones are missing`() {
        val input = """{"id":"a","rawId":"b","type":"public-key","response":{"clientDataJSON":"c","attestationObject":"d"}}"""

        val result = passkeyRegistrationResponse(input)

        assertThat(result.keys, `is`(setOf("id", "rawId", "type", "response")))
        assertThat(response(result).keys, `is`(setOf("clientDataJSON", "attestationObject")))
    }

    @Test
    public fun `drops fields the schema does not allow`() {
        val input = edit {
            addProperty("unexpected", "value")
            getAsJsonObject("response").apply {
                addProperty("signature", "signature")
                addProperty("userHandle", "handle")
                addProperty("other", "value")
            }
        }

        val result = passkeyRegistrationResponse(input)

        assertThat(result.containsKey("unexpected"), `is`(false))
        assertThat(response(result).containsKey("signature"), `is`(false))
        assertThat(response(result).containsKey("userHandle"), `is`(false))
        assertThat(response(result).containsKey("other"), `is`(false))
    }

    @Test
    public fun `keeps the publicKeyAlgorithm as a whole number`() {
        val result = passkeyRegistrationResponse(validRegistration)

        assertThat(response(result)["publicKeyAlgorithm"], `is`(-7L))
    }

    @Test
    public fun `leaves out a publicKeyAlgorithm that is not a whole number`() {
        for (value in listOf("-7.5", "\"-7\"", "true", "null", "[-7]")) {
            val input = edit { getAsJsonObject("response").add("publicKeyAlgorithm", JsonParser.parseString(value)) }

            assertThat("value=$value", response(passkeyRegistrationResponse(input)).containsKey("publicKeyAlgorithm"), `is`(false))
        }
    }

    @Test
    public fun `keeps platform and cross-platform authenticatorAttachment`() {
        for (attachment in listOf("platform", "cross-platform")) {
            val input = edit { addProperty("authenticatorAttachment", attachment) }

            assertThat(passkeyRegistrationResponse(input)["authenticatorAttachment"], `is`(attachment))
        }
    }

    @Test
    public fun `leaves out authenticatorAttachment when missing, unknown, null or not a string`() {
        val values = listOf<JsonObject.() -> Unit>(
            { remove("authenticatorAttachment") },
            { addProperty("authenticatorAttachment", "usb") },
            { add("authenticatorAttachment", com.google.gson.JsonNull.INSTANCE) },
            { addProperty("authenticatorAttachment", 1) }
        )
        for (change in values) {
            assertThat(passkeyRegistrationResponse(edit(change)).containsKey("authenticatorAttachment"), `is`(false))
        }
    }

    @Test
    public fun `keeps clientExtensionResults with at most 20 entries`() {
        val input = edit { add("clientExtensionResults", extensionResults(20)) }

        assertThat((passkeyRegistrationResponse(input)["clientExtensionResults"] as JsonObject).size(), `is`(20))
    }

    @Test
    public fun `leaves out clientExtensionResults with more than 20 entries`() {
        val input = edit { add("clientExtensionResults", extensionResults(21)) }

        assertThat(passkeyRegistrationResponse(input).containsKey("clientExtensionResults"), `is`(false))
    }

    @Test
    public fun `leaves out clientExtensionResults that is not an object`() {
        val input = edit { add("clientExtensionResults", JsonParser.parseString("[1]")) }

        assertThat(passkeyRegistrationResponse(input).containsKey("clientExtensionResults"), `is`(false))
    }

    @Test
    public fun `keeps transports with at most 10 entries of at most 100 characters`() {
        val transports = JsonArray().apply { repeat(10) { add("t".repeat(100)) } }
        val input = edit { getAsJsonObject("response").add("transports", transports) }

        assertThat((response(passkeyRegistrationResponse(input))["transports"] as List<*>).size, `is`(10))
    }

    @Test
    public fun `leaves out transports with more than 10 entries`() {
        val transports = JsonArray().apply { repeat(11) { add("internal") } }
        val input = edit { getAsJsonObject("response").add("transports", transports) }

        assertThat(response(passkeyRegistrationResponse(input)).containsKey("transports"), `is`(false))
    }

    @Test
    public fun `leaves out transports with an entry over 100 characters`() {
        val input = edit { getAsJsonObject("response").add("transports", JsonArray().apply { add("t".repeat(101)) }) }

        assertThat(response(passkeyRegistrationResponse(input)).containsKey("transports"), `is`(false))
    }

    @Test
    public fun `leaves out transports that are not an array of strings`() {
        for (value in listOf("\"internal\"", "[1]", "[\"internal\", null]", "{\"a\":1}")) {
            val input = edit { getAsJsonObject("response").add("transports", JsonParser.parseString(value)) }

            assertThat("value=$value", response(passkeyRegistrationResponse(input)).containsKey("transports"), `is`(false))
        }
    }

    @Test
    public fun `keeps the optional response strings at their maximum length`() {
        val input = edit {
            getAsJsonObject("response").apply {
                addProperty("authenticatorData", "a".repeat(1000))
                addProperty("publicKey", "k".repeat(2048))
            }
        }

        val result = response(passkeyRegistrationResponse(input))

        assertThat((result["authenticatorData"] as String).length, `is`(1000))
        assertThat((result["publicKey"] as String).length, `is`(2048))
    }

    @Test
    public fun `leaves out the optional response strings that are empty, too long or not strings`() {
        val cases = mapOf(
            "authenticatorData" to listOf("\"\"", "\"${"a".repeat(1001)}\"", "1", "null"),
            "publicKey" to listOf("\"\"", "\"${"k".repeat(2049)}\"", "1", "null")
        )
        for ((field, values) in cases) {
            for (value in values) {
                val input = edit { getAsJsonObject("response").add(field, JsonParser.parseString(value)) }

                assertThat("$field=${value.take(12)}", response(passkeyRegistrationResponse(input)).containsKey(field), `is`(false))
            }
        }
    }

    @Test
    public fun `rejects input that is not a JSON object`() {
        for (input in listOf("not json", "[]", "\"text\"", "1")) {
            assertRejected(input)
        }
    }

    @Test
    public fun `rejects a missing or non-object response`() {
        assertRejected(edit { remove("response") }, "response")
        assertRejected(edit { addProperty("response", "text") }, "response")
        assertRejected(edit { add("response", JsonArray()) }, "response")
    }

    @Test
    public fun `rejects each required field that is missing, empty, not a string or null`() {
        val top = listOf("id", "rawId", "type")
        val inResponse = listOf("clientDataJSON", "attestationObject")
        val invalid = listOf<(JsonObject, String) -> Unit>(
            { o, f -> o.remove(f) },
            { o, f -> o.addProperty(f, "") },
            { o, f -> o.addProperty(f, 1) },
            { o, f -> o.add(f, com.google.gson.JsonNull.INSTANCE) }
        )
        for (field in top) {
            for (change in invalid) {
                assertRejected(edit { change(this, field) }, field)
            }
        }
        for (field in inResponse) {
            for (change in invalid) {
                assertRejected(edit { change(getAsJsonObject("response"), field) }, "response.$field")
            }
        }
    }

    @Test
    public fun `rejects a type other than public-key`() {
        assertRejected(edit { addProperty("type", "password") }, "type")
    }

    @Test
    public fun `accepts every required field at its maximum length`() {
        val input = edit {
            addProperty("id", "i".repeat(1364))
            addProperty("rawId", "r".repeat(1364))
            getAsJsonObject("response").apply {
                addProperty("clientDataJSON", "c".repeat(1000))
                addProperty("attestationObject", "a".repeat(2000))
            }
        }

        val result = passkeyRegistrationResponse(input)

        assertThat((result["id"] as String).length, `is`(1364))
        assertThat((response(result)["attestationObject"] as String).length, `is`(2000))
    }

    @Test
    public fun `rejects every required field one character over its maximum length`() {
        assertRejected(edit { addProperty("id", "i".repeat(1365)) }, "id")
        assertRejected(edit { addProperty("rawId", "r".repeat(1365)) }, "rawId")
        assertRejected(edit { getAsJsonObject("response").addProperty("clientDataJSON", "c".repeat(1001)) }, "response.clientDataJSON")
        assertRejected(edit { getAsJsonObject("response").addProperty("attestationObject", "a".repeat(2001)) }, "response.attestationObject")
    }

    @Test
    public fun `error messages never include the rejected value`() {
        val secret = "SECRET-VALUE-" + "a".repeat(2100)

        val tooLong = assertRejected(edit { getAsJsonObject("response").addProperty("attestationObject", secret) }, "response.attestationObject")
        val wrongType = assertRejected(edit { addProperty("type", "SECRET-TYPE") }, "type")

        assertThat(tooLong.message, not(containsString("SECRET-VALUE")))
        assertThat(wrongType.message, not(containsString("SECRET-TYPE")))
    }

    private fun response(result: Map<String, Any>): Map<*, *> = result["response"] as Map<*, *>

    private fun extensionResults(count: Int): JsonObject =
        JsonObject().apply { repeat(count) { addProperty("extension$it", true) } }

    private fun edit(change: JsonObject.() -> Unit): String =
        JsonParser.parseString(validRegistration).asJsonObject.apply(change).toString()

    private fun assertRejected(input: String, field: String? = null): InvalidPasskeyResponseException {
        try {
            passkeyRegistrationResponse(input)
        } catch (e: InvalidPasskeyResponseException) {
            if (field != null) {
                assertThat(e.message, containsString("\"$field\""))
            }
            return e
        }
        fail("expected InvalidPasskeyResponseException")
        throw AssertionError()
    }
}
