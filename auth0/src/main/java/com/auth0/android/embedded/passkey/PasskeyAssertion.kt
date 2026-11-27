package com.auth0.android.embedded.passkey

import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonParseException
import com.google.gson.JsonParser

private const val ID_KEY = "id"
private const val RAW_ID_KEY = "rawId"
private const val TYPE_KEY = "type"
private const val RESPONSE_KEY = "response"
private const val CLIENT_DATA_JSON_KEY = "clientDataJSON"
private const val AUTHENTICATOR_DATA_KEY = "authenticatorData"
private const val SIGNATURE_KEY = "signature"
private const val USER_HANDLE_KEY = "userHandle"
private const val AUTHENTICATOR_ATTACHMENT_KEY = "authenticatorAttachment"
private const val CLIENT_EXTENSION_RESULTS_KEY = "clientExtensionResults"

private const val PUBLIC_KEY_TYPE = "public-key"
private const val MAX_CREDENTIAL_ID_LENGTH = 1364
private const val MAX_CLIENT_DATA_JSON_LENGTH = 1000
private const val MAX_AUTHENTICATOR_DATA_LENGTH = 750
private const val MAX_SIGNATURE_LENGTH = 750
private const val MAX_USER_HANDLE_LENGTH = 100
private const val MAX_CLIENT_EXTENSION_RESULTS = 20

private val AUTHENTICATOR_ATTACHMENTS = setOf("platform", "cross-platform")

/**
 * The result of a passkey sign-in ceremony, as the platform returned it. Pass it to
 * [com.auth0.android.embedded.EmbeddedAuthClient.verifyPasskey].
 *
 * @property authenticationResponseJson the `authenticationResponseJson` of the `PublicKeyCredential` that
 * Credential Manager returned for [com.auth0.android.embedded.authorize.NextAction.VerifyPasskey.requestJson].
 */
public data class PasskeyAssertion(public val authenticationResponseJson: String) {

    override fun toString(): String = "PasskeyAssertion(authenticationResponseJson='xxxxx')"
}

/** The assertion was rejected locally; the message names the field and never includes its value. */
internal class InvalidPasskeyResponseException(message: String) : IllegalArgumentException(message)

/**
 * Builds the `authn_response` object from the `authenticationResponseJson` the platform returns,
 * keeping only the fields `/e/authorize` accepts. It enforces the required fields, the `type` value and the
 * length limits of the `PasskeyAssertion.json` schema of the embedded authorize API, and must be kept in line
 * with them. `authenticatorAttachment` is kept only when it is a known value; `clientExtensionResults` is
 * forwarded unchanged when it is an object with at most 20 entries, and left out otherwise.
 *
 * These are checked here because the server answers a request that breaks the schema with a terminal
 * `invalid_request`, which ends the flow, while a local failure leaves the flow open. The server applies
 * the schema's other rules, such as the characters a string may contain; the platform's responses meet them.
 *
 * @throws InvalidPasskeyResponseException if the assertion doesn't satisfy the schema.
 */
internal fun passkeyAuthnResponse(authenticationResponseJson: String): Map<String, Any> {
    val root = try {
        JsonParser.parseString(authenticationResponseJson)
    } catch (e: JsonParseException) {
        throw InvalidPasskeyResponseException("The passkey response is not valid JSON.")
    }
    val assertion = root as? JsonObject
        ?: throw InvalidPasskeyResponseException("The passkey response must be a JSON object.")
    val response = (assertion.get(RESPONSE_KEY) as? JsonObject)
        ?: throw InvalidPasskeyResponseException("The passkey response is missing \"$RESPONSE_KEY\".")

    val type = assertion.requiredString(TYPE_KEY, PUBLIC_KEY_TYPE.length)
    if (type != PUBLIC_KEY_TYPE) {
        throw InvalidPasskeyResponseException("The passkey response \"$TYPE_KEY\" must be \"$PUBLIC_KEY_TYPE\".")
    }

    return buildMap {
        put(ID_KEY, assertion.requiredString(ID_KEY, MAX_CREDENTIAL_ID_LENGTH))
        put(RAW_ID_KEY, assertion.requiredString(RAW_ID_KEY, MAX_CREDENTIAL_ID_LENGTH))
        put(TYPE_KEY, type)
        put(
            RESPONSE_KEY,
            mapOf(
                CLIENT_DATA_JSON_KEY to response.requiredString(CLIENT_DATA_JSON_KEY, MAX_CLIENT_DATA_JSON_LENGTH, "$RESPONSE_KEY."),
                AUTHENTICATOR_DATA_KEY to response.requiredString(AUTHENTICATOR_DATA_KEY, MAX_AUTHENTICATOR_DATA_LENGTH, "$RESPONSE_KEY."),
                SIGNATURE_KEY to response.requiredString(SIGNATURE_KEY, MAX_SIGNATURE_LENGTH, "$RESPONSE_KEY."),
                USER_HANDLE_KEY to response.requiredString(USER_HANDLE_KEY, MAX_USER_HANDLE_LENGTH, "$RESPONSE_KEY.")
            )
        )
        assertion.stringOrNull(AUTHENTICATOR_ATTACHMENT_KEY)
            ?.takeIf { it in AUTHENTICATOR_ATTACHMENTS }
            ?.let { put(AUTHENTICATOR_ATTACHMENT_KEY, it) }
        (assertion.get(CLIENT_EXTENSION_RESULTS_KEY) as? JsonObject)
            ?.takeIf { it.size() <= MAX_CLIENT_EXTENSION_RESULTS }
            ?.let { put(CLIENT_EXTENSION_RESULTS_KEY, it) }
    }
}

internal fun JsonObject.requiredString(key: String, maxLength: Int, path: String = ""): String {
    val value = stringOrNull(key)
    if (value.isNullOrEmpty()) {
        throw InvalidPasskeyResponseException("The passkey response is missing \"$path$key\".")
    }
    if (value.length > maxLength) {
        throw InvalidPasskeyResponseException("The passkey response \"$path$key\" is longer than $maxLength characters.")
    }
    return value
}

internal fun JsonObject.stringOrNull(key: String): String? {
    val element: JsonElement = get(key) ?: return null
    return if (element.isJsonPrimitive && element.asJsonPrimitive.isString) element.asString else null
}
