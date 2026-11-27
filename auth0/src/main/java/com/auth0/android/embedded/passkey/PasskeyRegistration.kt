package com.auth0.android.embedded.passkey

import com.google.gson.JsonArray
import com.google.gson.JsonObject
import com.google.gson.JsonParseException
import com.google.gson.JsonParser

private const val ID_KEY = "id"
private const val RAW_ID_KEY = "rawId"
private const val TYPE_KEY = "type"
private const val RESPONSE_KEY = "response"
private const val CLIENT_DATA_JSON_KEY = "clientDataJSON"
private const val ATTESTATION_OBJECT_KEY = "attestationObject"
private const val TRANSPORTS_KEY = "transports"
private const val AUTHENTICATOR_DATA_KEY = "authenticatorData"
private const val PUBLIC_KEY_ALGORITHM_KEY = "publicKeyAlgorithm"
private const val PUBLIC_KEY_KEY = "publicKey"
private const val AUTHENTICATOR_ATTACHMENT_KEY = "authenticatorAttachment"
private const val CLIENT_EXTENSION_RESULTS_KEY = "clientExtensionResults"

private const val PUBLIC_KEY_TYPE = "public-key"
private const val MAX_CREDENTIAL_ID_LENGTH = 1364
private const val MAX_CLIENT_DATA_JSON_LENGTH = 1000
private const val MAX_ATTESTATION_OBJECT_LENGTH = 2000
private const val MAX_AUTHENTICATOR_DATA_LENGTH = 1000
private const val MAX_PUBLIC_KEY_LENGTH = 2048
private const val MAX_TRANSPORTS = 10
private const val MAX_TRANSPORT_LENGTH = 100
private const val MAX_CLIENT_EXTENSION_RESULTS = 20
private const val LONG_BITS = 64

private val AUTHENTICATOR_ATTACHMENTS = setOf("platform", "cross-platform")

/**
 * The result of creating a passkey at signup, as the platform returned it. Pass it to
 * [com.auth0.android.embedded.EmbeddedAuthClient.confirmSignup].
 *
 * @property registrationResponseJson the `registrationResponseJson` of the `CreatePublicKeyCredentialResponse`
 * that Credential Manager returned for [SignupPasskey.requestJson].
 */
public data class PasskeyRegistration(public val registrationResponseJson: String) {

    override fun toString(): String = "PasskeyRegistration(registrationResponseJson='xxxxx')"
}

/**
 * Builds the `passkey` object from the `registrationResponseJson` the platform returns, keeping only the
 * fields `/e/authorize` accepts. It enforces the required fields, the `type` value and the length limits
 * of the `PasskeyRegistration.json` schema of the embedded authorize API, and must be kept in line with
 * them. The optional fields are kept only when they have the expected type and size, and left out
 * otherwise; `clientExtensionResults` is forwarded unchanged when it is an object with at most 20 entries.
 *
 * @throws InvalidPasskeyResponseException if the registration doesn't satisfy the schema.
 */
internal fun passkeyRegistrationResponse(registrationResponseJson: String): Map<String, Any> {
    val root = try {
        JsonParser.parseString(registrationResponseJson)
    } catch (e: JsonParseException) {
        throw InvalidPasskeyResponseException("The passkey response is not valid JSON.")
    }
    val registration = root as? JsonObject
        ?: throw InvalidPasskeyResponseException("The passkey response must be a JSON object.")
    val response = (registration.get(RESPONSE_KEY) as? JsonObject)
        ?: throw InvalidPasskeyResponseException("The passkey response is missing \"$RESPONSE_KEY\".")

    val type = registration.requiredString(TYPE_KEY, PUBLIC_KEY_TYPE.length)
    if (type != PUBLIC_KEY_TYPE) {
        throw InvalidPasskeyResponseException("The passkey response \"$TYPE_KEY\" must be \"$PUBLIC_KEY_TYPE\".")
    }

    return buildMap {
        put(ID_KEY, registration.requiredString(ID_KEY, MAX_CREDENTIAL_ID_LENGTH))
        put(RAW_ID_KEY, registration.requiredString(RAW_ID_KEY, MAX_CREDENTIAL_ID_LENGTH))
        put(TYPE_KEY, type)
        put(
            RESPONSE_KEY,
            buildMap<String, Any> {
                put(CLIENT_DATA_JSON_KEY, response.requiredString(CLIENT_DATA_JSON_KEY, MAX_CLIENT_DATA_JSON_LENGTH, "$RESPONSE_KEY."))
                put(ATTESTATION_OBJECT_KEY, response.requiredString(ATTESTATION_OBJECT_KEY, MAX_ATTESTATION_OBJECT_LENGTH, "$RESPONSE_KEY."))
                response.transports()?.let { put(TRANSPORTS_KEY, it) }
                response.stringOrNull(AUTHENTICATOR_DATA_KEY)
                    ?.takeIf { it.isNotEmpty() && it.length <= MAX_AUTHENTICATOR_DATA_LENGTH }
                    ?.let { put(AUTHENTICATOR_DATA_KEY, it) }
                response.wholeNumberOrNull(PUBLIC_KEY_ALGORITHM_KEY)?.let { put(PUBLIC_KEY_ALGORITHM_KEY, it) }
                response.stringOrNull(PUBLIC_KEY_KEY)
                    ?.takeIf { it.isNotEmpty() && it.length <= MAX_PUBLIC_KEY_LENGTH }
                    ?.let { put(PUBLIC_KEY_KEY, it) }
            }
        )
        registration.stringOrNull(AUTHENTICATOR_ATTACHMENT_KEY)
            ?.takeIf { it in AUTHENTICATOR_ATTACHMENTS }
            ?.let { put(AUTHENTICATOR_ATTACHMENT_KEY, it) }
        (registration.get(CLIENT_EXTENSION_RESULTS_KEY) as? JsonObject)
            ?.takeIf { it.size() <= MAX_CLIENT_EXTENSION_RESULTS }
            ?.let { put(CLIENT_EXTENSION_RESULTS_KEY, it) }
    }
}

private fun JsonObject.transports(): List<String>? {
    val array = get(TRANSPORTS_KEY) as? JsonArray ?: return null
    if (array.size() > MAX_TRANSPORTS) return null
    val transports = array.map { element ->
        if (element.isJsonPrimitive && element.asJsonPrimitive.isString) element.asString else return null
    }
    return transports.takeIf { list -> list.all { it.length <= MAX_TRANSPORT_LENGTH } }
}

private fun JsonObject.wholeNumberOrNull(key: String): Long? {
    val element = get(key) ?: return null
    if (!element.isJsonPrimitive || !element.asJsonPrimitive.isNumber) return null
    val value = element.asBigDecimal
    return try {
        value.toBigIntegerExact().takeIf { it.bitLength() < LONG_BITS }?.toLong()
    } catch (e: ArithmeticException) {
        null
    }
}
