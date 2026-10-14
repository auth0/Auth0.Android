package com.auth0.android.request.internal

import com.auth0.android.result.AuthnParamsPublicKey
import com.auth0.android.result.PasskeyRegistrationChallenge
import com.auth0.android.result.PasskeyVerificationMethod
import com.google.gson.JsonDeserializationContext
import com.google.gson.JsonDeserializer
import com.google.gson.JsonElement
import com.google.gson.JsonParseException
import com.google.gson.reflect.TypeToken
import java.lang.reflect.Type

/**
 * Gson skips Kotlin default values for fields missing from the JSON, which would leave
 * `verificationRequired` as `null`. This builds the challenge through its constructor instead, so
 * the field is an empty list when the server omits `verification_required`.
 */
internal class PasskeyRegistrationChallengeDeserializer :
    JsonDeserializer<PasskeyRegistrationChallenge> {

    @Throws(JsonParseException::class)
    override fun deserialize(
        json: JsonElement,
        typeOfT: Type,
        context: JsonDeserializationContext
    ): PasskeyRegistrationChallenge {
        if (!json.isJsonObject) {
            throw JsonParseException("passkey registration challenge json is not a valid json object")
        }
        val jsonObject = json.asJsonObject
        val authSession = context.deserialize<String?>(jsonObject.get(AUTH_SESSION), String::class.java)
            ?: throw JsonParseException("Missing the required property $AUTH_SESSION")
        val authParamsPublicKey = context.deserialize<AuthnParamsPublicKey?>(
            jsonObject.get(AUTHN_PARAMS_PUBLIC_KEY),
            AuthnParamsPublicKey::class.java
        ) ?: throw JsonParseException("Missing the required property $AUTHN_PARAMS_PUBLIC_KEY")
        val verificationRequired = context.deserialize<List<PasskeyVerificationMethod>?>(
            jsonObject.get(VERIFICATION_REQUIRED),
            VERIFICATION_LIST_TYPE
        ) ?: emptyList()

        return PasskeyRegistrationChallenge(authSession, authParamsPublicKey, verificationRequired)
    }

    private companion object {
        private const val AUTH_SESSION = "auth_session"
        private const val AUTHN_PARAMS_PUBLIC_KEY = "authn_params_public_key"
        private const val VERIFICATION_REQUIRED = "verification_required"
        private val VERIFICATION_LIST_TYPE: Type =
            object : TypeToken<List<PasskeyVerificationMethod>>() {}.type
    }
}
