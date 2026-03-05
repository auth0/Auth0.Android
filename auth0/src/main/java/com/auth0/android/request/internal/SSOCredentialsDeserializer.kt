package com.auth0.android.request.internal

import androidx.annotation.VisibleForTesting
import com.auth0.android.result.SSOCredentials
import com.google.gson.JsonDeserializationContext
import com.google.gson.JsonDeserializer
import com.google.gson.JsonElement
import com.google.gson.JsonParseException
import java.lang.reflect.Type
import java.util.Date

internal open class SSOCredentialsDeserializer : JsonDeserializer<SSOCredentials> {
    @Throws(JsonParseException::class)
    override fun deserialize(
        json: JsonElement,
        typeOfT: Type,
        context: JsonDeserializationContext
    ): SSOCredentials {
        if (!json.isJsonObject || json.isJsonNull || json.asJsonObject.entrySet().isEmpty()) {
            throw JsonParseException("sso credentials json is not a valid json object")
        }
        val jsonObject = json.asJsonObject
        val sessionTransferToken =
            context.deserialize<String>(jsonObject.remove("access_token"), String::class.java)
        val idToken =
            context.deserialize<String>(jsonObject.remove("id_token"), String::class.java)
        val issuedTokenType =
            context.deserialize<String>(jsonObject.remove("issued_token_type"), String::class.java)
        val tokenType =
            context.deserialize<String>(jsonObject.remove("token_type"), String::class.java)
        val expiresIn =
            context.deserialize<Long>(jsonObject.remove("expires_in"), Long::class.java)
        val refreshToken =
            context.deserialize<String>(jsonObject.remove("refresh_token"), String::class.java)

        var expiresInDate: Date?
        if (expiresIn != null) {
            expiresInDate = Date(currentTimeInMillis + expiresIn * 1000)
        } else {
            throw JsonParseException("Missing the required property expires_in")
        }

        return createSSOCredentials(
            sessionTransferToken,
            idToken,
            issuedTokenType,
            tokenType,
            expiresInDate!!,
            refreshToken
        )
    }

    @get:VisibleForTesting
    open val currentTimeInMillis: Long
        get() = System.currentTimeMillis()

    @VisibleForTesting
    open fun createSSOCredentials(
        sessionTransferToken: String,
        idToken: String,
        issuedTokenType: String,
        tokenType: String,
        expiresIn: Date,
        refreshToken: String?
    ): SSOCredentials {
        return SSOCredentials(
            sessionTransferToken, idToken, issuedTokenType, tokenType, expiresIn, refreshToken
        )
    }
}
