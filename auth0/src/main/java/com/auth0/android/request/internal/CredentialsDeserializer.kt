package com.auth0.android.request.internal

import androidx.annotation.VisibleForTesting
import com.auth0.android.result.Credentials
import com.google.gson.JsonDeserializationContext
import com.google.gson.JsonDeserializer
import com.google.gson.JsonElement
import com.google.gson.JsonParseException
import java.lang.reflect.Type
import java.util.*

internal open class CredentialsDeserializer : JsonDeserializer<Credentials> {
    @Throws(JsonParseException::class)
    override fun deserialize(
        json: JsonElement,
        typeOfT: Type,
        context: JsonDeserializationContext
    ): Credentials {
        if (!json.isJsonObject || json.isJsonNull || json.asJsonObject.entrySet().isEmpty()) {
            throw JsonParseException("credentials json is not a valid json object")
        }
        val jsonObject = json.asJsonObject
        val idToken = context.deserialize<String>(jsonObject.remove("id_token"), String::class.java)
        val accessToken =
            context.deserialize<String>(jsonObject.remove("access_token"), String::class.java)
        val type = context.deserialize<String>(jsonObject.remove("token_type"), String::class.java)
        val refreshToken =
            context.deserialize<String>(jsonObject.remove("refresh_token"), String::class.java)
        val expiresIn = context.deserialize<Long>(jsonObject.remove("expires_in"), Long::class.java)
        val scope = context.deserialize<String>(jsonObject.remove("scope"), String::class.java)
        val recoveryCode =
            context.deserialize<String>(jsonObject.remove("recovery_code"), String::class.java)
        var expiresAt = context.deserialize<Date>(jsonObject.remove("expires_at"), Date::class.java)
        if (expiresAt == null && expiresIn != null) {
            expiresAt = Date(currentTimeInMillis + expiresIn * 1000)
        }
        return createCredentials(
            idToken,
            accessToken,
            type,
            refreshToken,
            expiresAt,
            scope,
            recoveryCode
        )
    }

    @get:VisibleForTesting
    open val currentTimeInMillis: Long
        get() = System.currentTimeMillis()

    @VisibleForTesting
    open fun createCredentials(
        idToken: String,
        accessToken: String,
        type: String,
        refreshToken: String?,
        expiresAt: Date,
        scope: String?,
        recoveryCode: String?
    ): Credentials {
        val credentials = Credentials(
            idToken, accessToken, type, refreshToken, expiresAt, scope
        )
        credentials.recoveryCode = recoveryCode
        return credentials
    }
}