package com.auth0.android.request.internal

import com.auth0.android.result.Credentials
import com.auth0.android.result.UserProfile
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.reflect.TypeToken
import java.security.PublicKey

internal object GsonProvider {
    internal val gson: Gson
    internal val credentialsGson: Gson

    init {
        val jwksType = TypeToken.getParameterized(
            Map::class.java,
            String::class.java,
            PublicKey::class.java
        ).type
        gson = GsonBuilder()
            .registerTypeAdapterFactory(JsonRequiredTypeAdapterFactory())
            .registerTypeAdapter(UserProfile::class.java, UserProfileDeserializer())
            .registerTypeAdapter(jwksType, JwksDeserializer())
            .create()

        // Credentials are stored as ISO 8601 UTC dates (with the `Z` suffix that indicates UTC)
        // But need to be interpreted as local dates for backwards compatibility.
        // So they have their own Gson instance with their own DateFormat which quotes the
        // `Z` suffix so that it's ignored when being deserialized to interpret the Date as local.
        credentialsGson = GsonBuilder()
            .registerTypeAdapter(Credentials::class.java, CredentialsDeserializer())
            .setDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
            .create()
    }

}