package com.auth0.android.request.internal

import androidx.annotation.VisibleForTesting
import com.auth0.android.result.Credentials
import com.auth0.android.result.SSOCredentials
import com.auth0.android.result.UserProfile
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.reflect.TypeToken
import java.security.PublicKey
import java.util.*

internal object GsonProvider {
    internal val gson: Gson

    init {
        val jwksType = TypeToken.getParameterized(
            Map::class.java,
            String::class.java,
            PublicKey::class.java
        ).type
        gson = GsonBuilder()
            .registerTypeAdapterFactory(JsonRequiredTypeAdapterFactory())
            .registerTypeAdapter(UserProfile::class.java, UserProfileDeserializer())
            .registerTypeAdapter(Credentials::class.java, CredentialsDeserializer())
            .registerTypeAdapter(SSOCredentials::class.java, SSOCredentialsDeserializer())
            .registerTypeAdapter(jwksType, JwksDeserializer())
            .registerTypeAdapter(Date::class.java, DateTypeAdapter())
            .create()
    }

    @JvmStatic
    @VisibleForTesting
    fun formatDate(date: Date): String {
        return DateTypeAdapter.format(date)
    }
}
