package com.auth0.android.request.internal

import androidx.annotation.VisibleForTesting
import com.auth0.android.result.Credentials
import com.auth0.android.result.UserProfile
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.reflect.TypeToken
import java.security.PublicKey
import java.text.SimpleDateFormat
import java.util.*

internal object GsonProvider {
    internal val gson: Gson
    internal val credentialsGson: Gson
    private var sdf: SimpleDateFormat
    private const val DATE_FORMAT = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"

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

        credentialsGson = GsonBuilder()
            .registerTypeAdapter(Credentials::class.java, CredentialsDeserializer())
            .setDateFormat(DATE_FORMAT)
            .create()
        sdf = SimpleDateFormat(DATE_FORMAT, Locale.US)
    }

    @JvmStatic
    @VisibleForTesting
    fun formatDate(date: Date): String {
        return sdf.format(date)
    }
}