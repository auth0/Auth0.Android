package com.auth0.android.request.kt

import com.auth0.android.request.internal.GsonProvider
import com.google.gson.Gson
import com.google.gson.TypeAdapter
import com.google.gson.reflect.TypeToken
import java.io.Reader

/**
 * Implementation that deserializes <T> using the given Gson client.
 */
internal class GsonAdapter<T> private constructor(private val adapter: TypeAdapter<T>) :
    JsonAdapter<T> {

    internal companion object {
        fun forMap(gson: Gson = supplyDefaultGson()): GsonAdapter<Map<String, Any>> {
            return GsonAdapter(object : TypeToken<Map<String, Any>>() {}, gson)
        }

        @Suppress("UNCHECKED_CAST")
        fun <T> forMapOf(
            tClass: Class<T>,
            gson: Gson = supplyDefaultGson()
        ): GsonAdapter<Map<String, T>> {
            val typeToken: TypeToken<Map<String, T>> =
                TypeToken.getParameterized(
                    Map::class.java,
                    String::class.java,
                    tClass
                ) as TypeToken<Map<String, T>>
            return GsonAdapter(typeToken, gson)
        }

        @Suppress("UNCHECKED_CAST")
        fun <T> forListOf(
            tClass: Class<T>,
            gson: Gson = supplyDefaultGson()
        ): GsonAdapter<List<T>> {
            val typeToken: TypeToken<List<T>> =
                TypeToken.getParameterized(List::class.java, tClass) as TypeToken<List<T>>
            return GsonAdapter(typeToken, gson)
        }

        private fun supplyDefaultGson() = GsonProvider.buildGson()
    }

    internal constructor(
        tClass: Class<T>,
        gson: Gson = supplyDefaultGson()
    ) : this(gson.getAdapter(tClass))

    internal constructor(
        tTypeToken: TypeToken<T>,
        gson: Gson = supplyDefaultGson()
    ) : this(gson.getAdapter(tTypeToken))

    override fun fromJson(reader: Reader): T {
        return adapter.fromJson(reader)
    }
}