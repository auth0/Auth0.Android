package com.auth0.android.request.kt

import com.auth0.android.Auth0Exception
import com.auth0.android.authentication.AuthenticationException
import com.google.gson.Gson
import com.google.gson.TypeAdapter
import com.google.gson.reflect.TypeToken
import java.io.Reader

/**
 * Temporary class that parses key/value responses into proper Errors
 */
internal class DefaultErrorBuilder(gson: Gson) : ErrorBuilder<AuthenticationException> {

    private var mapAdapter: TypeAdapter<Map<String, Any>>

    init {
        val mapType = object : TypeToken<Map<String, Any>>() {}
        mapAdapter = gson.getAdapter(mapType)
    }

    override fun fromJson(reader: Reader): AuthenticationException {
        val parsed = mapAdapter.fromJson(reader)
        return AuthenticationException(parsed)
    }

    override fun fromException(message: String, exception: Exception): AuthenticationException {
        return AuthenticationException(message, Auth0Exception("Err", exception))
    }

}