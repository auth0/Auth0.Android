package com.auth0.android.request.kt

import com.auth0.android.Auth0Exception
import com.auth0.android.authentication.AuthenticationException
import com.google.gson.Gson
import com.google.gson.TypeAdapter
import com.google.gson.reflect.TypeToken
import java.io.Reader

internal class DefaultErrorBuilder<out U : Auth0Exception>(gson: Gson) : ErrorBuilder<U> {

    private var mapAdapter: TypeAdapter<Map<String, Any>>

    init {
        val mapType = object : TypeToken<Map<String, Any>>() {}
        mapAdapter = gson.getAdapter(mapType)
    }

    override fun fromJson(reader: Reader): U {
        val parsed = mapAdapter.fromJson(reader)
        //FIXME: UNchecked cast below
        return AuthenticationException(parsed) as U
    }

    override fun fromException(message: String, exception: Exception): U {
        //FIXME: UNchecked cast below
        return AuthenticationException(message, Auth0Exception("Err", exception)) as U
    }

}