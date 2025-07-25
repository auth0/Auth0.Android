package com.auth0.android.request

import android.util.Log
import com.google.gson.Gson
import com.google.gson.annotations.SerializedName
import okhttp3.Response
import java.io.InputStreamReader

/**
 * A generic error body that can be returned by the Auth0 API.
 */
public data class ErrorBody(
    @SerializedName("error")
    val errorCode: String,
    @SerializedName("error_description")
    val description: String
)

/**
 * Extension method to parse [ErrorBody] from [Response]
 */
public fun Response.getErrorBody(): ErrorBody {
    return InputStreamReader(body?.byteStream(), Charsets.UTF_8).use { reader ->
        try {
            Gson().fromJson(reader, ErrorBody::class.java)
        } catch (error: Exception) {
            Log.e("ErrorBody", "Error parsing the error body ${error.stackTraceToString()}")
            return ErrorBody("", "")
        }
    }
}
