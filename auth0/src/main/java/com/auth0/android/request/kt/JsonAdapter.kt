package com.auth0.android.request.kt

import java.io.IOException
import java.io.Reader

/**
 * Converts from a Reader containing the JSON representation of the result
 * into the actual <T> instance.
 */
public interface JsonAdapter<T> {

    @Throws(IOException::class)
    public fun fromJson(reader: Reader): T

}

/**
 * Converts from a Reader containing the JSON representation of the error
 * into the actual <T> instance.
 * Alternatively, supports creating a new <T> instance passing a stacktrace.
 */
public interface ErrorAdapter<T> {

    @Throws(IOException::class)
    public fun fromJsonResponse(statusCode: Int, reader: Reader): T
    public fun fromRawResponse(statusCode: Int, bodyText: String, headers: Map<String, List<String>>): T
    public fun fromException(err: Throwable): T
}