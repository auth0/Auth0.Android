package com.auth0.android.request.kt

import java.io.Reader

/**
 * Converts from a Reader containing the JSON representation of the result
 * into the actual <T> instance.
 */
public interface JsonAdapter<T> {

    public fun fromJson(json: Reader): T

}

/**
 * Converts from a Reader containing the JSON representation of the error
 * into the actual <T> instance.
 * Alternatively, supports creating a new <T> instance passing a stacktrace.
 */
public interface ErrorAdapter<T> : JsonAdapter<T> {

    public fun fromException(err: Throwable): T
}