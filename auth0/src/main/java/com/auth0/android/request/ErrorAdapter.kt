package com.auth0.android.request

import java.io.IOException
import java.io.Reader

/**
 * Adapter that converts from different sources into the <T> class that represents an error.
 */
public interface ErrorAdapter<T> {

    /**
     * Converts the JSON input given in the Reader to the <T> instance.
     * @param statusCode the response HTTP status code.
     * @param reader the reader that contains the JSON encoded string.
     * @throws IOException could be thrown to signal that the input was invalid.
     */
    @Throws(IOException::class)
    public fun fromJsonResponse(statusCode: Int, reader: Reader): T

    /**
     * Converts the raw input to a <T> instance.
     * @param statusCode the response HTTP status code.
     * @param bodyText the plain text received in the response body.
     * @param headers the response headers received.
     */
    public fun fromRawResponse(
        statusCode: Int,
        bodyText: String,
        headers: Map<String, List<String>>
    ): T

    /**
     * Constructs a <T> instance from the given stack trace.
     * @param cause the cause of this error.
     */
    public fun fromException(cause: Throwable): T
}