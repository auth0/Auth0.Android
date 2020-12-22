package com.auth0.android.request

import java.io.InputStream

/**
 * Contains the information received from the server after executing a network request.
 * @param statusCode the response HTTP status code.
 * @param body the response body stream.
 * @param headers the response headers received.
 */
public data class ServerResponse(
    val statusCode: Int,
    val body: InputStream,
    val headers: Map<String, List<String>>
) {
    /**
     * Checks if the status code is between 200 and 299.
     * @return whether this response was successful or not.
     */
    public fun isSuccess(): Boolean = statusCode in 200.until(300)

    /**
     * Checks if the Content-Type headers declare the received media type as 'application/json'.
     * @return whether this response contains a JSON body or not.
     */
    public fun isJson(): Boolean = headers["Content-Type"]?.contains("application/json") ?: false
}