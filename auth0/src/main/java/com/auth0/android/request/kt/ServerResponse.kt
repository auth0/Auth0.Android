package com.auth0.android.request.kt

import java.io.InputStream

/**
 * Holder for the information required to configure a request
 */
public data class ServerResponse(
    val statusCode: Int,
    val body: InputStream,
    val headers: Map<String, List<String>>
) {
    public fun isSuccess(): Boolean = statusCode in 200.until(300)
    public fun isJson(): Boolean = headers["Content-Type"]?.contains("application/json") ?: false
}