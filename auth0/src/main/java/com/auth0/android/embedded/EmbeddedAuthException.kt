package com.auth0.android.embedded

import com.auth0.android.Auth0Exception
import com.auth0.android.NetworkErrorException

/**
 * Represents an error raised by Auth0's embedded authentication API.
 *
 * [code] and [description] carry the `error` and `error_description` values of the response. When
 * the failure produced no such body — a network error, or a response that was not JSON — [code] is
 * one of the `a0.sdk.internal_error.*` constants declared on [Auth0Exception], and [statusCode] is
 * the only indication of what went wrong.
 */
public class EmbeddedAuthException internal constructor(
    /**
     * The `error` value from the response body. The API pins one value per response, so this is safe
     * to branch on: `invalid_request`, `invalid_client` or `server_error`.
     */
    public val code: String,

    /**
     * The `error_description` value from the response body. Human readable and owned by the server:
     * show it or log it, but do not branch on it.
     */
    public val description: String,

    /** HTTP status code of the response, or `0` when no response was received. */
    public val statusCode: Int = 0,

    cause: Throwable? = null
) : Auth0Exception(description, cause) {

    /** Whether the request failed before reaching Auth0, rather than being rejected by it. */
    public val isNetworkError: Boolean
        get() = cause is NetworkErrorException
}
