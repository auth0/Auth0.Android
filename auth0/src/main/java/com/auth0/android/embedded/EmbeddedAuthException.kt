package com.auth0.android.embedded

import com.auth0.android.Auth0Exception
import com.auth0.android.NetworkErrorException

/**
 * Represents an error raised by Auth0's embedded authentication API.
 */
public class EmbeddedAuthException internal constructor(

    public val code: String,

    public val description: String,

    /** HTTP status code of the response, or `0` when no response was received. */
    public val statusCode: Int = 0,

    cause: Throwable? = null
) : Auth0Exception(description, cause) {

    public val isNetworkError: Boolean
        get() = cause is NetworkErrorException
}
