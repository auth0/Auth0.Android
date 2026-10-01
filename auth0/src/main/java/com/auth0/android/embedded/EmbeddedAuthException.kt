package com.auth0.android.embedded

import com.auth0.android.Auth0Exception

/**
 * Represents an error raised by Auth0's embedded authentication API.
 *
 * Branch on [error] with an exhaustive `when` to handle each case; read [code], [description],
 * and [statusCode] for diagnostics or to present specific messages.
 */
public class EmbeddedAuthException internal constructor(

    public val code: String,

    public val description: String,

    /** HTTP status code of the response, or `0` when no response was received. */
    public val statusCode: Int = 0,

    /** The typed classification of this error. */
    public val error: EmbeddedAuthError,

    internal val authSession: String? = null,

    cause: Throwable? = null
) : Auth0Exception(description, cause)
