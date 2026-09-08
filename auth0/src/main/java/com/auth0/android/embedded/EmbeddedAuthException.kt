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

    /**
     * When the attempt is not finished ([isInsufficientAuthorization]), the menu of actions the
     * server will accept next; empty on terminal outcomes such as [isAccessDenied] or a network
     * failure. Switch on the entries to decide which [EmbeddedAuthClient] method to call next.
     */
    public val nextActions: List<NextAction> = emptyList(),

    /** The rotated session token; threaded into the next call by [EmbeddedAuthClient] automatically. */
    internal val authSession: String? = null,

    cause: Throwable? = null
) : Auth0Exception(description, cause) {

    public val isNetworkError: Boolean
        get() = cause is NetworkErrorException

    /**
     * The attempt isn't done — the server returned a continuation, not a failure. Read [nextActions]
     * for what to render or call next; the session token is threaded into the next call for you.
     */
    public val isInsufficientAuthorization: Boolean
        get() = code == INSUFFICIENT_AUTHORIZATION

    /**
     * Terminal — the attempt is over; do not retry. Inspect [description] for the server's reason
     * code (e.g. `consent_required` vs `too_many_wrong_otp_attempts`) to decide what to show.
     */
    public val isAccessDenied: Boolean
        get() = code == ACCESS_DENIED

    private companion object {
        private const val INSUFFICIENT_AUTHORIZATION = "insufficient_authorization"
        private const val ACCESS_DENIED = "access_denied"
    }
}
