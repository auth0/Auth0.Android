package com.auth0.android.embedded

import com.auth0.android.Auth0Exception
import com.auth0.android.NetworkErrorException
import com.auth0.android.embedded.authorize.NextAction

/**
 * Represents an error raised by Auth0's embedded authentication API.
 */
public class EmbeddedAuthException internal constructor(

    public val code: String,

    public val description: String,

    /** HTTP status code of the response, or `0` when no response was received. */
    public val statusCode: Int = 0,

    /** When the attempt is not finished, the menu of actions the server will accept next. */
    public val nextActions: List<NextAction> = emptyList(),

    internal val authSession: String? = null,

    cause: Throwable? = null
) : Auth0Exception(description, cause) {

    public val isNetworkError: Boolean
        get() = cause is NetworkErrorException

    /** The attempt isn't done: the server returned a continuation. Read [nextActions] for what to call next. */
    public val isInsufficientAuthorization: Boolean
        get() = code == INSUFFICIENT_AUTHORIZATION

    /** Terminal: the attempt was denied and must not be retried. */
    public val isAccessDenied: Boolean
        get() = code == ACCESS_DENIED

    /** Terminal: too many failed verification attempts. */
    public val isTooManyAttempts: Boolean
        get() = statusCode == TOO_MANY_REQUESTS_STATUS &&
            code == TOO_MANY_REQUESTS && description == TOO_MANY_ATTEMPTS

    /** Terminal: too many login attempts. */
    public val isTooManyLogins: Boolean
        get() = statusCode == TOO_MANY_REQUESTS_STATUS &&
            code == TOO_MANY_REQUESTS && description == TOO_MANY_LOGINS

    private companion object {
        private const val INSUFFICIENT_AUTHORIZATION = "insufficient_authorization"
        private const val ACCESS_DENIED = "access_denied"
        private const val TOO_MANY_REQUESTS = "too_many_requests"
        private const val TOO_MANY_ATTEMPTS = "too_many_attempts"
        private const val TOO_MANY_LOGINS = "too_many_logins"
        private const val TOO_MANY_REQUESTS_STATUS = 429
    }
}
