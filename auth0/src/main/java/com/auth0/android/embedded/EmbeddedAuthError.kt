package com.auth0.android.embedded

import com.auth0.android.embedded.authorize.NextAction

/**
 * The typed classification of an [EmbeddedAuthException].
 *
 */
public sealed interface EmbeddedAuthError {

    /**
     * The flow is not complete and can continue: act on one of [nextActions].
     * Corresponds to `code == "insufficient_authorization"`.
     */
    public data class InsufficientAuthorization(
        public val nextActions: List<NextAction>
    ) : EmbeddedAuthError

    /** Terminal: too many wrong OTP submissions. Restart the flow. */
    public data object TooManyWrongOtpAttempts : EmbeddedAuthError

    /** Terminal: the OTP challenge expired before it was verified. Restart the flow. */
    public data object ChallengeExpired : EmbeddedAuthError

    /**
     * Terminal: access denied for a reason not modelled as its own case.
     * Read [EmbeddedAuthException.description] for specifics.
     */
    public data object AccessDenied : EmbeddedAuthError

    /** Terminal: rate-limited by attack protection . */
    public data object TooManyAttempts : EmbeddedAuthError

    /** Terminal: rate-limited by same-user-login protection. */
    public data object TooManyLogins : EmbeddedAuthError

    /**
     * Terminal: the grant being redeemed is no longer valid. Start a new flow with
     * [EmbeddedAuthClient.authorize].
     */
    public data object SessionExpired : EmbeddedAuthError

    /** The request never reached the server (`cause` is a network error). Retry the step. */
    public data object Network : EmbeddedAuthError

    /** Client-side guard: no flow is in progress. Call [EmbeddedAuthClient.authorize] first. */
    public data object NoActiveSession : EmbeddedAuthError

    /**
     * An error this version of the SDK does not classify. Read [EmbeddedAuthException.code] / [EmbeddedAuthException.description] /
     * [EmbeddedAuthException.statusCode] to diagnose.
     */
    public data object Unknown : EmbeddedAuthError
}
