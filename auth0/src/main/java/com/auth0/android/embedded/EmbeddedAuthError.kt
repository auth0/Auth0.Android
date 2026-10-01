package com.auth0.android.embedded

import com.auth0.android.embedded.authorize.NextAction

/**
 * The typed classification of an [EmbeddedAuthException].
 *
 */
public sealed interface EmbeddedAuthError {

    /**
     * The flow is not complete and can continue: act on one of [nextActions].
     * Corresponds to `code == "insufficient_authorization"`. [reason] reports why the
     * previous step's input was rejected, when the server says so.
     */
    public data class InsufficientAuthorization(
        public val nextActions: List<NextAction>,
        public val reason: Reason
    ) : EmbeddedAuthError {

        public enum class Reason {
            /**  a plain step-forward continuation. */
            NONE,

            /** The submitted one-time code was invalid. */
            INVALID_CODE,

            /** The identifier or the code was invalid; the server does not say which. */
            INVALID_IDENTIFIER_OR_CODE
        }
    }

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

    /**
     * Terminal: the request was malformed (`code == "invalid_request"`).Read [EmbeddedAuthException.description] for
     * specifics, fix the request, and start a new flow with [EmbeddedAuthClient.authorize].
     */
    public data object InvalidRequest : EmbeddedAuthError

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
