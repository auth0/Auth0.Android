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
            INVALID_IDENTIFIER_OR_CODE,

            /** The username or the password was invalid; the server does not say which. */
            INVALID_IDENTIFIER_OR_PASSWORD,

            /** Authorization is pending (e.g., push notification awaiting user approval). Retry after a delay. */
            AUTHORIZATION_PENDING,

            /** The app is polling too fast. Back off and retry with a longer delay. */
            SLOW_DOWN
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

    /** Terminal: the user rejected or canceled the authorization (e.g., denied a push notification). */
    public data object AuthorizationRejected : EmbeddedAuthError

    /** Terminal: no eligible factors are available for the user. Enroll factors and retry the flow. */
    public data object NoEligibleFactors : EmbeddedAuthError

    /** Terminal: additional consent is required before the flow can proceed. */
    public data object ConsentRequired : EmbeddedAuthError

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
