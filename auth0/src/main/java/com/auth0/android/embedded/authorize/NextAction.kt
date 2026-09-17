package com.auth0.android.embedded.authorize

import com.auth0.android.embedded.EmbeddedAuthClient
import com.auth0.android.embedded.EmbeddedAuthException

/** One way to continue the embedded authentication flow, as reported on [EmbeddedAuthException.nextActions]. */
public sealed interface NextAction {

    public val action: EmbeddedAction

    /** Continue by submitting an email address. Act on it with [EmbeddedAuthClient.identifyEmail]. */
    public data object IdentifyEmail : NextAction {
        override val action: EmbeddedAction = EmbeddedAction.IDENTIFY_EMAIL
    }

    /** Continue by submitting a phone number. Act on it with [EmbeddedAuthClient.identifyPhone]. */
    public data object IdentifyPhone : NextAction {
        override val action: EmbeddedAction = EmbeddedAction.IDENTIFY_PHONE
    }

    /** Continue by requesting an email challenge. Act on it with [EmbeddedAuthClient.challengeEmail]. */
    @ConsistentCopyVisibility
    public data class ChallengeEmail internal constructor(
        public val index: Int?,
        public val identifier: String?
    ) : NextAction {
        override val action: EmbeddedAction = EmbeddedAction.CHALLENGE_EMAIL
    }

    /** Continue by verifying a one-time code. Act on it with [EmbeddedAuthClient.verifyOtp]. */
    @ConsistentCopyVisibility
    public data class VerifyOtp internal constructor(
        public val channel: String?,
        public val identifier: String?
    ) : NextAction {
        override val action: EmbeddedAction = EmbeddedAction.VERIFY_OTP
    }

    /** An action the server offered that this version of the SDK does not model. */
    @ConsistentCopyVisibility
    public data class Unknown internal constructor(
        public val rawAction: String
    ) : NextAction {
        override val action: EmbeddedAction = EmbeddedAction.UNKNOWN
    }
}
