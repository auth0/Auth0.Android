package com.auth0.android.embedded

/**
 * One way to continue the embedded-authentication loop, as reported on
 * [EmbeddedAuthException.nextActions]. When a step does not complete the flow, the server returns the menu
 * of actions that may come next; switch on the subtype to read what each one needs and which
 * [EmbeddedAuthClient] method acts on it.
 */
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

    /** Continue by requesting an email challenge. Act on it with [EmbeddedAuthClient.challenge]. */
    public data object ChallengeEmail : NextAction {
        override val action: EmbeddedAction = EmbeddedAction.CHALLENGE_EMAIL
    }

    /**
     * Continue by verifying a one-time code. Act on it with [EmbeddedAuthClient.verifyOtp].
     *
     * @param channel where the code was delivered — e.g. `sms`, `voice`, `email`, `totp` — when the
     * server reports it.
     * @param identifier the destination the code was sent to, when the server reports it.
     */
    @ConsistentCopyVisibility
    public data class VerifyOtp internal constructor(
        public val channel: String?,
        public val identifier: String?
    ) : NextAction {
        override val action: EmbeddedAction = EmbeddedAction.VERIFY_OTP
    }

    /**
     * An action the server offered that this version of the SDK does not model. Reported rather
     * than dropped, so the menu stays a truthful account of what the server said.
     *
     * @param rawAction the `action` string the server sent.
     */
    @ConsistentCopyVisibility
    public data class Unknown internal constructor(
        public val rawAction: String
    ) : NextAction {
        override val action: EmbeddedAction = EmbeddedAction.UNKNOWN
    }
}
