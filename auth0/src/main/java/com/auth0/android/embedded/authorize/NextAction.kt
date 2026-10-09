package com.auth0.android.embedded.authorize

import com.auth0.android.embedded.EmbeddedAuthClient
import com.auth0.android.embedded.EmbeddedAuthException

/** One way to continue the embedded authentication flow, as reported on [EmbeddedAuthException.nextActions]. */
public sealed interface NextAction {

    public val capability: EmbeddedCapability

    /** Continue by submitting an email address. Act on it with [EmbeddedAuthClient.identify]. */
    public data object IdentifyEmail : NextAction {
        override val capability: EmbeddedCapability = EmbeddedCapability.IDENTIFY_EMAIL
    }

    /** Continue by submitting a phone number. */
    public data object IdentifyPhone : NextAction {
        override val capability: EmbeddedCapability = EmbeddedCapability.IDENTIFY_PHONE
    }

    /** Continue by submitting a username. Act on it with [EmbeddedAuthClient.identify]. */
    public data object IdentifyUsername : NextAction {
        override val capability: EmbeddedCapability = EmbeddedCapability.IDENTIFY_USERNAME
    }

    /** Continue by verifying the user's password. Act on it with [EmbeddedAuthClient.verifyPassword]. */
    public data object VerifyPassword : NextAction {
        override val capability: EmbeddedCapability = EmbeddedCapability.VERIFY_PASSWORD
    }

    /** Continue by requesting an email challenge. Act on it with [EmbeddedAuthClient.challengeEmail]. */
    @ConsistentCopyVisibility
    public data class ChallengeEmail internal constructor(
        public val index: Int,
        public val identifier: String
    ) : NextAction {
        override val capability: EmbeddedCapability = EmbeddedCapability.CHALLENGE_EMAIL
    }

    /** Continue by verifying a one-time code. Act on it with [EmbeddedAuthClient.verifyOtp]. */
    @ConsistentCopyVisibility
    public data class VerifyOtp internal constructor(
        public val channel: OtpChannel,
        public val identifier: String?
    ) : NextAction {
        override val capability: EmbeddedCapability = EmbeddedCapability.VERIFY_OTP
    }

    /** Continue by challenging a phone factor. Act on it with [EmbeddedAuthClient.challengePhone]. */
    @ConsistentCopyVisibility
    public data class ChallengePhone internal constructor(
        public val index: Int,
        public val identifier: String,
        public val deliveryMethods: List<PhoneDeliveryMethod>,
    ) : NextAction {
        override val capability: EmbeddedCapability = EmbeddedCapability.CHALLENGE_PHONE
    }

    /** Continue by challenging a push notification factor. Act on it with [EmbeddedAuthClient.challengePush]. */
    @ConsistentCopyVisibility
    public data class ChallengePush internal constructor(
        public val index: Int,
        public val name: String,
    ) : NextAction {
        override val capability: EmbeddedCapability = EmbeddedCapability.CHALLENGE_PUSH
    }

    /** Continue by verifying an out-of-band (push) notification. Act on it with [EmbeddedAuthClient.verifyOob]. */
    @ConsistentCopyVisibility
    public data class VerifyOob internal constructor(
        public val pollInMs: Int,
    ) : NextAction {
        override val capability: EmbeddedCapability = EmbeddedCapability.VERIFY_OOB
    }

    /** Continue by verifying a recovery code. Act on it with [EmbeddedAuthClient.verifyRecoveryCode]. */
    public data object VerifyRecoveryCode : NextAction {
        override val capability: EmbeddedCapability = EmbeddedCapability.VERIFY_RECOVERY_CODE
    }

    /** Continue by confirming a recovery code after verification. Act on it with [EmbeddedAuthClient.confirmRecoveryCode]. */
    @ConsistentCopyVisibility
    public data class ConfirmRecoveryCode internal constructor(
        public val newCode: String,
    ) : NextAction {
        override val capability: EmbeddedCapability = EmbeddedCapability.CONFIRM_RECOVERY_CODE
    }

    /** An action the server offered that this version of the SDK does not model. */
    @ConsistentCopyVisibility
    public data class Unknown internal constructor(
        public val rawAction: String
    ) : NextAction {
        override val capability: EmbeddedCapability = EmbeddedCapability.UNKNOWN
    }
}
