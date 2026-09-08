package com.auth0.android.embedded

private const val ACTION_KEY = "action"
private const val CHANNEL_KEY = "channel"
private const val IDENTIFIER_KEY = "identifier"

/**
 * Translates the raw `next` array of an `insufficient_authorization` response into the public
 * [NextAction] menu. Entries without an `action` string are dropped; an action this SDK does not
 * model becomes [NextAction.Unknown], so the menu stays a faithful account of what the server sent.
 */
internal fun List<Map<String, Any>>.toNextActions(): List<NextAction> = mapNotNull { it.toNextAction() }

private fun Map<String, Any>.toNextAction(): NextAction? {
    val raw = this[ACTION_KEY] as? String ?: return null
    return when (EmbeddedAction.fromValue(raw)) {
        EmbeddedAction.IDENTIFY_EMAIL -> NextAction.IdentifyEmail
        EmbeddedAction.IDENTIFY_PHONE -> NextAction.IdentifyPhone
        EmbeddedAction.CHALLENGE_EMAIL -> NextAction.ChallengeEmail
        EmbeddedAction.VERIFY_OTP -> NextAction.VerifyOtp(
            channel = this[CHANNEL_KEY] as? String,
            identifier = this[IDENTIFIER_KEY] as? String
        )
        EmbeddedAction.UNKNOWN -> NextAction.Unknown(raw)
    }
}
