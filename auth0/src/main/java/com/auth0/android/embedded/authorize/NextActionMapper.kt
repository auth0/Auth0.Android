package com.auth0.android.embedded.authorize

private const val ACTION_KEY = "action"
private const val CHANNEL_KEY = "channel"
private const val IDENTIFIER_KEY = "identifier"
private const val INDEX_KEY = "index"

internal fun List<Map<String, Any>>.toNextActions(): List<NextAction> = mapNotNull { it.toNextAction() }

private fun Map<String, Any>.toNextAction(): NextAction? {
    val raw = this[ACTION_KEY] as? String ?: return null
    return when (EmbeddedAction.fromValue(raw)) {
        EmbeddedAction.IDENTIFY_EMAIL -> NextAction.IdentifyEmail
        EmbeddedAction.IDENTIFY_PHONE -> NextAction.IdentifyPhone
        EmbeddedAction.CHALLENGE_EMAIL -> NextAction.ChallengeEmail(
            index = (this[INDEX_KEY] as? Number)?.toInt() ?: 0,
            identifier = this[IDENTIFIER_KEY] as? String
        )
        EmbeddedAction.VERIFY_OTP -> NextAction.VerifyOtp(
            channel = this[CHANNEL_KEY] as? String,
            identifier = this[IDENTIFIER_KEY] as? String
        )
        EmbeddedAction.UNKNOWN -> NextAction.Unknown(raw)
    }
}
