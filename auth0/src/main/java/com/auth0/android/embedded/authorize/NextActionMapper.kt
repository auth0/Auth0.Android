package com.auth0.android.embedded.authorize

import android.util.Log

private const val TAG = "NextActionMapper"

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
        EmbeddedAction.CHALLENGE_EMAIL -> {
            val index = (this[INDEX_KEY] as? Number)?.toInt() ?: return dropped(raw, INDEX_KEY)
            val identifier = this[IDENTIFIER_KEY] as? String ?: return dropped(raw, IDENTIFIER_KEY)
            NextAction.ChallengeEmail(index = index, identifier = identifier)
        }
        EmbeddedAction.VERIFY_OTP -> {
            val channel = OtpChannel.fromValue(this[CHANNEL_KEY] as? String)
                ?: return dropped(raw, CHANNEL_KEY)
            NextAction.VerifyOtp(
                channel = channel,
                identifier = this[IDENTIFIER_KEY] as? String
            )
        }
        EmbeddedAction.UNKNOWN -> NextAction.Unknown(raw)
    }
}

/**
 * Logs and drops a recognised next action whose required [field] the server omitted or sent
 * malformed. Returns `null` so the entry is filtered out by [toNextActions].
 */
private fun dropped(action: String, field: String): NextAction? {
    Log.w(TAG, "Dropping \"$action\" next action: required field \"$field\" was missing or invalid.")
    return null
}
