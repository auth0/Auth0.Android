package com.auth0.android.embedded.authorize

import android.util.Log

private const val TAG = "NextActionMapper"

private const val ACTION_KEY = "action"
private const val CHANNEL_KEY = "channel"
private const val IDENTIFIER_KEY = "identifier"
private const val INDEX_KEY = "index"
private const val DELIVERY_METHODS_KEY = "delivery_methods"
private const val POLL_IN_MS_KEY = "poll_in_ms"
private const val NAME_KEY = "name"
private const val NEW_CODE_KEY = "new_code"

internal fun List<Map<String, Any>>.toNextActions(): List<NextAction> = mapNotNull { it.toNextAction() }

private fun Map<String, Any>.toNextAction(): NextAction? {
    val raw = this[ACTION_KEY] as? String ?: return null
    return when (EmbeddedCapability.fromValue(raw)) {
        EmbeddedCapability.IDENTIFY_EMAIL -> NextAction.IdentifyEmail
        EmbeddedCapability.IDENTIFY_PHONE -> NextAction.IdentifyPhone
        EmbeddedCapability.CHALLENGE_EMAIL -> {
            val index = (this[INDEX_KEY] as? Number)?.toInt() ?: return dropped(raw, INDEX_KEY)
            val identifier = this[IDENTIFIER_KEY] as? String ?: return dropped(raw, IDENTIFIER_KEY)
            NextAction.ChallengeEmail(index = index, identifier = identifier)
        }
        EmbeddedCapability.VERIFY_OTP -> {
            val channel = OtpChannel.fromValue(this[CHANNEL_KEY] as? String)
                ?: return dropped(raw, CHANNEL_KEY)
            NextAction.VerifyOtp(
                channel = channel,
                identifier = this[IDENTIFIER_KEY] as? String
            )
        }
        EmbeddedCapability.CHALLENGE_PHONE -> {
            val index = (this[INDEX_KEY] as? Number)?.toInt() ?: return dropped(raw, INDEX_KEY)
            val identifier = this[IDENTIFIER_KEY] as? String ?: return dropped(raw, IDENTIFIER_KEY)
            @Suppress("UNCHECKED_CAST")
            val rawDeliveryMethods = this[DELIVERY_METHODS_KEY] as? List<String> ?: emptyList()
            val deliveryMethods = rawDeliveryMethods.mapNotNull {
                when (it) {
                    PhoneDeliveryMethod.TEXT.value -> PhoneDeliveryMethod.TEXT
                    PhoneDeliveryMethod.VOICE.value -> PhoneDeliveryMethod.VOICE
                    else -> null
                }
            }
            NextAction.ChallengePhone(index, identifier, deliveryMethods)
        }
        EmbeddedCapability.CHALLENGE_PUSH -> {
            val index = (this[INDEX_KEY] as? Number)?.toInt() ?: return dropped(raw, INDEX_KEY)
            val name = this[NAME_KEY] as? String
            NextAction.ChallengePush(index, name)
        }
        EmbeddedCapability.VERIFY_OOB -> {
            val pollInMs = (this[POLL_IN_MS_KEY] as? Number)?.toInt()
            if (pollInMs == null) null else NextAction.VerifyOob(pollInMs)
        }
        EmbeddedCapability.VERIFY_RECOVERY_CODE -> NextAction.VerifyRecoveryCode
        EmbeddedCapability.CONFIRM_RECOVERY_CODE -> {
            val newCode = this[NEW_CODE_KEY] as? String ?: return dropped(raw, NEW_CODE_KEY)
            NextAction.ConfirmRecoveryCode(newCode)
        }
        EmbeddedCapability.UNKNOWN -> NextAction.Unknown(raw)
    }
}

/**
 * Logs and drops a recognized next action whose required [field] the server omitted or sent
 * malformed. Returns `null` so the entry is filtered out by [toNextActions].
 */
private fun dropped(action: String, field: String): NextAction? {
    Log.w(TAG, "Dropping \"$action\" next action: required field \"$field\" was missing or invalid.")
    return null
}
