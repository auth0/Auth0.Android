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
private const val IDENTIFIERS_KEY = "identifiers"
private const val EMAIL_KEY = "email"
private const val PHONE_NUMBER_KEY = "phone_number"
private const val REQUIRED_KEY = "required"

internal fun List<Map<String, Any>>.toNextActions(): List<NextAction> = mapNotNull { it.toNextAction() }

private fun Map<String, Any>.toNextAction(): NextAction? {
    val raw = this[ACTION_KEY] as? String ?: return null
    return when (EmbeddedCapability.fromValue(raw)) {
        EmbeddedCapability.IDENTIFY_EMAIL -> NextAction.IdentifyEmail
        EmbeddedCapability.IDENTIFY_PHONE -> NextAction.IdentifyPhone
        EmbeddedCapability.IDENTIFY_USERNAME -> NextAction.IdentifyUsername
        EmbeddedCapability.VERIFY_PASSWORD -> NextAction.VerifyPassword
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
            val deliveryMethods = (this[DELIVERY_METHODS_KEY] as? List<*>)
                ?.filterIsInstance<String>()
                ?.mapNotNull(PhoneDeliveryMethod::fromValue)
                ?: return dropped(raw, DELIVERY_METHODS_KEY)
            NextAction.ChallengePhone(index, identifier, deliveryMethods)
        }
        EmbeddedCapability.CHALLENGE_PUSH -> {
            val index = (this[INDEX_KEY] as? Number)?.toInt() ?: return dropped(raw, INDEX_KEY)
            val name = this[NAME_KEY] as? String ?: return dropped(raw, NAME_KEY)
            NextAction.ChallengePush(index, name)
        }
        EmbeddedCapability.VERIFY_OOB -> {
            val pollInMs = (this[POLL_IN_MS_KEY] as? Number)?.toInt()
                ?: return dropped(raw, POLL_IN_MS_KEY)
            NextAction.VerifyOob(pollInMs)
        }
        EmbeddedCapability.VERIFY_RECOVERY_CODE -> NextAction.VerifyRecoveryCode
        EmbeddedCapability.CONFIRM_RECOVERY_CODE -> {
            val newCode = this[NEW_CODE_KEY] as? String ?: return dropped(raw, NEW_CODE_KEY)
            NextAction.ConfirmRecoveryCode(newCode)
        }
        EmbeddedCapability.SIGNUP -> {
            val identifiers = (this[IDENTIFIERS_KEY] as? Map<*, *>)?.toSignupIdentifiers()
                ?: return dropped(raw, IDENTIFIERS_KEY)
            NextAction.Signup(identifiers)
        }
        EmbeddedCapability.CONFIRM_SIGNUP -> NextAction.ConfirmSignup
        EmbeddedCapability.UNKNOWN -> NextAction.Unknown(raw)
    }
}

/**
 * Reads the signup `identifiers` object, ignoring keys this SDK doesn't model. Returns `null` when it
 * offers no identifier, or when an offered identifier is missing its boolean `required` flag.
 */
private fun Map<*, *>.toSignupIdentifiers(): List<SignupIdentifier>? {
    val identifiers = SIGNUP_IDENTIFIER_TYPES.mapNotNull { (key, type) ->
        if (!containsKey(key)) return@mapNotNull null
        val required = (this[key] as? Map<*, *>)?.get(REQUIRED_KEY) as? Boolean ?: return null
        SignupIdentifier(type, required)
    }
    return identifiers.ifEmpty { null }
}

private val SIGNUP_IDENTIFIER_TYPES: List<Pair<String, IdentifierType>> = listOf(
    EMAIL_KEY to IdentifierType.EMAIL,
    PHONE_NUMBER_KEY to IdentifierType.PHONE
)

/**
 * Logs and drops a recognized next action whose required [field] the server omitted or sent
 * malformed. Returns `null` so the entry is filtered out by [toNextActions].
 */
private fun dropped(action: String, field: String): NextAction? {
    Log.w(TAG, "Dropping \"$action\" next action: required field \"$field\" was missing or invalid.")
    return null
}
