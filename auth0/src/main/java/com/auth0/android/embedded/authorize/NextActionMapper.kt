package com.auth0.android.embedded.authorize

import android.util.Log
import com.auth0.android.embedded.passkey.PasskeyRequestOptions
import com.auth0.android.embedded.passkey.UserVerification
import com.auth0.android.request.internal.GsonProvider

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
private const val AUTHN_PARAMS_PUBLIC_KEY_KEY = "authn_params_public_key"
private const val CHALLENGE_KEY = "challenge"
private const val TIMEOUT_KEY = "timeout"
private const val RP_ID_KEY = "rpId"
private const val USER_VERIFICATION_KEY = "userVerification"
private const val HINTS_KEY = "hints"
private const val ALLOW_CREDENTIALS_KEY = "allowCredentials"

internal fun List<Map<String, Any>>.toNextActions(): List<NextAction> = mapNotNull { it.toNextAction() }

private fun Map<String, Any>.toNextAction(): NextAction? {
    val raw = this[ACTION_KEY] as? String ?: return null
    return when (EmbeddedCapability.fromValue(raw)) {
        EmbeddedCapability.IDENTIFY_EMAIL -> NextAction.IdentifyEmail
        EmbeddedCapability.IDENTIFY_PHONE -> NextAction.IdentifyPhone
        EmbeddedCapability.IDENTIFY_USERNAME -> NextAction.IdentifyUsername
        EmbeddedCapability.VERIFY_PASSWORD -> NextAction.VerifyPassword
        EmbeddedCapability.VERIFY_PASSKEY -> {
            val params = this[AUTHN_PARAMS_PUBLIC_KEY_KEY] as? Map<*, *>
                ?: return dropped(raw, AUTHN_PARAMS_PUBLIC_KEY_KEY)
            val challenge = params[CHALLENGE_KEY] as? String
                ?: return dropped(raw, "$AUTHN_PARAMS_PUBLIC_KEY_KEY.$CHALLENGE_KEY")
            val timeout = params[TIMEOUT_KEY] as? Long
                ?: return dropped(raw, "$AUTHN_PARAMS_PUBLIC_KEY_KEY.$TIMEOUT_KEY")
            val rpId = params[RP_ID_KEY] as? String
                ?: return dropped(raw, "$AUTHN_PARAMS_PUBLIC_KEY_KEY.$RP_ID_KEY")
            val userVerification = UserVerification.fromValue(params[USER_VERIFICATION_KEY] as? String)
                ?: return dropped(raw, "$AUTHN_PARAMS_PUBLIC_KEY_KEY.$USER_VERIFICATION_KEY")
            val hints = (params[HINTS_KEY] as? List<*>)?.filterIsInstance<String>().orEmpty()
            val allowCredentials = (params[ALLOW_CREDENTIALS_KEY] as? List<*>)
                ?.filterIsInstance<Map<*, *>>()
                ?.map { it.toStringKeyedMap() }
                .orEmpty()
            NextAction.VerifyPasskey(
                options = PasskeyRequestOptions(challenge, timeout, rpId, userVerification, hints, allowCredentials),
                requestJson = GsonProvider.gson.toJson(params)
            )
        }
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
 * Reads the signup `identifiers` object, ignoring keys this SDK doesn't model and skipping any offered
 * identifier that is missing its boolean `required` flag. Returns `null` when no valid identifier remains.
 */
private fun Map<*, *>.toSignupIdentifiers(): List<SignupIdentifier>? {
    val identifiers = SIGNUP_IDENTIFIER_TYPES.mapNotNull { (key, type) ->
        if (!containsKey(key)) return@mapNotNull null
        val required = (this[key] as? Map<*, *>)?.get(REQUIRED_KEY) as? Boolean
        if (required == null) {
            Log.w(TAG, "Skipping signup identifier \"$key\": required field \"$REQUIRED_KEY\" was missing or invalid.")
            return@mapNotNull null
        }
        SignupIdentifier(type, required)
    }
    return identifiers.ifEmpty { null }
}

private val SIGNUP_IDENTIFIER_TYPES: List<Pair<String, IdentifierType>> = listOf(
    EMAIL_KEY to IdentifierType.EMAIL,
    PHONE_NUMBER_KEY to IdentifierType.PHONE
)

private fun Map<*, *>.toStringKeyedMap(): Map<String, Any> =
    entries.mapNotNull { (key, value) -> if (key is String && value != null) key to value else null }.toMap()

/**
 * Logs and drops a recognized next action whose required [field] the server omitted or sent
 * malformed. Returns `null` so the entry is filtered out by [toNextActions].
 */
private fun dropped(action: String, field: String): NextAction? {
    Log.w(TAG, "Dropping \"$action\" next action: required field \"$field\" was missing or invalid.")
    return null
}
