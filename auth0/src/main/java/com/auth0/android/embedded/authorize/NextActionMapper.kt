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
private const val AUTHENTICATION_METHODS_KEY = "authentication_methods"
private const val PASSWORD_KEY = "password"
private const val PASSWORD_COMPLEXITY_OPTIONS_KEY = "password_complexity_options"
private const val MIN_LENGTH_KEY = "min_length"
private const val CHARACTER_TYPES_KEY = "character_types"

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
            NextAction.Signup(identifiers, toPasswordRequirement())
        }
        EmbeddedCapability.CONFIRM_SIGNUP -> NextAction.ConfirmSignup(toSignupPassword())
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

/**
 * Reads whether the signup action announces a password: `required: true` is [CredentialRequirement.REQUIRED],
 * `required: false` is [CredentialRequirement.OPTIONAL], and no password entry is [CredentialRequirement.NONE].
 * A password entry without a boolean `required` is logged and treated as [CredentialRequirement.NONE].
 */
private fun Map<String, Any>.toPasswordRequirement(): CredentialRequirement {
    val password = (this[AUTHENTICATION_METHODS_KEY] as? Map<*, *>)?.get(PASSWORD_KEY) ?: return CredentialRequirement.NONE
    return when ((password as? Map<*, *>)?.get(REQUIRED_KEY) as? Boolean) {
        true -> CredentialRequirement.REQUIRED
        false -> CredentialRequirement.OPTIONAL
        null -> {
            Log.w(TAG, "Ignoring signup password: required field \"$REQUIRED_KEY\" was missing or invalid.")
            CredentialRequirement.NONE
        }
    }
}

/**
 * Reads the confirm action's `password_complexity_options`, which the server sends exactly when the
 * connection collects a password. The result is `null` when they are absent, or when `min_length` is missing
 * or not a positive integer. Unknown `character_types` are skipped. [SignupPassword.required] is `false`
 * here; the client sets it from the requirement announced on the signup action.
 */
private fun Map<String, Any>.toSignupPassword(): SignupPassword? {
    val options = this[PASSWORD_COMPLEXITY_OPTIONS_KEY] as? Map<*, *> ?: return null
    val minLength = (options[MIN_LENGTH_KEY] as? Number)?.toWholeInt()?.takeIf { it >= 1 }
    if (minLength == null) {
        Log.w(TAG, "Ignoring signup password: required field \"$MIN_LENGTH_KEY\" was missing or invalid.")
        return null
    }
    val characterTypes = (options[CHARACTER_TYPES_KEY] as? List<*>)
        ?.filterIsInstance<String>()
        ?.mapNotNull(::passwordCharacterType)
        ?.distinct()
        .orEmpty()
    return SignupPassword(required = false, complexity = PasswordComplexity(minLength, characterTypes))
}

private fun Number.toWholeInt(): Int? =
    toDouble().takeIf { it % 1.0 == 0.0 && it in Int.MIN_VALUE.toDouble()..Int.MAX_VALUE.toDouble() }?.toInt()

private fun passwordCharacterType(value: String): PasswordComplexity.CharacterType? = when (value) {
    "lowercase" -> PasswordComplexity.CharacterType.LOWERCASE
    "uppercase" -> PasswordComplexity.CharacterType.UPPERCASE
    "number" -> PasswordComplexity.CharacterType.NUMBER
    "special" -> PasswordComplexity.CharacterType.SPECIAL
    else -> null
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
