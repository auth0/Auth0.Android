package com.auth0.android.embedded.authorize

import android.util.Log
import com.auth0.android.embedded.passkey.AuthenticatorSelection
import com.auth0.android.embedded.passkey.PasskeyCreationOptions
import com.auth0.android.embedded.passkey.PasskeyRequestOptions
import com.auth0.android.embedded.passkey.PasskeyUser
import com.auth0.android.embedded.passkey.PublicKeyCredentialParameter
import com.auth0.android.embedded.passkey.RelyingParty
import com.auth0.android.embedded.passkey.ResidentKey
import com.auth0.android.embedded.passkey.SignupPasskey
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
private const val AUTHENTICATION_METHODS_KEY = "authentication_methods"
private const val PASSWORD_KEY = "password"
private const val PASSWORD_COMPLEXITY_OPTIONS_KEY = "password_complexity_options"
private const val MIN_LENGTH_KEY = "min_length"
private const val CHARACTER_TYPES_KEY = "character_types"
private const val PASSKEY_KEY = "passkey"
private const val ID_KEY = "id"
private const val RP_KEY = "rp"
private const val USER_KEY = "user"
private const val DISPLAY_NAME_KEY = "displayName"
private const val PUB_KEY_CRED_PARAMS_KEY = "pubKeyCredParams"
private const val TYPE_KEY = "type"
private const val ALG_KEY = "alg"
private const val AUTHENTICATOR_SELECTION_KEY = "authenticatorSelection"
private const val RESIDENT_KEY_KEY = "residentKey"
private const val PUBLIC_KEY_TYPE = "public-key"

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
            val timeout = (params[TIMEOUT_KEY] as? Number)?.toWholeLong()
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
            NextAction.Signup(identifiers, toCredentialRequirement(PASSWORD_KEY), toCredentialRequirement(PASSKEY_KEY))
        }
        EmbeddedCapability.CONFIRM_SIGNUP -> NextAction.ConfirmSignup(toSignupPassword(), toSignupPasskey())
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
 * Reads whether the signup action announces the [credential] (`password` or `passkey`) under
 * `authentication_methods`: `required: true` is [CredentialRequirement.REQUIRED], `required: false` is
 * [CredentialRequirement.OPTIONAL], and no entry is [CredentialRequirement.NONE]. An entry without a boolean
 * `required` is logged and treated as [CredentialRequirement.NONE].
 */
private fun Map<String, Any>.toCredentialRequirement(credential: String): CredentialRequirement {
    val entry = (this[AUTHENTICATION_METHODS_KEY] as? Map<*, *>)?.get(credential) ?: return CredentialRequirement.NONE
    return when ((entry as? Map<*, *>)?.get(REQUIRED_KEY) as? Boolean) {
        true -> CredentialRequirement.REQUIRED
        false -> CredentialRequirement.OPTIONAL
        null -> {
            Log.w(TAG, "Ignoring signup $credential: required field \"$REQUIRED_KEY\" was missing or invalid.")
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
    return SignupPassword(required = false, complexity = SignupPasswordComplexity(minLength, characterTypes))
}

/**
 * Reads the confirm action's `authn_params_public_key`, which the server sends when it offers to create a
 * passkey. The result is `null` when it is absent, or when a required field is missing or invalid; the
 * confirm action is kept either way, so the user can still finish without a passkey. Unknown entries of
 * `pubKeyCredParams` are skipped, and an empty result is invalid. [SignupPasskey.requestJson] is the object
 * as the server sent it.
 */
private fun Map<String, Any>.toSignupPasskey(): SignupPasskey? {
    val params = this[AUTHN_PARAMS_PUBLIC_KEY_KEY] as? Map<*, *> ?: return null
    fun invalid(field: String): SignupPasskey? {
        Log.w(TAG, "Ignoring signup passkey: required field \"$AUTHN_PARAMS_PUBLIC_KEY_KEY.$field\" was missing or invalid.")
        return null
    }
    val challenge = params[CHALLENGE_KEY] as? String ?: return invalid(CHALLENGE_KEY)
    val timeout = (params[TIMEOUT_KEY] as? Number)?.toWholeLong() ?: return invalid(TIMEOUT_KEY)
    val rp = (params[RP_KEY] as? Map<*, *>)?.let { map ->
        RelyingParty(map[ID_KEY] as? String ?: return invalid(RP_KEY), map[NAME_KEY] as? String ?: return invalid(RP_KEY))
    } ?: return invalid(RP_KEY)
    val user = (params[USER_KEY] as? Map<*, *>)?.let { map ->
        PasskeyUser(
            map[ID_KEY] as? String ?: return invalid(USER_KEY),
            map[NAME_KEY] as? String ?: return invalid(USER_KEY),
            map[DISPLAY_NAME_KEY] as? String ?: return invalid(USER_KEY)
        )
    } ?: return invalid(USER_KEY)
    val pubKeyCredParams = (params[PUB_KEY_CRED_PARAMS_KEY] as? List<*>)
        ?.filterIsInstance<Map<*, *>>()
        ?.mapNotNull { map ->
            val type = map[TYPE_KEY] as? String
            val alg = (map[ALG_KEY] as? Number)?.toWholeInt()
            if (type == PUBLIC_KEY_TYPE && alg != null) PublicKeyCredentialParameter(type, alg) else null
        }
        ?.takeIf { it.isNotEmpty() }
        ?: return invalid(PUB_KEY_CRED_PARAMS_KEY)
    val selection = (params[AUTHENTICATOR_SELECTION_KEY] as? Map<*, *>)?.let { map ->
        AuthenticatorSelection(
            ResidentKey.fromValue(map[RESIDENT_KEY_KEY] as? String),
            UserVerification.fromValue(map[USER_VERIFICATION_KEY] as? String)
        )
    } ?: return invalid(AUTHENTICATOR_SELECTION_KEY)
    return SignupPasskey(
        options = PasskeyCreationOptions(challenge, timeout, rp, user, pubKeyCredParams, selection),
        requestJson = GsonProvider.gson.toJson(params)
    )
}

private fun Number.toWholeInt(): Int? =
    toDouble().takeIf { it % 1.0 == 0.0 && it in Int.MIN_VALUE.toDouble()..Int.MAX_VALUE.toDouble() }?.toInt()

private fun Number.toWholeLong(): Long? =
    toDouble().takeIf { it % 1.0 == 0.0 && it in Long.MIN_VALUE.toDouble()..Long.MAX_VALUE.toDouble() }?.toLong()

private fun passwordCharacterType(value: String): SignupPasswordComplexity.CharacterType? = when (value) {
    "lowercase" -> SignupPasswordComplexity.CharacterType.LOWERCASE
    "uppercase" -> SignupPasswordComplexity.CharacterType.UPPERCASE
    "number" -> SignupPasswordComplexity.CharacterType.NUMBER
    "special" -> SignupPasswordComplexity.CharacterType.SPECIAL
    else -> null
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
