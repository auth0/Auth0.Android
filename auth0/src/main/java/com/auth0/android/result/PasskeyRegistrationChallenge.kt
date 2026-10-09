package com.auth0.android.result


import com.google.gson.annotations.SerializedName

/**
 * Represents a challenge when user tries to register via passkeys.
 */
public data class PasskeyRegistrationChallenge @JvmOverloads constructor(
    @SerializedName("auth_session")
    val authSession: String,
    @SerializedName("authn_params_public_key")
    val authParamsPublicKey: AuthnParamsPublicKey,
    /**
     * The identifiers (e.g. `["email"]` or `["email", "phone"]`) that require OTP verification
     * before a credential can be created and tokens issued. `null` when the server did not
     * request any identifier verification. The OTP codes collected for these identifiers must
     * be passed to [com.auth0.android.authentication.AuthenticationAPIClient.signinWithPasskey]
     * via the `verification` parameter.
     */
    @SerializedName("verification_required")
    val verificationRequired: List<String>? = null
)

public data class AuthnParamsPublicKey(
    @SerializedName("authenticatorSelection")
    val authenticatorSelection: AuthenticatorSelection,
    @SerializedName("challenge")
    val challenge: String,
    @SerializedName("pubKeyCredParams")
    val pubKeyCredParams: List<PubKeyCredParam>,
    @SerializedName("rp")
    val relyingParty: RelyingParty,
    @SerializedName("timeout")
    val timeout: Long,
    @SerializedName("user")
    val user: PasskeyUser
)

public data class AuthenticatorSelection(
    @SerializedName("residentKey")
    val residentKey: String,
    @SerializedName("userVerification")
    val userVerification: String
)

public data class PubKeyCredParam(
    @SerializedName("alg")
    val alg: Int,
    @SerializedName("type")
    val type: String
)

public data class RelyingParty(
    @SerializedName("id")
    val id: String,
    @SerializedName("name")
    val name: String
)

public data class PasskeyUser(
    @SerializedName("displayName")
    val displayName: String,
    @SerializedName("id")
    val id: String,
    @SerializedName("name")
    val name: String
)