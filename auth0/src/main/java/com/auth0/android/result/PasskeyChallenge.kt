package com.auth0.android.result


import com.google.gson.annotations.SerializedName

/**
 * Represents a challenge when user tries to login via passkeys.
 */
public data class PasskeyChallenge(
    @SerializedName("auth_session")
    val authSession: String,
    @SerializedName("authn_params_public_key")
    val authParamsPublicKey: AuthParamsPublicKey
)

public data class AuthParamsPublicKey(
    @SerializedName("challenge")
    val challenge: String,
    @SerializedName("rpId")
    val rpId: String,
    @SerializedName("timeout")
    val timeout: Int,
    @SerializedName("userVerification")
    val userVerification: String
)