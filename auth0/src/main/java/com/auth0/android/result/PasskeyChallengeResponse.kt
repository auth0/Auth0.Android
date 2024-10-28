package com.auth0.android.result


import com.google.gson.annotations.SerializedName

internal data class PasskeyChallengeResponse(
    @SerializedName("auth_session")
    val authSession: String,
    @SerializedName("authn_params_public_key")
    val authParamsPublicKey: AuthParamsPublicKey
)

internal data class AuthParamsPublicKey(
    @SerializedName("challenge")
    val challenge: String,
    @SerializedName("rpId")
    val rpId: String,
    @SerializedName("timeout")
    val timeout: Int,
    @SerializedName("userVerification")
    val userVerification: String
)