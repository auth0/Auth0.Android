package com.auth0.android.result

import com.google.gson.annotations.SerializedName

/**
 * Represents the challenge data required for enrolling a passkey.
 */
public data class PasskeyEnrollmentChallenge(
    val authenticationMethodId: String,
    @SerializedName("auth_session")
    val authSession: String,
    @SerializedName("authn_params_public_key")
    val authParamsPublicKey: AuthnParamsPublicKey
)
