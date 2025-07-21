package com.auth0.android.result

import com.google.gson.annotations.SerializedName

public data class PasskeyEnrollmentChallenge(
    public override val authSession: String,
    @SerializedName("authn_params_public_key")
    public val publicKeyCredentialCreationOptions: PublicKeyCredentialCreationOptions
) : EnrollmentChallenge(null, authSession)