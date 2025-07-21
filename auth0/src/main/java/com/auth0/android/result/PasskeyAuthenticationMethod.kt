package com.auth0.android.result

import com.google.gson.annotations.SerializedName

public data class PasskeyAuthenticationMethod(
    public override val id: String,
    public override val type: String,
    public override val createdAt: String,
    public override val usage: List<String>,
    @SerializedName("credential_backed_up")
    public val credentialBackedUp: Boolean,
    @SerializedName("credential_device_type")
    public val credentialDeviceType: String,
    @SerializedName("identity_user_id")
    public val identityUserId: String,
    @SerializedName("key_id")
    public val keyId: String,
    @SerializedName("public_key")
    public val publicKey: String,
    @SerializedName("transports")
    public val transports: List<String>?,
    @SerializedName("user_agent")
    public val userAgent: String?,
    @SerializedName("user_handle")
    public val userHandle: String
) : AuthenticationMethod(id, type, createdAt, usage)