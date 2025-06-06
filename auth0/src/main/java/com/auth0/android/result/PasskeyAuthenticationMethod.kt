package com.auth0.android.result


import com.google.gson.annotations.SerializedName

/**
 * A passkey authentication method.
 */
public data class PasskeyAuthenticationMethod(
    @SerializedName("created_at")
    val createdAt: String,
    @SerializedName("credential_backed_up")
    val credentialBackedUp: Boolean,
    @SerializedName("credential_device_type")
    val credentialDeviceType: String,
    @SerializedName("id")
    val id: String,
    @SerializedName("identity_user_id")
    val identityUserId: String,
    @SerializedName("key_id")
    val keyId: String,
    @SerializedName("public_key")
    val publicKey: String,
    @SerializedName("transports")
    val transports: List<String>?,
    @SerializedName("type")
    val type: String,
    @SerializedName("user_agent")
    val userAgent: String,
    @SerializedName("user_handle")
    val userHandle: String
)