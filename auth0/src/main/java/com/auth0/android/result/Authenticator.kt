package com.auth0.android.result

import com.google.gson.annotations.SerializedName

/**
 * Represents an enrolled MFA authenticator.
 */
public data class Authenticator(
    @SerializedName("id")
    public val id: String,
    @SerializedName("type")
    public val type: String,
    @SerializedName("authenticator_type")
    public val authenticatorType: String?,
    @SerializedName("active")
    public val active: Boolean,
    @SerializedName("oob_channel")
    public val oobChannel: String?,
    @SerializedName("name")
    public val name: String?,
    @SerializedName("created_at")
    public val createdAt: String?,
    @SerializedName("last_auth")
    public val lastAuth: String?
)
