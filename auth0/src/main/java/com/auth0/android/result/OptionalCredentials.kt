package com.auth0.android.result

import com.google.gson.annotations.SerializedName
import java.util.*


/**
 * Internal class used as a bridge to handle the migration
 * from v1 Credentials to v2 Credentials, where some properties
 * could previously be null and are no longer null.
 */
internal data class OptionalCredentials(
    @field:SerializedName("id_token") val idToken: String?,
    @field:SerializedName("access_token") val accessToken: String?,
    @field:SerializedName("token_type") val type: String?,
    @field:SerializedName("refresh_token") val refreshToken: String?,
    @field:SerializedName("expires_at") val expiresAt: Date?,
    @field:SerializedName("scope") val scope: String?
)