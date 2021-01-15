package com.auth0.android.result

import com.auth0.android.util.JsonRequired
import com.google.gson.annotations.SerializedName
import java.io.Serializable

/**
 * Class that holds the information from a Identity Provider like Facebook or Twitter.
 */
public class UserIdentity(
    @field:SerializedName("user_id") @field:JsonRequired public val id: String,
    @field:SerializedName(
        "connection"
    ) @field:JsonRequired public val connection: String,
    @field:SerializedName("provider") @field:JsonRequired public val provider: String,
    @field:SerializedName(
        "isSocial"
    ) public val isSocial: Boolean,
    @field:SerializedName("access_token") public val accessToken: String?,
    @field:SerializedName("access_token_secret") public val accessTokenSecret: String?,
    @field:SerializedName(
        "profileData"
    ) private val profileInfo: Map<String, Any>?
) : Serializable {

    public fun getProfileInfo(): Map<String, Any> {
        return profileInfo?.toMap() ?: emptyMap()
    }
}