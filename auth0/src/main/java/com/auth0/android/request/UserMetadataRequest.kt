package com.auth0.android.request

import com.google.gson.annotations.SerializedName

/**
 *  User metadata request used in Passkey authentication
 */
internal data class UserMetadataRequest(
    @field:SerializedName("email") val email: String? = null,
    @field:SerializedName("phone_number") val phoneNumber: String? = null,
    @field:SerializedName("username") val userName: String? = null,
    @field:SerializedName("name") val name: String? = null,
)