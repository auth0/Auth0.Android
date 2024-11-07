package com.auth0.android.request

import com.google.gson.annotations.SerializedName

/**
 *  User information for registering user when signing up using passkey.
 *  @param email the email of the user. email can be optional, required, or forbidden depending on the attribute configuration for the database
 *  @param phoneNumber the phone number of the user. phone number can be optional, required, or forbidden depending on the attribute configuration for the database
 *  @param userName the username of the user. username can be optional, required, or forbidden depending on the attribute configuration for the database
 *  @param name optional display name
 */
public data class UserData(
    @field:SerializedName("email") val email: String? = null,
    @field:SerializedName("phone_number") val phoneNumber: String? = null,
    @field:SerializedName("username") val userName: String? = null,
    @field:SerializedName("name") val name: String? = null,
)