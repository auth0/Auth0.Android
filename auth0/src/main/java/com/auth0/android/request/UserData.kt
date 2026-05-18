package com.auth0.android.request

import com.google.gson.annotations.SerializedName

/**
 *  User information for registering user when signing up using passkey.
 *  @param email the email of the user. email can be optional, required, or forbidden depending on the attribute configuration for the database
 *  @param phoneNumber the phone number of the user. phone number can be optional, required, or forbidden depending on the attribute configuration for the database
 *  @param userName the username of the user. username can be optional, required, or forbidden depending on the attribute configuration for the database
 *  @param name optional display name
 *  @param givenName the first name of the user
 *  @param familyName the last name of the user
 *  @param nickName the preferred nickname of the user
 *  @param picture URL pointing to the user's profile picture
 *  @param userMetadata additional user metadata as key-value pairs
 */
public data class UserData(
    @field:SerializedName("email") val email: String? = null,
    @field:SerializedName("phone_number") val phoneNumber: String? = null,
    @field:SerializedName("username") val userName: String? = null,
    @field:SerializedName("name") val name: String? = null,
    @field:SerializedName("given_name") val givenName: String? = null,
    @field:SerializedName("family_name") val familyName: String? = null,
    @field:SerializedName("nickname") val nickName: String? = null,
    @field:SerializedName("picture") val picture: String? = null,
    @field:SerializedName("user_metadata") val userMetadata: Map<String, String>? = null,
)