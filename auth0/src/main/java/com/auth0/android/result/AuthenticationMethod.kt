package com.auth0.android.result

import com.google.gson.annotations.SerializedName

/**
 * An Authentication Method. This single class represents all possible types of methods.
 * Properties are nullable to accommodate different types.
 */
public data class AuthenticationMethod(
    @SerializedName("id")
    val id: String,
    @SerializedName("type")
    val type: String,
    @SerializedName("created_at")
    val createdAt: String,
    @SerializedName("usage")
    val usage: List<String>,

    // Common MFA/Passkey properties
    @SerializedName("identity_user_id")
    val identityUserId: String?,
    @SerializedName("key_id")
    val keyId: String?,
    @SerializedName("public_key")
    val publicKey: String?,
    @SerializedName("user_agent")
    val userAgent: String?,
    @SerializedName("user_handle")
    val userHandle: String?,
    @SerializedName("transports")
    val transports: List<String>?,
    @SerializedName("credential_backed_up")
    val credentialBackedUp: Boolean?,
    @SerializedName("credential_device_type")
    val credentialDeviceType: String?,
    @SerializedName("name")
    val name: String?,
    @SerializedName("confirmed")
    val confirmed: Boolean?,

    // Password properties
    @SerializedName("last_password_reset")
    val lastPasswordReset: String?,

    // Phone properties
    @SerializedName("phone_number")
    val phoneNumber: String?,
    @SerializedName("preferred_authentication_method")
    val preferredAuthenticationMethod: String?,

    // Email properties
    @SerializedName("email")
    val email: String?
)

/**
 * List of Authentication Methods
 */
public data class AuthenticationMethods(
    @SerializedName("authentication_methods")
    val authenticationMethods: List<AuthenticationMethod>
)