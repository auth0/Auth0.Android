package com.auth0.android.result

import com.google.gson.annotations.SerializedName

/**
 * Represents an MFA authenticator that can be used for multi-factor authentication.
 *
 * @see [com.auth0.android.authentication.AuthenticationAPIClient.listAuthenticators]
 */
public data class Authenticator(
    /**
     * Unique identifier for this authenticator
     */
    @SerializedName("id")
    public val id: String,

    /**
     * Type of authenticator (e.g., "otp", "oob", "recovery-code")
     */
    @SerializedName("authenticator_type")
    public val authenticatorType: String,

    /**
     * Whether this authenticator is active
     */
    @SerializedName("active")
    public val active: Boolean,

    /**
     * OOB channel if this is an out-of-band authenticator (e.g., "sms", "email", "auth0")
     */
    @SerializedName("oob_channel")
    public val oobChannel: String? = null,

    /**
     * Name of the authenticator
     */
    @SerializedName("name")
    public val name: String? = null,

    /**
     * Creation timestamp
     */
    @SerializedName("created_at")
    public val createdAt: String? = null,

    /**
     * Last update timestamp
     */
    @SerializedName("updated_at")
    public val updatedAt: String? = null
) {
    /**
     * Check if this is an SMS authenticator
     */
    public val isSms: Boolean
        get() = authenticatorType == "oob" && oobChannel == "sms"

    /**
     * Check if this is an OTP authenticator (TOTP)
     */
    public val isOTP: Boolean
        get() = authenticatorType == "otp"

    /**
     * Check if this is an email authenticator
     */
    public val isEmail: Boolean
        get() = authenticatorType == "oob" && oobChannel == "email"

    /**
     * Check if this is a recovery code authenticator
     */
    public val isRecoveryCode: Boolean
        get() = authenticatorType == "recovery-code"
}
