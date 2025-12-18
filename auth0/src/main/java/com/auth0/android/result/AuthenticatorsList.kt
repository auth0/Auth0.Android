package com.auth0.android.result

import com.auth0.android.request.internal.JsonRequired
import com.google.gson.annotations.SerializedName

/**
 * Response containing a list of available MFA authenticators for the user.
 *
 * @see [com.auth0.android.authentication.AuthenticationAPIClient.listAuthenticators]
 */
public data class AuthenticatorsList(
    /**
     * List of authenticators available for this user
     */
    @field:JsonRequired
    @SerializedName("authenticators")
    public val authenticators: List<Authenticator>
) {
    /**
     * Get all SMS authenticators
     */
    public val smsAuthenticators: List<Authenticator>
        get() = authenticators.filter { it.isSms }

    /**
     * Get all OTP authenticators (TOTP)
     */
    public val otpAuthenticators: List<Authenticator>
        get() = authenticators.filter { it.isOTP }

    /**
     * Get all email authenticators
     */
    public val emailAuthenticators: List<Authenticator>
        get() = authenticators.filter { it.isEmail }

    /**
     * Get the first active SMS authenticator, if available
     */
    public val firstActiveSmsAuthenticator: Authenticator?
        get() = smsAuthenticators.firstOrNull { it.active }

    /**
     * Get the first active OTP authenticator, if available
     */
    public val firstActiveOtpAuthenticator: Authenticator?
        get() = otpAuthenticators.firstOrNull { it.active }
}
