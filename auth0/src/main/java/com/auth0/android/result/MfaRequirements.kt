package com.auth0.android.result

import com.google.gson.annotations.SerializedName

/**
 * Represents the payload returned when multifactor authentication is required.
 *
 * This structure contains the MFA token needed to complete the authentication flow
 * and the available enrollment options for MFA factors.
 *
 * ## Usage
 *
 * ```kotlin
 * if (error.isMultifactorRequired) {
 *     val mfaPayload = error.mfaRequiredErrorPayload
 *     val mfaToken = mfaPayload?.mfaToken
 *     val enrollmentTypes = mfaPayload?.mfaRequirements?.enroll?.map { it.type }
 * }
 * ```
 *
 * @see [com.auth0.android.authentication.AuthenticationException.isMultifactorRequired]
 * @see [com.auth0.android.authentication.AuthenticationException.mfaRequiredErrorPayload]
 */
public data class MfaRequiredErrorPayload(
    /** The error code returned by Auth0 (e.g., "mfa_required"). */
    @SerializedName("error") val error: String,
    
    /** A human-readable description of the error. */
    @SerializedName("error_description") val errorDescription: String,
    
    /** The MFA token required to complete the authentication flow. */
    @SerializedName("mfa_token") val mfaToken: String,
    
    /** The MFA requirements containing available enrollment options. */
    @SerializedName("mfa_requirements") val mfaRequirements: MfaRequirements?
)

/**
 * Represents the MFA requirements including enrollment and challenge options.
 *
 * Can contain either 'challenge' (for challenging existing authenticators) or 'enroll' 
 * (for enrolling new authenticators).
 */
public data class MfaRequirements(
    /** Array of available MFA enrollment types. */
    @SerializedName("enroll") val enroll: List<MfaFactor>?,
    
    /** Array of available MFA challenge types. */
    @SerializedName("challenge") val challenge: List<MfaFactor>?
)

/**
 * Represents an MFA factor type option.
 *
 * Common factor types include:
 * - `"recovery-code"`: Recovery codes for account recovery
 * - `"otp"`: Time-based one-time password (TOTP)
 * - `"phone"`: SMS-based authentication
 * - `"push-notification"`: Push notification-based authentication
 * - `"email"`: Email-based authentication
 */
public data class MfaFactor(
    /** The type of MFA factor available for enrollment or challenge. */
    @SerializedName("type") val type: String
)
