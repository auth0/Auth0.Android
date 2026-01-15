package com.auth0.android.result

import com.google.gson.annotations.SerializedName

/**
 * Represents the MFA requirements returned by Auth0 when multi-factor authentication is required.
 * Can contain either 'challenge' (for challenging existing authenticators) or 'enroll' (for enrolling new authenticators),
 * but not both at the same time.
 */
public data class MfaRequirements(
    @SerializedName("challenge") val challenge: List<MfaChallengeRequirement>?,
    @SerializedName("enroll") val enroll: List<MfaChallengeRequirement>?
)

/**
 * Represents a single MFA challenge or enrollment requirement.
 */
public data class MfaChallengeRequirement(
    @SerializedName("type") val type: String
)
