package com.auth0.android.result

import com.auth0.android.request.internal.JsonRequired
import com.google.gson.annotations.SerializedName

/**
 * Result of a passwordless challenge.
 *
 * Holds the opaque `auth_session` token returned when a passwordless challenge is issued.
 *
 * @see [com.auth0.android.authentication.passwordless.PasswordlessClient.challengeWithEmail]
 * @see [com.auth0.android.authentication.passwordless.PasswordlessClient.challengeWithPhoneNumber]
 */
public class PasswordlessChallenge(
    @field:JsonRequired @field:SerializedName("auth_session")
    public val authSession: String
)
