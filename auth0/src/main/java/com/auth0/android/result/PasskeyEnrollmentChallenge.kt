package com.auth0.android.result

/**
 * A passkey enrollment challenge, combining the authentication method ID from the response headers
 * with the challenge details from the response body.
 */
public data class PasskeyEnrollmentChallenge(
    public val authenticationMethodId: String,
    public val authSession: String,
    public val authParamsPublicKey: AuthnParamsPublicKey
)