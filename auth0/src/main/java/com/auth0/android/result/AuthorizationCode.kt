package com.auth0.android.result

/**
 * Result returned when the SDK completes a PAR (Pushed Authorization Request) flow.
 * Contains the authorization code that should be sent to your backend (BFF) for token exchange.
 *
 * @property code The authorization code received from Auth0.
 * @property state The optional state parameter received from Auth0, if present.
 */
public data class AuthorizationCode(
    /**
     * The authorization code received from Auth0.
     * This code should be sent to your BFF for token exchange.
     */
    public val code: String,

    /**
     * The optional state parameter received from Auth0.
     * This can be used by the BFF to correlate the response with the original request.
     */
    public val state: String? = null
)
