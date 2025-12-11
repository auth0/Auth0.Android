package com.auth0.android.result

/**
 * Result when SDK returns authorization code instead of credentials.
 * Used in PAR (Pushed Authorization Request) flows where the BFF
 * handles the token exchange.
 *
 * @property code The authorization code from the callback
 * @property state The optional state parameter from the callback, if present
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
