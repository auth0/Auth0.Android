package com.auth0.android.result

/**
 * Result returned when the SDK completes a PAR (Pushed Authorization Request) flow.
 * Contains the authorization code that should be sent to your backend (BFF) for token exchange.
 *
 * **Important:** The SDK does not validate the [state] parameter. Your app or BFF must validate
 * that the returned [state] matches the value originally used in the PAR request to prevent
 * CSRF attacks.
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
     * Your app or BFF must validate this against the original state used in the
     * PAR request to prevent CSRF attacks.
     */
    public val state: String? = null
)
