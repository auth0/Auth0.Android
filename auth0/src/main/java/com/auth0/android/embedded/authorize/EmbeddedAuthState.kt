package com.auth0.android.embedded.authorize

/**
 * The state of the flow in progress, created when the first response to `authorize()` arrives. It holds the PKCE
 * [codeVerifier] that is sent with the token exchange, and the latest [authSession] from the server.
 */
internal data class EmbeddedAuthState(
    val codeVerifier: String,
    val authSession: String
) {
    override fun toString(): String = "EmbeddedAuthState(codeVerifier='xxxxx', authSession='xxxxx')"
}
