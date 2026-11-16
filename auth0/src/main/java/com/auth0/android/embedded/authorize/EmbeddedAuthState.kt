package com.auth0.android.embedded.authorize

/**
 * The state of the flow in progress, created by `authorize()` with the PKCE [codeVerifier] that is sent with
 * the token exchange. [authSession] is the latest session from the server, and is `null` until the first
 * response arrives. Neither is ever logged.
 */
internal data class EmbeddedAuthState(
    val codeVerifier: String,
    val authSession: String? = null
) {
    override fun toString(): String = "EmbeddedAuthState(codeVerifier='xxxxx', authSession='xxxxx')"
}
