package com.auth0.android.embedded.authorize

/**
 * The state of the flow in progress, created when the first response to `authorize()` arrives. It holds the PKCE
 * [codeVerifier] that is sent with the token exchange, the latest [authSession] from the server, and the
 * [passwordRequirement] announced on the signup action, which is `null` until one arrives.
 */
internal data class EmbeddedAuthState(
    val codeVerifier: String,
    val authSession: String,
    val passwordRequirement: CredentialRequirement? = null
) {
    override fun toString(): String =
        "EmbeddedAuthState(codeVerifier='xxxxx', authSession='xxxxx', passwordRequirement=$passwordRequirement)"
}
