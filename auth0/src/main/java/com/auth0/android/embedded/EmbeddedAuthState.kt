package com.auth0.android.embedded

/**
 * The SDK-owned state of one in-progress embedded-authentication flow.
 *
 * Only [authSession] is tracked today. A `codeVerifier` slot is intentionally reserved here for the
 * future PKCE work; wiring it up is explicitly out of scope for this PoC.
 */
internal data class EmbeddedAuthState(
    val authSession: String
)
