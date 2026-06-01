package com.auth0.android.authentication.request

/**
 * Represents the acting party in a token exchange delegation/impersonation flow.
 *
 * An `ActorToken` bundles the token and its type URI together, ensuring both are always provided as required by
 * [RFC 8693](https://tools.ietf.org/html/rfc8693). Auth0 requires both `actor_token` and `actor_token_type` to be
 * present when performing delegation.
 *
 * @param token The token representing the acting party (the entity performing actions on behalf of the subject).
 * @param tokenType A URI indicating the type of the actor token (e.g., `urn:ietf:params:oauth:token-type:id_token`
 *  or a custom URI like `http://corporate-idp/id-token`).
 *
 * @see [RFC 8693: OAuth 2.0 Token Exchange](https://tools.ietf.org/html/rfc8693#section-2.1)
 * @see [Custom Token Exchange Documentation](https://auth0.com/docs/authenticate/custom-token-exchange)
 */
public data class ActorToken(
    val token: String,
    val tokenType: String
)
