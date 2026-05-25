package com.auth0.android.authentication.request

/**
 * Data class representing custom token exchange options.
 * @param actorToken A token representing the acting party for delegation or impersonation scenarios. Used when one principal needs to act on behalf of another.
 *  For example, an AI agent acting on behalf of a user.
 * @param actorTokenType The type identifier for the actor token. Must be a URI under your organization's control, following the same
 *  rules as subject_token_type.
 */
public data class CustomTokenExchangeOptions(
    val actorToken: String,
    val actorTokenType: String
)
