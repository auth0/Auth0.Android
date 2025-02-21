package com.auth0.android.result

import com.google.gson.annotations.SerializedName

/**
 * Holds the session token credentials required for web SSO .
 *
 *  * *sessionToken*: Session Token for web SSO
 *  * *refreshToken*: Refresh Token that can be used to request new tokens without signing in again
 *  * *tokenType*: Contains information about how the token should be used.
 *  * *expiresIn*: The token expiration duration.
 *  * *issuedTokenType*: Type of the token issued.
 *
 */
public data class SSOCredentials(
    /**
     * The Session Token used for web SSO .
     *
     * @return the Session Token.
     */
    @field:SerializedName("access_token") public val sessionToken: String,

    /**
     * Type of the token issued.In this case, an Auth0 session token
     *
     * @return the issued token type.
     */
    @field:SerializedName("issued_token_type") public val issuedTokenType: String,

    /**
     * Contains information about how the token should be used.
     * If the issued token is not an access token or usable as an access token, then the token_type
     * value N_A is used to indicate that an OAuth 2.0 token_type identifier is not applicable in that context
     *
     * @return the token type.
     */
    @field:SerializedName("token_type") public val tokenType: String,

    /**
     * Expiration duration of the session token in seconds. Session tokens are short-lived and expire after a few minutes.
     * Once expired, the Session Token can no longer be used for SSO.
     *
     * @return the expiration duration of this Session Token
     */
    @field:SerializedName("expires_in") public val expiresIn: Int,


    /**
     *  Refresh Token that can be used to request new tokens without signing in again.
     *
     * @return the Refresh Token.
     */
    @field:SerializedName("refresh_token") public val refreshToken: String? = null
)