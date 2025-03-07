package com.auth0.android.result

import com.google.gson.annotations.SerializedName

/**
 * Holds the token credentials required for web SSO .
 *
 *  * *webSsoToken*:  Token for web SSO
 *  * *refreshToken*: Refresh Token that can be used to request new tokens without signing in again
 *  * *tokenType*: Contains information about how the token should be used.
 *  * *expiresIn*: The token expiration duration.
 *  * *issuedTokenType*: Type of the token issued.
 *
 */
public data class SSOCredentials(
    /**
     * The token used for web SSO .
     *
     * @return the web sso Token.
     */
    @field:SerializedName("access_token") public val webSsoToken: String,

    /**
     * Type of the token issued.In this case, an Auth0 web sso token
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
     * Expiration duration of the web sso token in seconds. Web SSO tokens are short-lived and expire after a few minutes.
     * Once expired, the web sso token can no longer be used for SSO.
     *
     * @return the expiration duration of this web sso token
     */
    @field:SerializedName("expires_in") public val expiresIn: Int,


    /**
     *  Refresh Token that can be used to request new tokens without signing in again.
     *
     * @return the Refresh Token.
     */
    @field:SerializedName("refresh_token") public val refreshToken: String? = null
)