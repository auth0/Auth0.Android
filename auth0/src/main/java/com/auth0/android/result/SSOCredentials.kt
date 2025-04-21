package com.auth0.android.result

import com.google.gson.annotations.SerializedName

/**
 * Holds the token credentials required for web SSO.
 */
public data class SSOCredentials(
    /**
     * The token used for web SSO.
     *
     * @return the session transfer token.
     */
    @field:SerializedName("access_token") public val sessionTransferToken: String,

    /**
     * Identity Token with user information.
     *
     * - Important: You must [validate](https://auth0.com/docs/secure/tokens/id-tokens/validate-id-tokens) any ID
     * tokens received from the Authentication API client before using the information they contain.
     *
     * ## See Also
     *
     *  - [ID Tokens](https://auth0.com/docs/secure/tokens/id-tokens)
     *  - [JSON Web Tokens](https://auth0.com/docs/secure/tokens/json-web-tokens)
     *  - [jwt.io](https://jwt.io)
     *
     * @return the Identity Token.
     */
    @field:SerializedName("id_token") public val idToken: String,

    /**
     * Type of the token issued. In this case, an Auth0 session transfer token.
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
     * Expiration duration of the session transfer token in seconds. Session transfer tokens are short-lived and expire after a few minutes.
     * Once expired, the session transfer tokens can no longer be used for web SSO.
     *
     * @return the expiration duration of this session transfer token
     */
    @field:SerializedName("expires_in") public val expiresIn: Int,

    /**
     *  Rotated refresh token. Only available when Refresh Token Rotation is enabled.
     *  - Important: If you're using the Authentication API client directly to perform the SSO exchange, make sure to store this
     *   new refresh token replacing the previous one.
     *
     * ## See Also
     * - [Refresh Token Rotation](https://auth0.com/docs/secure/tokens/refresh-tokens/refresh-token-rotation)
     *
     * @return the Refresh Token.
     */
    @field:SerializedName("refresh_token") public val refreshToken: String? = null
) {

    override fun toString(): String {
        return "SSOCredentials(sessionTransferToken = ****, idToken = ****,issuedTokenType = $issuedTokenType, tokenType = $tokenType, expiresIn = $expiresIn, refreshToken = ****)"
    }
}