package com.auth0.android.result

import com.google.gson.annotations.SerializedName
import java.util.Date

/**
 * Holds the user's credentials obtained from Auth0 for a specific API as the result of exchanging a refresh token.
 *
 *  * *accessToken*: Access Token for Auth0 API
 *  * *type*: The type of the received Access Token.
 *  * *expiresAt*: The token expiration date.
 *  * *scope*: The token's granted scope.
 *
 */
public data class APICredentials(
    /**
     * Getter for the Access Token for Auth0 API.
     *
     * @return the Access Token.
     */
    @field:SerializedName("access_token")
    val accessToken: String,
    /**
     * Getter for the type of the received Token.
     *
     * @return the token type.
     */
    @field:SerializedName("token_type")
    val type: String,
    /**
     * Getter for the expiration date of the Access Token.
     * Once expired, the Access Token can no longer be used to access an API and a new Access Token needs to be obtained.
     *
     * @return the expiration date of this Access Token
     */
    @field:SerializedName("expires_at")
    val expiresAt: Date,
    /**
     * Getter for the access token's granted scope. Only available if the requested scope differs from the granted one.
     *
     * @return the granted scope.
     */
    @field:SerializedName("scope")
    val scope: String
) {
    override fun toString(): String {
        return "APICredentials( accessToken='xxxxx', type='$type', expiresAt='$expiresAt', scope='$scope')"
    }
}


/**
 * Converts a Credentials instance to an APICredentials instance.
 */
internal fun Credentials.toAPICredentials(): APICredentials {
    val newScope = scope ?: "openid"
    return APICredentials(accessToken, type, expiresAt, newScope)
}
