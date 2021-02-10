package com.auth0.android.result

import com.google.gson.annotations.SerializedName
import java.util.*


/**
 * Internal class used as a bridge to handle the migration
 * from v1 Credentials to v2 Credentials, where some properties
 * could previously be null and are no longer null.
 */
internal data class OptionalCredentials(

    @field:SerializedName("id_token") val idToken: String?,
    /**
     * Getter for the Access Token for Auth0 API.
     *
     * @return the Access Token.
     */
    @field:SerializedName("access_token") val accessToken: String?,
    /**
     * Getter for the type of the received Token.
     *
     * @return the token type.
     */
    @field:SerializedName("token_type") val type: String?,

    /**
     * Getter for the Refresh Token that can be used to request new tokens without signing in again.
     *
     * @return the Refresh Token.
     */
    @field:SerializedName("refresh_token") val refreshToken: String?,

    /**
     * Getter for the expiration date of the Access Token.
     * Once expired, the Access Token can no longer be used to access an API and a new Access Token needs to be obtained.
     *
     * @return the expiration date of this Access Token
     */
    @field:SerializedName("expires_at")
    val expiresAt: Date?,

    /**
     * Getter for the access token's granted scope. Only available if the requested scope differs from the granted one.
     *
     * @return the granted scope.
     */
    @field:SerializedName(
        "scope"
    ) val scope: String?
)