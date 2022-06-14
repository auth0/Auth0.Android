package com.auth0.android.result

import androidx.annotation.VisibleForTesting
import com.auth0.android.request.internal.GsonProvider
import com.auth0.android.request.internal.Jwt
import com.google.gson.annotations.SerializedName

import java.util.*

/**
 * Holds the user's credentials returned by Auth0.
 *
 *  * *idToken*: Identity Token with user information
 *  * *accessToken*: Access Token for Auth0 API
 *  * *refreshToken*: Refresh Token that can be used to request new tokens without signing in again
 *  * *type*: The type of the received Access Token.
 *  * *expiresAt*: The token expiration date.
 *  * *scope*: The token's granted scope.
 *
 */
public open class Credentials(
    /**
     * Getter for the Identity Token with user information.
     *
     * @return the Identity Token.
     */
    @field:SerializedName("id_token") public val idToken: String,
    /**
     * Getter for the Access Token for Auth0 API.
     *
     * @return the Access Token.
     */
    @field:SerializedName("access_token") public val accessToken: String,
    /**
     * Getter for the type of the received Token.
     *
     * @return the token type.
     */
    @field:SerializedName("token_type") public val type: String,

    /**
     * Getter for the Refresh Token that can be used to request new tokens without signing in again.
     *
     * @return the Refresh Token.
     */
    @field:SerializedName("refresh_token") public val refreshToken: String?,

    /**
     * Getter for the expiration date of the Access Token.
     * Once expired, the Access Token can no longer be used to access an API and a new Access Token needs to be obtained.
     *
     * @return the expiration date of this Access Token
     */
    @field:SerializedName("expires_at") public val expiresAt: Date,

    /**
     * Getter for the access token's granted scope. Only available if the requested scope differs from the granted one.
     *
     * @return the granted scope.
     */
    @field:SerializedName("scope") public val scope: String?
) {

    //TODO this could be removed and the class be a data class instead
    @get:VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    internal open val currentTimeInMillis: Long
        get() = System.currentTimeMillis()

    /**
     * Getter for the new multi-factor authentication recovery code. Only available if these credentials are the result of logging in using an MFA recovery code.
     *
     * @return the new MFA recovery code.
     */
    @field:SerializedName("recovery_code")
    public var recoveryCode: String? = null
        internal set

    public val user: UserProfile get() {
        val (_, payload) = Jwt.splitToken(idToken)
        val gson = GsonProvider.gson
        return gson.fromJson(Jwt.decodeBase64(payload), UserProfile::class.java)
    }

}