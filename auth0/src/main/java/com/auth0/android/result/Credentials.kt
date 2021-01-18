package com.auth0.android.result

import androidx.annotation.VisibleForTesting
import com.google.gson.annotations.SerializedName
import java.util.*

/**
 * Holds the user's credentials returned by Auth0.
 *
 *  * *idToken*: Identity Token with user information
 *  * *accessToken*: Access Token for Auth0 API
 *  * *refreshToken*: Refresh Token that can be used to request new tokens without signing in again
 *  * *type*: The type of the received Token.
 *  * *expiresIn*: The token lifetime in seconds.
 *  * *expiresAt*: The token expiration date.
 *  * *scope*: The token's granted scope.
 *
 */
public open class Credentials private constructor(
    /**
     * Getter for the Identity Token with user information.
     *
     * @return the Identity Token.
     */
    @field:SerializedName("id_token") public val idToken: String?,
    /**
     * Getter for the Access Token for Auth0 API.
     *
     * @return the Access Token.
     */
    @field:SerializedName("access_token") public val accessToken: String?,
    /**
     * Getter for the type of the received Token.
     *
     * @return the token type.
     */
    @field:SerializedName("token_type") public val type: String?,
    /**
     * Getter for the Refresh Token that can be used to request new tokens without signing in again.
     *
     * @return the Refresh Token.
     */
    @field:SerializedName("refresh_token") public val refreshToken: String?,
    expiresIn: Long?,
    expiresAt: Date?,
    /**
     * Getter for the token's granted scope. Only available if the requested scope differs from the granted one.
     *
     * @return the granted scope.
     */
    @field:SerializedName(
        "scope"
    ) public val scope: String?
) {

    /**
     * Getter for the token lifetime in seconds.
     * Once expired, the token can no longer be used to access an API and a new token needs to be obtained.
     *
     * @return the token lifetime in seconds.
     */
    @SerializedName("expires_in")
    public var expiresIn: Long? = null

    /**
     * Getter for the expiration date of this token.
     * Once expired, the token can no longer be used to access an API and a new token needs to be obtained.
     *
     * @return the expiration date of this token
     */
    @SerializedName("expires_at")
    public var expiresAt: Date? = null

    //TODO [SDK-1431]: Deprecate this constructor
    public constructor(
        idToken: String?,
        accessToken: String?,
        type: String?,
        refreshToken: String?,
        expiresIn: Long?
    ) : this(idToken, accessToken, type, refreshToken, expiresIn, null, null)

    public constructor(
        idToken: String?,
        accessToken: String?,
        type: String?,
        refreshToken: String?,
        expiresAt: Date?,
        scope: String?
    ) : this(idToken, accessToken, type, refreshToken, null, expiresAt, scope)

    @get:VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    internal open val currentTimeInMillis: Long
        get() = System.currentTimeMillis()

    init {
        if (expiresAt == null && expiresIn != null) {
            this.expiresAt = Date(currentTimeInMillis + expiresIn * 1000)
        } else {
            this.expiresAt = expiresAt
        }
        this.expiresIn = if (expiresIn == null && expiresAt != null) {
            (expiresAt.time - currentTimeInMillis) / 1000
        } else {
            expiresIn
        }
    }
}