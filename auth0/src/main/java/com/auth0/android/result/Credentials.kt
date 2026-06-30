package com.auth0.android.result

import com.auth0.android.request.internal.GsonProvider
import com.auth0.android.request.internal.Jwt
import com.google.gson.annotations.SerializedName
import java.util.Date

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
public data class Credentials(
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

    /**
     * Getter for the new multi-factor authentication recovery code. Only available if these credentials are the result of logging in using an MFA recovery code.
     *
     * @return the new MFA recovery code.
     */
    @field:SerializedName("recovery_code")
    public var recoveryCode: String? = null
        internal set

    override fun toString(): String {
        return "Credentials(idToken='xxxxx', accessToken='xxxxx', type='$type', refreshToken='xxxxx', expiresAt='$expiresAt', scope='$scope')"
    }

    public val user: UserProfile
        get() {
            val (_, payload) = Jwt.splitToken(idToken)
            val gson = GsonProvider.gson
            return gson.fromJson(Jwt.decodeBase64(payload), UserProfile::class.java)
        }

    /**
     * The session-expiry ceiling pinned at the initial login, in Unix seconds, stamped by the
     * credentials manager when it serves these credentials. When set, it is the value actually
     * enforced by the SDK and takes precedence over the live [idToken] claim — so [sessionExpiresAt]
     * does not diverge from enforcement after a refresh whose token omits or re-emits the claim.
     */
    @Transient
    internal var pinnedSessionExpiresAt: Long? = null

    /**
     * The absolute session-expiry ceiling, in **Unix seconds**, asserted by the upstream identity
     * provider via the IPSIE `session_expiry` claim, or `null` when the connection does not emit it.
     *
     * This is a session-level ceiling that is independent of [expiresAt] (the access-token expiry):
     * it usually sits much further out and caps how long the local session may live, regardless of
     * access-token renewals. A `null` value means there is no such ceiling.
     *
     * When these credentials were served by a credentials manager, this reflects the value pinned at
     * the initial login (the one the SDK enforces). Otherwise it is decoded on demand from [idToken].
     */
    public val sessionExpiresAt: Long?
        get() = pinnedSessionExpiresAt ?: runCatching { Jwt(idToken).sessionExpiry }.getOrNull()

}