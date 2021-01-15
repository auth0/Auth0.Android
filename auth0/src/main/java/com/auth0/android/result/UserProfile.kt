package com.auth0.android.result

import java.io.Serializable
import java.util.*

/**
 * Class that holds the information of a user's profile in Auth0.
 * Used both in [com.auth0.android.management.UsersAPIClient] and [com.auth0.android.authentication.AuthenticationAPIClient].
 */
public class UserProfile(
    private val id: String?,
    public val name: String?,
    public val nickname: String?,
    public val pictureURL: String?,
    public val email: String?,
    public val isEmailVerified: Boolean?,
    public val familyName: String?,
    public val createdAt: Date?,
    /**
     * List of the identities from a Identity Provider associated to the user.
     *
     * @return a list of identity provider information.
     */
    private val identities: List<UserIdentity>?,
    private val extraInfo: Map<String, Any>?,
    private val userMetadata: Map<String, Any>?,
    private val appMetadata: Map<String, Any>?,
    public val givenName: String?
) : Serializable {

    /**
     * Getter for the unique Identifier of the user. If this represents a Full User Profile (Management API) the 'id' field will be returned.
     * If the value is not present, it will be considered a User Information and the id will be obtained from the 'sub' claim.
     *
     * @return the unique identifier of the user.
     */
    public fun getId(): String? {
        if (id != null) {
            return id
        }
        return if (getExtraInfo().containsKey("sub")) getExtraInfo()["sub"] as String? else null
    }

    public fun getUserMetadata(): Map<String, Any> {
        return userMetadata ?: emptyMap()
    }

    public fun getAppMetadata(): Map<String, Any> {
        return appMetadata ?: emptyMap()
    }

    public fun getIdentities(): List<UserIdentity> {
        return identities ?: emptyList()
    }

    /**
     * Returns extra information of the profile that is not part of the normalized profile
     *
     * @return a map with user's extra information found in the profile
     */
    public fun getExtraInfo(): Map<String, Any> {
        return extraInfo?.toMap() ?: emptyMap()
    }
}