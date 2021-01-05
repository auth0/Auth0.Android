/*
 * UserProfile.java
 *
 * Copyright (c) 2015 Auth0 (http://auth0.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
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