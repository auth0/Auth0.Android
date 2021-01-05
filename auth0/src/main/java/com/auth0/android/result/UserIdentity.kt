/*
 * UserIdentity.java
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

import com.auth0.android.util.JsonRequired
import com.google.gson.annotations.SerializedName
import java.io.Serializable

/**
 * Class that holds the information from a Identity Provider like Facebook or Twitter.
 */
public class UserIdentity(
    @field:SerializedName("user_id") @field:JsonRequired public val id: String,
    @field:SerializedName(
        "connection"
    ) @field:JsonRequired public val connection: String,
    @field:SerializedName("provider") @field:JsonRequired public val provider: String,
    @field:SerializedName(
        "isSocial"
    ) public val isSocial: Boolean,
    @field:SerializedName("access_token") public val accessToken: String?,
    @field:SerializedName("access_token_secret") public val accessTokenSecret: String?,
    @field:SerializedName(
        "profileData"
    ) private val profileInfo: Map<String, Any>?
) : Serializable {

    public fun getProfileInfo(): Map<String, Any> {
        return profileInfo?.toMap() ?: emptyMap()
    }
}