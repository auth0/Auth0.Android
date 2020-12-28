/*
 * Token.java
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

package com.auth0.android.result;


import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;

import com.google.gson.annotations.SerializedName;

import java.util.Date;

/**
 * Holds the user's credentials returned by Auth0.
 * <ul>
 * <li><i>idToken</i>: Identity Token with user information</li>
 * <li><i>accessToken</i>: Access Token for Auth0 API</li>
 * <li><i>refreshToken</i>: Refresh Token that can be used to request new tokens without signing in again</li>
 * <li><i>type</i>: The type of the received Token.</li>
 * <li><i>expiresIn</i>: The token lifetime in seconds.</li>
 * <li><i>expiresAt</i>: The token expiration date.</li>
 * <li><i>scope</i>: The token's granted scope.</li>
 * </ul>
 */
public class Credentials {

    @SerializedName("access_token")
    private final String accessToken;

    @SerializedName("token_type")
    private final String type;

    @SerializedName("id_token")
    private final String idToken;

    @SerializedName("refresh_token")
    private final String refreshToken;

    @SerializedName("expires_in")
    private Long expiresIn;

    @SerializedName("scope")
    private final String scope;

    @SerializedName("expires_at")
    private Date expiresAt;

    //TODO [SDK-1431]: Deprecate this constructor
    public Credentials(@Nullable String idToken, @Nullable String accessToken, @Nullable String type, @Nullable String refreshToken, @Nullable Long expiresIn) {
        this(idToken, accessToken, type, refreshToken, expiresIn, null, null);
    }

    public Credentials(@Nullable String idToken, @Nullable String accessToken, @Nullable String type, @Nullable String refreshToken, @Nullable Date expiresAt, @Nullable String scope) {
        this(idToken, accessToken, type, refreshToken, null, expiresAt, scope);
    }

    private Credentials(@Nullable String idToken, @Nullable String accessToken, @Nullable String type, @Nullable String refreshToken, @Nullable Long expiresIn, @Nullable Date expiresAt, @Nullable String scope) {
        this.idToken = idToken;
        this.accessToken = accessToken;
        this.type = type;
        this.refreshToken = refreshToken;
        this.expiresIn = expiresIn;
        this.scope = scope;
        this.expiresAt = expiresAt;
        if (expiresAt == null && expiresIn != null) {
            this.expiresAt = new Date(getCurrentTimeInMillis() + expiresIn * 1000);
        }
        if (expiresIn == null && expiresAt != null) {
            this.expiresIn = (expiresAt.getTime() - getCurrentTimeInMillis()) / 1000;
        }
    }

    @VisibleForTesting
    long getCurrentTimeInMillis() {
        return System.currentTimeMillis();
    }

    /**
     * Getter for the Identity Token with user information.
     *
     * @return the Identity Token.
     */
    @Nullable
    public String getIdToken() {
        return idToken;
    }

    /**
     * Getter for the Access Token for Auth0 API.
     *
     * @return the Access Token.
     */
    @Nullable
    public String getAccessToken() {
        return accessToken;
    }

    /**
     * Getter for the type of the received Token.
     *
     * @return the token type.
     */
    @Nullable
    public String getType() {
        return type;
    }

    /**
     * Getter for the Refresh Token that can be used to request new tokens without signing in again.
     *
     * @return the Refresh Token.
     */
    @Nullable
    public String getRefreshToken() {
        return refreshToken;
    }

    /**
     * Getter for the token lifetime in seconds.
     * Once expired, the token can no longer be used to access an API and a new token needs to be obtained.
     *
     * @return the token lifetime in seconds.
     */
    @Nullable
    public Long getExpiresIn() {
        return expiresIn;
    }

    /**
     * Getter for the token's granted scope. Only available if the requested scope differs from the granted one.
     *
     * @return the granted scope.
     */
    @Nullable
    public String getScope() {
        return scope;
    }

    /**
     * Getter for the expiration date of this token.
     * Once expired, the token can no longer be used to access an API and a new token needs to be obtained.
     *
     * @return the expiration date of this token
     */
    @Nullable
    public Date getExpiresAt() {
        return expiresAt;
    }
}
