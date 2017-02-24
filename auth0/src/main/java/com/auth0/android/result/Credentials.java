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


import android.support.annotation.Nullable;

import com.google.gson.annotations.SerializedName;

/**
 * Holds the user's credentials returned by Auth0.
 * <ul>
 * <li><i>idToken</i>: Identity Token with user information</li>
 * <li><i>accessToken</i>: Access Token for Auth0 API</li>
 * <li><i>refreshToken</i>: Refresh Token that can be used to request new tokens without signing in again</li>
 * <li><i>type</i>: The type of the received Token.</li>
 * </ul>
 */
public class Credentials {

    @SerializedName("access_token")
    private String accessToken;

    @SerializedName("token_type")
    private String type;

    @SerializedName("id_token")
    private String idToken;

    @SerializedName("refresh_token")
    private String refreshToken;

    @SerializedName("expires_in")
    private Long expiresIn;

    public Credentials(String idToken, String accessToken, String type, String refreshToken, Long expiresIn) {
        this.idToken = idToken;
        this.accessToken = accessToken;
        this.type = type;
        this.refreshToken = refreshToken;
        this.expiresIn = expiresIn;
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

    public Long getExpiresIn() {
        return expiresIn;
    }
}
