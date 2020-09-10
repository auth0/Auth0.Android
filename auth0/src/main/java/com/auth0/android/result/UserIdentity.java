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

package com.auth0.android.result;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import com.auth0.android.util.JsonRequired;
import com.google.gson.annotations.SerializedName;

import java.io.Serializable;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Class that holds the information from a Identity Provider like Facebook or Twitter.
 */
public class UserIdentity implements Serializable {

    @JsonRequired
    @SerializedName("user_id")
    private final String id;
    @JsonRequired
    @SerializedName("connection")
    private final String connection;
    @JsonRequired
    @SerializedName("provider")
    private final String provider;

    @SerializedName("isSocial")
    private final boolean social;

    @SerializedName("access_token")
    private final String accessToken;
    @SerializedName("access_token_secret")
    private final String accessTokenSecret;

    @SerializedName("profileData")
    private final Map<String, Object> profileInfo;

    public UserIdentity(@NonNull String id, @NonNull String connection, @NonNull String provider, boolean social,
                        @Nullable String accessToken, @Nullable String accessTokenSecret, @NonNull Map<String, Object> profileInfo) {
        this.id = id;
        this.connection = connection;
        this.provider = provider;
        this.social = social;
        this.accessToken = accessToken;
        this.accessTokenSecret = accessTokenSecret;
        this.profileInfo = profileInfo;
    }

    @NonNull
    public String getId() {
        return id;
    }

    @NonNull
    public String getConnection() {
        return connection;
    }

    @NonNull
    public String getProvider() {
        return provider;
    }

    public boolean isSocial() {
        return social;
    }

    @Nullable
    public String getAccessToken() {
        return accessToken;
    }

    @Nullable
    public String getAccessTokenSecret() {
        return accessTokenSecret;
    }

    @NonNull
    public Map<String, Object> getProfileInfo() {
        return profileInfo != null ? new HashMap<>(profileInfo) : Collections.<String, Object>emptyMap();
    }
}
