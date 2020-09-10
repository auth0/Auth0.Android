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

package com.auth0.android.result;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import java.io.Serializable;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Class that holds the information of a user's profile in Auth0.
 * Used both in {@link com.auth0.android.management.UsersAPIClient} and {@link com.auth0.android.authentication.AuthenticationAPIClient}.
 */
public class UserProfile implements Serializable {
    private final String id;
    private final String name;
    private final String nickname;
    private final String pictureURL;

    private final String email;
    private final boolean emailVerified;
    private final String givenName;
    private final String familyName;
    private final Map<String, Object> userMetadata;
    private final Map<String, Object> appMetadata;
    private final Date createdAt;
    private final List<UserIdentity> identities;

    private final Map<String, Object> extraInfo;

    public UserProfile(@Nullable String id, @Nullable String name, @Nullable String nickname, @Nullable String pictureURL, @Nullable String email, boolean emailVerified, @Nullable String familyName, @Nullable Date createdAt, @Nullable List<UserIdentity> identities, @Nullable Map<String, Object> extraInfo, @Nullable Map<String, Object> userMetadata, @Nullable Map<String, Object> appMetadata, @Nullable String givenName) {
        this.id = id;
        this.name = name;
        this.nickname = nickname;
        this.pictureURL = pictureURL;
        this.email = email;
        this.emailVerified = emailVerified;
        this.givenName = givenName;
        this.familyName = familyName;
        this.userMetadata = userMetadata;
        this.appMetadata = appMetadata;
        this.createdAt = createdAt;
        this.identities = identities;
        this.extraInfo = extraInfo;
    }

    /**
     * Getter for the unique Identifier of the user. If this represents a Full User Profile (Management API) the 'id' field will be returned.
     * If the value is not present, it will be considered a User Information and the id will be obtained from the 'sub' claim.
     *
     * @return the unique identifier of the user.
     */
    @Nullable
    public String getId() {
        if (id != null) {
            return id;
        }
        return getExtraInfo().containsKey("sub") ? (String) getExtraInfo().get("sub") : null;
    }

    @Nullable
    public String getName() {
        return name;
    }

    @Nullable
    public String getNickname() {
        return nickname;
    }

    @Nullable
    public String getEmail() {
        return email;
    }

    public boolean isEmailVerified() {
        return emailVerified;
    }

    @Nullable
    public String getPictureURL() {
        return pictureURL;
    }

    @Nullable
    public Date getCreatedAt() {
        return createdAt;
    }

    @Nullable
    public String getGivenName() {
        return givenName;
    }

    @Nullable
    public String getFamilyName() {
        return familyName;
    }

    @NonNull
    public Map<String, Object> getUserMetadata() {
        return userMetadata != null ? userMetadata : Collections.<String, Object>emptyMap();
    }

    @NonNull
    public Map<String, Object> getAppMetadata() {
        return appMetadata != null ? appMetadata : Collections.<String, Object>emptyMap();
    }

    /**
     * Returns extra information of the profile that is not part of the normalized profile
     *
     * @return a map with user's extra information found in the profile
     */
    @NonNull
    public Map<String, Object> getExtraInfo() {
        return extraInfo != null ? new HashMap<>(extraInfo) : Collections.<String, Object>emptyMap();
    }

    /**
     * List of the identities from a Identity Provider associated to the user.
     *
     * @return a list of identity provider information.
     */
    @Nullable
    public List<UserIdentity> getIdentities() {
        return identities;
    }
}
