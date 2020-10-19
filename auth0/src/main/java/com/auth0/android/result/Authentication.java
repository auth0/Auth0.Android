/*
 * Authentication.java
 *
 * Copyright (c) 2016 Auth0 (http://auth0.com)
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


import androidx.annotation.NonNull;

import com.auth0.android.authentication.AuthenticationAPIClient;
import com.auth0.android.request.AuthenticationRequest;

/**
 * The result of a successful authentication against Auth0
 * Contains the logged in user's {@link Credentials} and {@link UserProfile}.
 *
 * @see AuthenticationAPIClient#getProfileAfter(AuthenticationRequest)
 */
public class Authentication {

    private final UserProfile profile;
    private final Credentials credentials;

    public Authentication(@NonNull UserProfile profile, @NonNull Credentials credentials) {
        this.profile = profile;
        this.credentials = credentials;
    }

    @NonNull
    public UserProfile getProfile() {
        return profile;
    }

    @NonNull
    public Credentials getCredentials() {
        return credentials;
    }
}
