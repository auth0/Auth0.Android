/*
 * AuthenticationRequest.java
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

package com.auth0.android.authentication.request;

import com.auth0.android.Auth0Exception;
import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.callback.BaseCallback;
import com.auth0.android.request.AuthenticationRequest;
import com.auth0.android.request.ParameterizableRequest;
import com.auth0.android.request.Request;
import com.auth0.android.result.Authentication;
import com.auth0.android.result.Credentials;
import com.auth0.android.result.UserProfile;

import java.util.Map;

/**
 * Request to fetch a profile after a successful authentication with Auth0 Authentication API
 */
public class ProfileRequest implements Request<Authentication, AuthenticationException> {

    private static final String HEADER_AUTHORIZATION = "Authorization";

    private final AuthenticationRequest credentialsRequest;
    private final ParameterizableRequest<UserProfile, AuthenticationException> userProfileRequest;

    public ProfileRequest(AuthenticationRequest credentialsRequest, ParameterizableRequest<UserProfile, AuthenticationException> userProfileRequest) {
        this.credentialsRequest = credentialsRequest;
        this.userProfileRequest = userProfileRequest;
    }

    /**
     * Adds additional parameters for the login request
     *
     * @param parameters as a non-null dictionary
     * @return itself
     */
    public ProfileRequest addParameters(Map<String, Object> parameters) {
        credentialsRequest.addAuthenticationParameters(parameters);
        return this;
    }

    /**
     * Set the scope used to authenticate the user
     *
     * @param scope value
     * @return itself
     */
    public ProfileRequest setScope(String scope) {
        credentialsRequest.setScope(scope);
        return this;
    }

    /**
     * Set the connection used to authenticate
     *
     * @param connection name
     * @return itself
     */
    public ProfileRequest setConnection(String connection) {
        credentialsRequest.setConnection(connection);
        return this;
    }

    /**
     * Starts the log in request and then fetches the user's profile
     *
     * @param callback called on either success or failure
     */
    @Override
    public void start(final BaseCallback<Authentication, AuthenticationException> callback) {
        credentialsRequest.start(new BaseCallback<Credentials, AuthenticationException>() {
            @Override
            public void onSuccess(final Credentials credentials) {
                userProfileRequest
                        .addHeader(HEADER_AUTHORIZATION, "Bearer " + credentials.getAccessToken())
                        .start(new BaseCallback<UserProfile, AuthenticationException>() {
                            @Override
                            public void onSuccess(UserProfile profile) {
                                callback.onSuccess(new Authentication(profile, credentials));
                            }

                            @Override
                            public void onFailure(AuthenticationException error) {
                                callback.onFailure(error);
                            }
                        });
            }

            @Override
            public void onFailure(AuthenticationException error) {
                callback.onFailure(error);
            }
        });
    }

    /**
     * Logs in the user with Auth0 and fetches it's profile.
     *
     * @return authentication object containing the user's tokens and profile
     * @throws Auth0Exception when either authentication or profile fetch fails
     */
    @Override
    public Authentication execute() throws Auth0Exception {
        Credentials credentials = credentialsRequest.execute();
        UserProfile profile = userProfileRequest
                .addHeader(HEADER_AUTHORIZATION, "Bearer " + credentials.getAccessToken())
                .execute();
        return new Authentication(profile, credentials);
    }
}
