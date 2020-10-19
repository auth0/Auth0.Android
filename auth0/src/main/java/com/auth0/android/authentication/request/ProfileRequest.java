/*
 * ProfileRequest.java
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

import android.annotation.SuppressLint;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.auth0.android.Auth0Exception;
import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.callback.BaseCallback;
import com.auth0.android.request.AuthRequest;
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

    private final AuthenticationRequest authenticationRequest;
    private final AuthRequest authRequest;
    final ParameterizableRequest<UserProfile, AuthenticationException> userInfoRequest;

    /**
     * @param authenticationRequest the request that will output a pair of credentials
     * @param userInfoRequest       the /userinfo request that will be wrapped
     * @deprecated using this constructor prevents from updating the request headers. See {@link #ProfileRequest(AuthRequest, ParameterizableRequest)}
     */
    @SuppressWarnings("DeprecatedIsStillUsed")
    @Deprecated
    public ProfileRequest(@NonNull AuthenticationRequest authenticationRequest, @NonNull ParameterizableRequest<UserProfile, AuthenticationException> userInfoRequest) {
        this.userInfoRequest = userInfoRequest;
        this.authenticationRequest = authenticationRequest;
        this.authRequest = null;
    }

    @SuppressLint("LambdaLast")
    public ProfileRequest(@NonNull AuthRequest authRequest, @NonNull ParameterizableRequest<UserProfile, AuthenticationException> userInfoRequest) {
        this.userInfoRequest = userInfoRequest;
        this.authRequest = authRequest;
        this.authenticationRequest = null;
    }

    @NonNull
    private AuthenticationRequest getAuthRequest() {
        //noinspection ConstantConditions
        return authenticationRequest == null ? authRequest : authenticationRequest;
    }

    /**
     * Adds additional parameters for the login request
     *
     * @param parameters as a non-null dictionary
     * @return itself
     */
    @NonNull
    public ProfileRequest addParameters(@NonNull Map<String, Object> parameters) {
        getAuthRequest().addAuthenticationParameters(parameters);
        return this;
    }

    /**
     * Adds a header to the request, e.g. "Authorization"
     * Only available when the underlying authentication request is of type {@link AuthRequest}.
     *
     * @param name  of the header
     * @param value of the header
     * @return itself
     * @see ProfileRequest#ProfileRequest(AuthRequest, ParameterizableRequest)
     */
    @NonNull
    public ProfileRequest addHeader(@NonNull String name, @NonNull String value) {
        if (authRequest != null) {
            authRequest.addHeader(name, value);
        }
        return this;
    }

    /**
     * Set the scope used to authenticate the user
     *
     * @param scope value
     * @return itself
     */
    @NonNull
    public ProfileRequest setScope(@NonNull String scope) {
        getAuthRequest().setScope(scope);
        return this;
    }

    /**
     * Set the connection used to authenticate
     *
     * @param connection name
     * @return itself
     */
    @NonNull
    public ProfileRequest setConnection(@NonNull String connection) {
        getAuthRequest().setConnection(connection);
        return this;
    }

    /**
     * Starts the log in request and then fetches the user's profile
     *
     * @param callback called on either success or failure
     */
    @Override
    public void start(@NonNull final BaseCallback<Authentication, AuthenticationException> callback) {
        getAuthRequest().start(new BaseCallback<Credentials, AuthenticationException>() {
            @Override
            public void onSuccess(@Nullable final Credentials credentials) {
                //noinspection ConstantConditions
                userInfoRequest
                        .addHeader(HEADER_AUTHORIZATION, "Bearer " + credentials.getAccessToken())
                        .start(new BaseCallback<UserProfile, AuthenticationException>() {
                            @Override
                            public void onSuccess(@Nullable UserProfile profile) {
                                //noinspection ConstantConditions
                                callback.onSuccess(new Authentication(profile, credentials));
                            }

                            @Override
                            public void onFailure(@NonNull AuthenticationException error) {
                                callback.onFailure(error);
                            }
                        });
            }

            @Override
            public void onFailure(@NonNull AuthenticationException error) {
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
    @NonNull
    @Override
    public Authentication execute() throws Auth0Exception {
        Credentials credentials = getAuthRequest().execute();
        UserProfile profile = userInfoRequest
                .addHeader(HEADER_AUTHORIZATION, "Bearer " + credentials.getAccessToken())
                .execute();
        return new Authentication(profile, credentials);
    }
}
