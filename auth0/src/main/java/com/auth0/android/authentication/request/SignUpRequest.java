/*
 * SignUpRequest.java
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

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import com.auth0.android.Auth0Exception;
import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.authentication.ParameterBuilder;
import com.auth0.android.callback.BaseCallback;
import com.auth0.android.request.AuthRequest;
import com.auth0.android.request.AuthenticationRequest;
import com.auth0.android.request.Request;
import com.auth0.android.result.Credentials;
import com.auth0.android.result.DatabaseUser;

import java.util.Map;

/**
 * Represent a request that creates a user in a Auth0 Database connection and then logs in.
 */
public class SignUpRequest implements Request<Credentials, AuthenticationException>, AuthRequest {

    private final DatabaseConnectionRequest<DatabaseUser, AuthenticationException> signUpRequest;
    private final AuthenticationRequest authenticationRequest;
    private final AuthRequest authRequest;

    /**
     * @param signUpRequest         the request that creates the user
     * @param authenticationRequest the request that will output a pair of credentials
     * @deprecated using this constructor prevents from updating the request headers. See {@link #SignUpRequest(DatabaseConnectionRequest, AuthRequest)}
     */
    @Deprecated
    public SignUpRequest(@NonNull DatabaseConnectionRequest<DatabaseUser, AuthenticationException> signUpRequest, @NonNull AuthenticationRequest authenticationRequest) {
        this.signUpRequest = signUpRequest;
        this.authenticationRequest = authenticationRequest;
        this.authRequest = null;
    }

    public SignUpRequest(@NonNull DatabaseConnectionRequest<DatabaseUser, AuthenticationException> signUpRequest, @NonNull AuthRequest authRequest) {
        this.signUpRequest = signUpRequest;
        this.authRequest = authRequest;
        this.authenticationRequest = null;
    }

    @NonNull
    private AuthenticationRequest getAuthRequest() {
        //noinspection ConstantConditions
        return authenticationRequest == null ? authRequest : authenticationRequest;
    }

    /**
     * Add additional parameters to be sent when creating a user.
     *
     * <p>A common use case for this is storing extra information in the user metadata.
     * To set user metadata you have to wrap your custom properties in a map containing
     * a field <code>user_metadadata</code>:</p>
     *
     * <pre>
     * {@code
     * // Define your custom fields
     * Map<String, Object> metadata = new HashMap<>();
     * metadata.put("key", value);
     *
     * // Define the sign up parameters, adding the user_metadata
     * Map<String, Object> params = new HashMap<>();
     * params.put("user_metadata", metadata);
     *
     * // Set the parameters in your request
     * signUpRequest.addSignUpParameters(params);
     * }
     * </pre>
     *
     * @param parameters sent with the request and must be non-null
     * @return itself
     * @see ParameterBuilder
     * @see <a href="https://auth0.com/docs/users/concepts/overview-user-metadata">User Metadata documentation</a>
     */
    @NonNull
    public SignUpRequest addSignUpParameters(@NonNull Map<String, Object> parameters) {
        signUpRequest.addParameters(parameters);
        return this;
    }

    /**
     * Add additional parameters to be sent when logging the user in.
     *
     * @param parameters sent with the request and must be non-null
     * @return itself
     * @see ParameterBuilder
     */
    @NonNull
    @Override
    public SignUpRequest addAuthenticationParameters(@NonNull Map<String, Object> parameters) {
        getAuthRequest().addAuthenticationParameters(parameters);
        return this;
    }

    /**
     * Add a header to the sign up request and to the authentication request, provided
     * it's of type {@link AuthRequest}.
     *
     * @param name  of the header
     * @param value of the header
     * @return itself
     */
    @NonNull
    @Override
    public SignUpRequest addHeader(@NonNull String name, @NonNull String value) {
        signUpRequest.addHeader(name, value);
        if (authRequest != null) {
            authRequest.addHeader(name, value);
        }
        return this;
    }

    @NonNull
    @Override
    public SignUpRequest setScope(@NonNull String scope) {
        getAuthRequest().setScope(scope);
        return this;
    }

    @NonNull
    @Override
    public SignUpRequest setDevice(@NonNull String device) {
        getAuthRequest().setDevice(device);
        return this;
    }

    @NonNull
    @Override
    public SignUpRequest setAudience(@NonNull String audience) {
        getAuthRequest().setAudience(audience);
        return this;
    }

    @NonNull
    @Override
    @Deprecated
    public SignUpRequest setAccessToken(@NonNull String accessToken) {
        getAuthRequest().setAccessToken(accessToken);
        return this;
    }

    @NonNull
    @Override
    public SignUpRequest setGrantType(@NonNull String grantType) {
        getAuthRequest().setGrantType(grantType);
        return this;
    }

    @NonNull
    @Override
    public SignUpRequest setConnection(@NonNull String connection) {
        signUpRequest.setConnection(connection);
        getAuthRequest().setConnection(connection);
        return this;
    }

    @NonNull
    @Override
    public SignUpRequest setRealm(@NonNull String realm) {
        signUpRequest.setConnection(realm);
        getAuthRequest().setRealm(realm);
        return this;
    }

    /**
     * Starts to execute create user request and then logs the user in.
     *
     * @param callback called on either success or failure.
     */
    @Override
    public void start(@NonNull final BaseCallback<Credentials, AuthenticationException> callback) {
        signUpRequest.start(new BaseCallback<DatabaseUser, AuthenticationException>() {
            @Override
            public void onSuccess(@Nullable final DatabaseUser user) {
                getAuthRequest().start(callback);
            }

            @Override
            public void onFailure(@NonNull AuthenticationException error) {
                callback.onFailure(error);
            }
        });
    }

    /**
     * Execute the create user request and then logs the user in.
     *
     * @return authentication object on success
     * @throws Auth0Exception on failure
     */
    @NonNull
    @Override
    public Credentials execute() throws Auth0Exception {
        signUpRequest.execute();
        return getAuthRequest().execute();
    }
}
