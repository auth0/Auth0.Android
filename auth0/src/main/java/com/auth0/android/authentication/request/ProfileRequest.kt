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
package com.auth0.android.authentication.request

import com.auth0.android.Auth0Exception
import com.auth0.android.authentication.AuthenticationException
import com.auth0.android.callback.BaseCallback
import com.auth0.android.request.AuthenticationRequest
import com.auth0.android.request.Request
import com.auth0.android.result.Authentication
import com.auth0.android.result.Credentials
import com.auth0.android.result.UserProfile

/**
 * Request to fetch a profile after a successful authentication with Auth0 Authentication API
 */
public class ProfileRequest
/**
 * @param authenticationRequest the request that will output a pair of credentials
 * @param userInfoRequest       the /userinfo request that will be wrapped
 */(
    private val authenticationRequest: AuthenticationRequest,
    private val userInfoRequest: Request<UserProfile, AuthenticationException>
) : Request<Authentication, AuthenticationException> {
    /**
     * Adds additional parameters for the login request
     *
     * @param parameters as a non-null dictionary
     * @return itself
     */
    override fun addParameters(parameters: Map<String, String>): ProfileRequest {
        authenticationRequest.addParameters(parameters)
        return this
    }

    override fun addParameter(name: String, value: String): ProfileRequest {
        authenticationRequest.addParameter(name, value)
        return this
    }

    /**
     * Adds a header to the request, e.g. "Authorization"
     *
     * @param name  of the header
     * @param value of the header
     * @return itself
     * @see ProfileRequest.ProfileRequest
     */
    override fun addHeader(name: String, value: String): ProfileRequest {
        authenticationRequest.addHeader(name, value)
        return this
    }

    /**
     * Set the scope used to authenticate the user
     *
     * @param scope value
     * @return itself
     */
    public fun setScope(scope: String): ProfileRequest {
        authenticationRequest.setScope(scope)
        return this
    }

    /**
     * Set the connection used to authenticate
     *
     * @param connection name
     * @return itself
     */
    public fun setConnection(connection: String): ProfileRequest {
        authenticationRequest.setConnection(connection)
        return this
    }

    /**
     * Starts the log in request and then fetches the user's profile
     *
     * @param callback called on either success or failure
     */
    override fun start(callback: BaseCallback<Authentication, AuthenticationException>) {
        authenticationRequest.start(object : BaseCallback<Credentials, AuthenticationException> {
            override fun onSuccess(credentials: Credentials) {
                userInfoRequest
                    .addHeader(HEADER_AUTHORIZATION, "Bearer " + credentials.accessToken)
                    .start(object : BaseCallback<UserProfile, AuthenticationException> {
                        override fun onSuccess(profile: UserProfile) {
                            callback.onSuccess(Authentication(profile, credentials))
                        }

                        override fun onFailure(error: AuthenticationException) {
                            callback.onFailure(error)
                        }
                    })
            }

            override fun onFailure(error: AuthenticationException) {
                callback.onFailure(error)
            }
        })
    }

    /**
     * Logs in the user with Auth0 and fetches it's profile.
     *
     * @return authentication object containing the user's tokens and profile
     * @throws Auth0Exception when either authentication or profile fetch fails
     */
    @Throws(Auth0Exception::class)
    override fun execute(): Authentication {
        val credentials = authenticationRequest.execute()
        val profile = userInfoRequest
            .addHeader(HEADER_AUTHORIZATION, "Bearer " + credentials.accessToken)
            .execute()
        return Authentication(profile, credentials)
    }

    private companion object {
        private const val HEADER_AUTHORIZATION = "Authorization"
    }
}