package com.auth0.android.request

import com.auth0.android.authentication.AuthenticationException
import com.auth0.android.result.Credentials

/**
 * Request to authenticate a user with Auth0 Authentication API
 */
public interface AuthenticationRequest : Request<Credentials, AuthenticationException> {
    /**
     * Sets the 'grant_type' parameter
     *
     * @param grantType grant type
     * @return itself
     */
    public fun setGrantType(grantType: String): AuthenticationRequest

    /**
     * Sets the 'connection' parameter
     *
     * @param connection name of the connection
     * @return itself
     */
    public fun setConnection(connection: String): AuthenticationRequest

    /**
     * Sets the 'realm' parameter. A realm identifies the host against which the authentication will be made, and usually helps to know which username and password to use.
     *
     * @param realm name of the realm to use.
     * @return itself
     */
    public fun setRealm(realm: String): AuthenticationRequest

    /**
     * Sets the 'scope' parameter.
     *
     * @param scope a scope value
     * @return itself
     */
    public fun setScope(scope: String): AuthenticationRequest

    /**
     * Sets the 'audience' parameter.
     *
     * @param audience an audience value
     * @return itself
     */
    public fun setAudience(audience: String): AuthenticationRequest
}