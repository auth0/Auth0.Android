package com.auth0.android.request

import com.auth0.android.Auth0
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

    /**
     * Calling this method will enable validating the claims in the ID Token.
     * This method is mandatory to be called and will be made as default in the next major.
     * The issuer and leeway can be customized using [AuthenticationRequest.withIdTokenVerificationIssuer]
     * and [AuthenticationRequest.withIdTokenVerificationLeeway] respectively.
     */
    public fun validateClaims(): AuthenticationRequest

    /**
     * Set the leeway or clock skew to be used for ID Token verification.
     * Defaults to 60 seconds.
     *
     * @param leeway to use for ID token verification, in seconds.
     * @return the current builder instance
     */
    public fun withIdTokenVerificationLeeway(leeway: Int): AuthenticationRequest

    /**
     * Set the expected issuer to be used for ID Token verification.
     * Defaults to the value returned by [Auth0.getDomainUrl].
     *
     * @param issuer to use for ID token verification.
     * @return the current builder instance
     */
    public fun withIdTokenVerificationIssuer(issuer: String): AuthenticationRequest

    /**
     * Adds a validator to be executed before the request is sent.
     * Multiple validators can be added and will be executed in order.
     *
     * @param validator the validator to add
     * @return itself
     */
    override fun addValidator(validator: RequestValidator): AuthenticationRequest {
        return this
    }
}