package com.auth0.android.request

import com.auth0.android.Auth0Exception
import com.auth0.android.authentication.AuthenticationException
import com.auth0.android.authentication.ParameterBuilder
import com.auth0.android.callback.Callback
import com.auth0.android.result.Credentials
import com.auth0.android.result.DatabaseUser

/**
 * Represent a request that creates a user in a Auth0 Database connection and then logs in.
 */
public class SignUpRequest
/**
 * @param signUpRequest the request that creates the user
 * @param authenticationRequest   the request that will output a pair of credentials
 */(
    private val signUpRequest: Request<DatabaseUser, AuthenticationException>,
    private val authenticationRequest: AuthenticationRequest
) : AuthenticationRequest {
    /**
     * Add additional parameters to be sent only when creating a user.
     *
     *
     * A common use case for this is storing extra information in the user metadata.
     * To set user metadata you have to wrap your custom properties in a map containing
     * a field `user_metadadata`:
     *
     * ```
     * // Define your custom fields
     * val metadata = mapOf("key"  to "value")
     *
     * // Define the sign up parameters, adding the user_metadata
     * val params = mapOf("user_metadata", "metadata")
     *
     * // Set the parameters in your request
     * signUpRequest.addSignUpParameters(params);
     * ```
     *
     * @param parameters sent with the request and must be non-null
     * @return itself
     * @see ParameterBuilder
     *
     * @see [User Metadata documentation](https://auth0.com/docs/users/concepts/overview-user-metadata)
     */
    public fun addSignUpParameters(parameters: Map<String, String>): SignUpRequest {
        signUpRequest.addParameters(parameters)
        return this
    }

    /**
     * Add additional parameters to be sent only when logging the user in.
     *
     * @param parameters sent with the request and must be non-null
     * @return itself
     * @see ParameterBuilder
     */
    public fun addAuthenticationParameters(parameters: Map<String, String>): SignUpRequest {
        authenticationRequest.addParameters(parameters)
        return this
    }

    /**
     * Add a header to the sign up request and to the authentication request, provided
     * it's of type [AuthenticationRequest].
     *
     * @param name  of the header
     * @param value of the header
     * @return itself
     */
    override fun addHeader(name: String, value: String): SignUpRequest {
        signUpRequest.addHeader(name, value)
        authenticationRequest.addHeader(name, value)
        return this
    }

    /**
     * Add additional parameters to be sent both when creating the user and logging in the user.
     *
     * @param parameters to send with the request
     * @return itself
     */
    override fun addParameters(parameters: Map<String, String>): SignUpRequest {
        signUpRequest.addParameters(parameters)
        authenticationRequest.addParameters(parameters)
        return this
    }

    override fun addParameter(name: String, value: String): SignUpRequest {
        signUpRequest.addParameter(name, value)
        authenticationRequest.addParameter(name, value)
        return this
    }

    override fun setScope(scope: String): SignUpRequest {
        authenticationRequest.setScope(scope)
        return this
    }

    override fun setAudience(audience: String): SignUpRequest {
        authenticationRequest.setAudience(audience)
        return this
    }

    override fun setGrantType(grantType: String): SignUpRequest {
        authenticationRequest.setGrantType(grantType)
        return this
    }

    override fun setConnection(connection: String): SignUpRequest {
        // sign-up endpoint only accepts a 'connection' parameter
        signUpRequest.addParameter(ParameterBuilder.CONNECTION_KEY, connection)
        authenticationRequest.setConnection(connection)
        return this
    }

    override fun setRealm(realm: String): SignUpRequest {
        // sign-up endpoint only accepts a 'connection' parameter
        signUpRequest.addParameter(ParameterBuilder.CONNECTION_KEY, realm)
        authenticationRequest.setRealm(realm)
        return this
    }

    /**
     * Starts to execute create user request and then logs the user in.
     *
     * @param callback called on either success or failure.
     */
    override fun start(callback: Callback<Credentials, AuthenticationException>) {
        signUpRequest.start(object : Callback<DatabaseUser, AuthenticationException> {
            override fun onSuccess(user: DatabaseUser) {
                authenticationRequest.start(callback)
            }

            override fun onFailure(error: AuthenticationException) {
                callback.onFailure(error)
            }
        })
    }

    /**
     * Execute the create user request and then logs the user in.
     *
     * @return authentication object on success
     * @throws Auth0Exception on failure
     */
    @Throws(Auth0Exception::class)
    override fun execute(): Credentials {
        signUpRequest.execute()
        return authenticationRequest.execute()
    }
}