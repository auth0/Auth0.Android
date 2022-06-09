package com.auth0.android.request.internal

import com.auth0.android.Auth0Exception
import com.auth0.android.authentication.AuthenticationException
import com.auth0.android.authentication.ParameterBuilder
import com.auth0.android.callback.Callback
import com.auth0.android.request.AuthenticationRequest
import com.auth0.android.request.Request
import com.auth0.android.result.Credentials

internal open class BaseAuthenticationRequest(private val request: Request<Credentials, AuthenticationException>) :
    AuthenticationRequest {
    /**
     * Sets the 'grant_type' parameter
     *
     * @param grantType grant type
     * @return itself
     */
    override fun setGrantType(grantType: String): AuthenticationRequest {
        addParameter(ParameterBuilder.GRANT_TYPE_KEY, grantType)
        return this
    }

    /**
     * Sets the 'connection' parameter.
     *
     * @param connection name of the connection
     * @return itself
     */
    override fun setConnection(connection: String): AuthenticationRequest {
        addParameter(ParameterBuilder.CONNECTION_KEY, connection)
        return this
    }

    /**
     * Sets the 'realm' parameter. A realm identifies the host against which the authentication will be made, and usually helps to know which username and password to use.
     *
     * @param realm name of the realm
     * @return itself
     */
    override fun setRealm(realm: String): AuthenticationRequest {
        addParameter(ParameterBuilder.REALM_KEY, realm)
        return this
    }

    /**
     * Sets the 'scope' parameter.
     *
     * @param scope a scope value
     * @return itself
     */
    override fun setScope(scope: String): AuthenticationRequest {
        addParameter(ParameterBuilder.SCOPE_KEY, scope)
        return this
    }

    /**
     * Sets the 'audience' parameter.
     *
     * @param audience an audience value
     * @return itself
     */
    override fun setAudience(audience: String): AuthenticationRequest {
        addParameter(ParameterBuilder.AUDIENCE_KEY, audience)
        return this
    }

    override fun addParameters(parameters: Map<String, String>): AuthenticationRequest {
        request.addParameters(parameters)
        return this
    }

    override fun addParameter(name: String, value: String): AuthenticationRequest {
        request.addParameter(name, value)
        return this
    }

    override fun addHeader(name: String, value: String): AuthenticationRequest {
        request.addHeader(name, value)
        return this
    }

    override fun start(callback: Callback<Credentials, AuthenticationException>) {
        request.start(callback)
    }

    @Throws(Auth0Exception::class)
    override fun execute(): Credentials {
        return request.execute()
    }

    @JvmSynthetic
    @Throws(Auth0Exception::class)
    override suspend fun await(): Credentials {
        return request.await()
    }
}