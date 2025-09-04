package com.auth0.android.request

import com.auth0.android.Auth0Exception
import com.auth0.android.authentication.AuthenticationException
import com.auth0.android.callback.Callback
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
     * @see [ProfileRequest]
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
    override fun start(callback: Callback<Authentication, AuthenticationException>) {
        authenticationRequest.start(object : Callback<Credentials, AuthenticationException> {
            override fun onSuccess(credentials: Credentials) {
                userInfoRequest
                    .addHeader(
                        HEADER_AUTHORIZATION,
                        "${credentials.type} ${credentials.accessToken}"
                    )
                    .start(object : Callback<UserProfile, AuthenticationException> {
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
            .addHeader(HEADER_AUTHORIZATION, "${credentials.type} ${credentials.accessToken}")
            .execute()
        return Authentication(profile, credentials)
    }

    /**
     * Logs in the user with Auth0 and fetches it's profile inside a Coroutine.
     * This is a Coroutine that is exposed only for Kotlin.
     *
     * @return authentication object containing the user's tokens and profile
     * @throws Auth0Exception when either authentication or profile fetch fails
     */
    @JvmSynthetic
    @Throws(Auth0Exception::class)
    override suspend fun await(): Authentication {
        val credentials = authenticationRequest.await()
        val profile = userInfoRequest
            .addHeader(HEADER_AUTHORIZATION, "${credentials.type} ${credentials.accessToken}")
            .await()
        return Authentication(profile, credentials)
    }

    private companion object {
        private const val HEADER_AUTHORIZATION = "Authorization"
    }
}