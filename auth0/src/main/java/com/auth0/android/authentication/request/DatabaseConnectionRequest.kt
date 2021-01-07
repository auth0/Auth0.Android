package com.auth0.android.authentication.request

import com.auth0.android.Auth0Exception
import com.auth0.android.authentication.ParameterBuilder
import com.auth0.android.callback.Callback
import com.auth0.android.request.Request

/**
 * Request to perform a non-authentication related action
 * like creating a user or requesting a change password
 */
public open class DatabaseConnectionRequest<T, U : Auth0Exception>(private val request: Request<T, U>) {
    /**
     * Add the given parameters to the request
     *
     * @param parameters to be sent with the request
     * @return itself
     */
    public fun addParameters(parameters: Map<String, String>): DatabaseConnectionRequest<T, U> {
        request.addParameters(parameters)
        return this
    }

    /**
     * Add a parameter by name to the request
     *
     * @param name  of the parameter
     * @param value of the parameter
     * @return itself
     */
    public fun addParameter(name: String, value: String): DatabaseConnectionRequest<T, U> {
        request.addParameter(name, value)
        return this
    }

    /**
     * Add a header to the request, e.g. "Authorization"
     *
     * @param name  of the header
     * @param value of the header
     * @return itself
     */
    public fun addHeader(name: String, value: String): DatabaseConnectionRequest<T, U> {
        request.addHeader(name, value)
        return this
    }

    /**
     * Set the Auth0 Database Connection used for this request using its name.
     *
     * @param connection name
     * @return itself
     */
    public fun setConnection(connection: String): DatabaseConnectionRequest<T, U> {
        request.addParameter(ParameterBuilder.CONNECTION_KEY, connection)
        return this
    }

    /**
     * Executes the request async and returns its results via callback
     *
     * @param callback called on success or failure of the request
     */
    public open fun start(callback: Callback<T, U>) {
        request.start(callback)
    }

    /**
     * Executes the request synchronously
     *
     * @return the request result
     * @throws Auth0Exception if the request failed
     */
    @Throws(Auth0Exception::class)
    public fun execute(): T? {
        return request.execute()
    }
}