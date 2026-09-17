package com.auth0.android.embedded.authorize

import com.auth0.android.Auth0Exception
import com.auth0.android.callback.Callback
import com.auth0.android.embedded.EmbeddedAuthException
import com.auth0.android.request.Request

/** A request that has already failed; used to report calling a continuation with no flow active. */
internal class FailedRequest<T>(
    private val error: EmbeddedAuthException
) : Request<T, EmbeddedAuthException> {

    override fun start(callback: Callback<T, EmbeddedAuthException>): Unit = callback.onFailure(error)

    @Throws(Auth0Exception::class)
    override suspend fun await(): T = throw error

    @Throws(Auth0Exception::class)
    override fun execute(): T = throw error

    override fun addParameters(parameters: Map<String, String>): Request<T, EmbeddedAuthException> = this
    override fun addParameter(name: String, value: String): Request<T, EmbeddedAuthException> = this
    override fun addParameter(name: String, value: Any): Request<T, EmbeddedAuthException> = this
    override fun addHeader(name: String, value: String): Request<T, EmbeddedAuthException> = this
}
