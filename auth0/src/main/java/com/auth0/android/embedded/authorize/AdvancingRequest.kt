package com.auth0.android.embedded.authorize

import com.auth0.android.Auth0Exception
import com.auth0.android.callback.Callback
import com.auth0.android.embedded.EmbeddedAuthException
import com.auth0.android.request.Request
import com.auth0.android.result.Credentials

/**
 * Runs one step of the embedded flow as a single [Request]. On a step failure the session is rotated
 * or cleared via [onStepFailure]; on the `200` that ends `/e/authorize` the authorization code is
 * exchanged for [Credentials] and the flow is completed via [onFlowComplete] only once that succeeds,
 * so a failed token exchange leaves the session intact for the caller to retry.
 */
internal class AdvancingRequest(
    private val authorize: Request<AuthorizeCode, EmbeddedAuthException>,
    private val exchange: (authorizationCode: String) -> Request<Credentials, EmbeddedAuthException>,
    private val onStepFailure: (EmbeddedAuthException) -> Unit,
    private val onFlowComplete: () -> Unit
) : Request<Credentials, EmbeddedAuthException> {

    override fun start(callback: Callback<Credentials, EmbeddedAuthException>) {
        authorize.start(object : Callback<AuthorizeCode, EmbeddedAuthException> {
            override fun onSuccess(result: AuthorizeCode) {
                exchange(result.authorizationCode).start(object : Callback<Credentials, EmbeddedAuthException> {
                    override fun onSuccess(result: Credentials) {
                        onFlowComplete()
                        callback.onSuccess(result)
                    }

                    override fun onFailure(error: EmbeddedAuthException) = callback.onFailure(error)
                })
            }

            override fun onFailure(error: EmbeddedAuthException) {
                onStepFailure(error)
                callback.onFailure(error)
            }
        })
    }

    @Throws(Auth0Exception::class)
    override suspend fun await(): Credentials {
        val code = try {
            authorize.await()
        } catch (error: EmbeddedAuthException) {
            onStepFailure(error)
            throw error
        }
        return exchange(code.authorizationCode).await().also { onFlowComplete() }
    }

    @Throws(Auth0Exception::class)
    override fun execute(): Credentials {
        val code = try {
            authorize.execute()
        } catch (error: EmbeddedAuthException) {
            onStepFailure(error)
            throw error
        }
        return exchange(code.authorizationCode).execute().also { onFlowComplete() }
    }

    override fun addParameters(parameters: Map<String, String>): Request<Credentials, EmbeddedAuthException> {
        authorize.addParameters(parameters)
        return this
    }

    override fun addParameter(name: String, value: String): Request<Credentials, EmbeddedAuthException> {
        authorize.addParameter(name, value)
        return this
    }

    override fun addHeader(name: String, value: String): Request<Credentials, EmbeddedAuthException> {
        authorize.addHeader(name, value)
        return this
    }
}
