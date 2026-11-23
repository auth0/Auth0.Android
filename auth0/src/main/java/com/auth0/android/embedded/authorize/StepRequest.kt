package com.auth0.android.embedded.authorize

import com.auth0.android.Auth0Exception
import com.auth0.android.callback.Callback
import com.auth0.android.embedded.EmbeddedAuthException
import com.auth0.android.request.Request
import com.auth0.android.request.RequestValidator

/**
 * Runs one non-terminal step of the embedded flow as a single [Request]. These steps never yield
 * credentials, so on the continuation failure the session is rotated (or cleared) via [onStepFailure]
 * before the error it returns is propagated to the caller.
 */
internal class StepRequest(
    private val request: Request<Void?, EmbeddedAuthException>,
    private val onStepFailure: (EmbeddedAuthException) -> EmbeddedAuthException
) : Request<Void?, EmbeddedAuthException> {

    override fun start(callback: Callback<Void?, EmbeddedAuthException>) {
        request.start(object : Callback<Void?, EmbeddedAuthException> {
            override fun onSuccess(result: Void?) = callback.onSuccess(result)

            override fun onFailure(error: EmbeddedAuthException) {
                callback.onFailure(onStepFailure(error))
            }
        })
    }

    @Throws(Auth0Exception::class)
    override suspend fun await(): Void? = try {
        request.await()
    } catch (error: EmbeddedAuthException) {
        throw onStepFailure(error)
    }

    @Throws(Auth0Exception::class)
    override fun execute(): Void? = try {
        request.execute()
    } catch (error: EmbeddedAuthException) {
        throw onStepFailure(error)
    }

    override fun addParameters(parameters: Map<String, String>): Request<Void?, EmbeddedAuthException> {
        request.addParameters(parameters)
        return this
    }

    override fun addParameter(name: String, value: String): Request<Void?, EmbeddedAuthException> {
        request.addParameter(name, value)
        return this
    }

    override fun addParameter(name: String, value: Any): Request<Void?, EmbeddedAuthException> {
        request.addParameter(name, value)
        return this
    }

    override fun addHeader(name: String, value: String): Request<Void?, EmbeddedAuthException> {
        request.addHeader(name, value)
        return this
    }

    override fun addValidator(validator: RequestValidator): Request<Void?, EmbeddedAuthException> {
        request.addValidator(validator)
        return this
    }
}
