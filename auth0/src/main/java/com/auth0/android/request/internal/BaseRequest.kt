package com.auth0.android.request.internal

import com.auth0.android.Auth0Exception
import com.auth0.android.callback.Callback
import com.auth0.android.request.*
import java.io.IOException
import java.nio.charset.StandardCharsets

/**
 * Base class for every request on this library.
 * @param method the HTTP method to use on this request.
 * @param url the destination URL to open the connection against.
 * @param client the client that will execute this request.
 * @param resultAdapter the adapter that will convert a successful response into the expected type.
 * @param errorAdapter the adapter that will convert a failed response into the expected type.
 */
internal open class BaseRequest<T, U : Auth0Exception>(
    method: HttpMethod,
    private val url: String,
    private val client: NetworkingClient,
    private val resultAdapter: JsonAdapter<T>,
    private val errorAdapter: ErrorAdapter<U>,
    private val threadSwitcher: ThreadSwitcher = CommonThreadSwitcher.getInstance()
) : Request<T, U> {

    private val options: RequestOptions = RequestOptions(method)

    override fun addHeader(name: String, value: String): Request<T, U> {
        options.headers[name] = value
        return this
    }

    override fun addParameters(parameters: Map<String, String>): Request<T, U> {
        val mapCopy = parameters.toMutableMap()
        if (parameters.containsKey(OidcUtils.KEY_SCOPE)) {
            val updatedScope =
                OidcUtils.includeRequiredScope(parameters.getValue(OidcUtils.KEY_SCOPE))
            mapCopy[OidcUtils.KEY_SCOPE] = updatedScope
        }
        options.parameters.putAll(mapCopy)
        return this
    }

    override fun addParameter(name: String, value: String): Request<T, U> {
        val anyValue: Any = if (name == OidcUtils.KEY_SCOPE) {
            OidcUtils.includeRequiredScope(value)
        } else {
            value
        }
        return addParameter(name, anyValue)
    }

    internal fun addParameter(name: String, value: Any): Request<T, U> {
        options.parameters[name] = value
        return this
    }

    /**
     * Runs asynchronously and executes the network request, without blocking the current thread.
     * The result is parsed into a <T> value and posted in the callback's onSuccess method or a <U>
     * exception is raised and posted in the callback's onFailure method if something went wrong.
     * @param callback the callback to post the results in. Uses the Main thread.
     */
    override fun start(callback: Callback<T, U>) {
        threadSwitcher.backgroundThread {
            try {
                val result: T = execute()
                threadSwitcher.mainThread {
                    callback.onSuccess(result)
                }
            } catch (error: Auth0Exception) {
                @Suppress("UNCHECKED_CAST") // https://youtrack.jetbrains.com/issue/KT-11774
                val uError: U = error as? U ?: errorAdapter.fromException(error)
                threadSwitcher.mainThread {
                    callback.onFailure(uError)
                }
            }
        }
    }

    /**
     * Blocks the thread and executes the network request.
     * The result is parsed into a <T> value or a <U> exception is thrown if something went wrong.
     */
    @kotlin.jvm.Throws(Auth0Exception::class)
    override fun execute(): T {
        val response: ServerResponse
        try {
            response = client.load(url, options)
        } catch (exception: IOException) {
            //1. Network exceptions, timeouts, etc
            val error: U = errorAdapter.fromException(exception)
            throw error
        }

        val reader = AwareInputStreamReader(response.body, StandardCharsets.UTF_8)
        if (response.isSuccess()) {
            //2. Successful scenario. Response of type T
            val result: T = resultAdapter.fromJson(reader)
            reader.close()
            return result
        }

        //3. Error scenario. Response of type U
        val error: U = if (response.isJson()) {
            errorAdapter.fromJsonResponse(response.statusCode, reader)
        } else {
            errorAdapter.fromRawResponse(
                response.statusCode,
                reader.readText(),
                response.headers
            )
        }
        reader.close()
        throw error
    }

}
