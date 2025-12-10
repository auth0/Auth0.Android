package com.auth0.android.request.internal

import androidx.annotation.VisibleForTesting
import com.auth0.android.Auth0Exception
import com.auth0.android.callback.Callback
import com.auth0.android.dpop.DPoP
import com.auth0.android.dpop.DPoPException
import com.auth0.android.dpop.DPoPUtil
import com.auth0.android.request.ErrorAdapter
import com.auth0.android.request.HttpMethod
import com.auth0.android.request.JsonAdapter
import com.auth0.android.request.NetworkingClient
import com.auth0.android.request.Request
import com.auth0.android.request.RequestOptions
import com.auth0.android.request.RequestValidator
import com.auth0.android.request.ServerResponse
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.IOException
import java.io.InputStreamReader
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
    private val method: HttpMethod,
    private val url: String,
    private val client: NetworkingClient,
    private val resultAdapter: JsonAdapter<T>,
    private val errorAdapter: ErrorAdapter<U>,
    private val threadSwitcher: ThreadSwitcher = CommonThreadSwitcher.getInstance(),
    private val dPoP: DPoP? = null
) : Request<T, U> {

    private val options: RequestOptions = RequestOptions(method)

    private val validators = mutableListOf<RequestValidator>()

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

    override fun addParameter(name: String, value: Any): Request<T, U> {
        options.parameters[name] = value
        return this
    }

    override fun addValidator(validator: RequestValidator): Request<T, U> {
        validators.add(validator)
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
     * Runs an asynchronous network request on a thread from [Dispatchers.IO]
     * The result is parsed into a <T> value or a <U> exception is thrown if something went wrong.
     * This is a Coroutine that is exposed only for Kotlin.
     */
    @JvmSynthetic
    @kotlin.jvm.Throws(Auth0Exception::class)
    override suspend fun await(): T {
        return switchRequestContext(Dispatchers.IO) {
            execute()
        }
    }

    /**
     * Used to switch to the provided [CoroutineDispatcher].
     * This extra method is used to mock and verify during testing. It is not exposed to public.
     */
    @VisibleForTesting
    internal suspend fun switchRequestContext(
        dispatcher: CoroutineDispatcher,
        runnable: () -> T
    ): T {
        return withContext(dispatcher) {
            return@withContext runnable.invoke()
        }
    }

    /**
     * Blocks the thread and executes the network request.
     * The result is parsed into a <T> value or a <U> exception is thrown if something went wrong.
     */
    @kotlin.jvm.Throws(Auth0Exception::class)
    override fun execute(): T {
        runClientValidation()
        val response: ServerResponse
        try {
            if (dPoP?.shouldGenerateProof(url, options.parameters) == true) {
                dPoP.generateKeyPair()
                dPoP.generateProof(url, method, options.headers)?.let {
                    options.headers[DPoPUtil.DPOP_HEADER] = it
                }
            }
            response = client.load(url, options)
        } catch (exception: DPoPException) {
            throw errorAdapter.fromException(exception)
        } catch (exception: IOException) {
            //1. Network exceptions, timeouts, etc
            val error: U = errorAdapter.fromException(exception)
            throw error
        }

        InputStreamReader(response.body, StandardCharsets.UTF_8).use { reader ->
            if (response.isSuccess()) {
                //2. Successful scenario. Response of type T
                return try {
                    resultAdapter.fromJson(reader, response.headers)
                } catch (exception: Exception) {
                    //multi catch IOException and JsonParseException (including JsonIOException)
                    //3. Network exceptions, timeouts, etc reading response body
                    val error: U = errorAdapter.fromException(exception)
                    throw error
                }
            }

            //4. Error scenario. Response of type U
            val error: U = try {
                if (response.isJson()) {
                    errorAdapter.fromJsonResponse(response.statusCode, reader)
                } else {
                    errorAdapter.fromRawResponse(
                        response.statusCode,
                        reader.readText(),
                        response.headers
                    )
                }
            } catch (exception: Exception) {
                //multi catch IOException and JsonParseException (including JsonIOException)
                //5. Network exceptions, timeouts, etc reading response body
                errorAdapter.fromException(exception)
            }
            throw error
        }
    }

    private fun runClientValidation() {
        validators.forEach { validator ->
            validator.validate(options)
        }
    }

}
