/*
 * BaseRequest.java
 *
 * Copyright (c) 2015 Auth0 (http://auth0.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package com.auth0.android.request.internal

import com.auth0.android.Auth0Exception
import com.auth0.android.callback.Callback
import com.auth0.android.request.*
import java.io.IOException
import java.nio.charset.Charset

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
    private val threadSwitcher: ThreadSwitcher = DefaultThreadSwitcher
) : Request<T, U> {

    private val options: RequestOptions = RequestOptions(method)

    override fun addHeader(name: String, value: String): Request<T, U> {
        options.headers[name] = value
        return this
    }

    override fun addParameters(parameters: Map<String, String>): Request<T, U> {
        options.parameters.putAll(parameters)
        return this
    }

    override fun addParameter(name: String, value: String): Request<T, U> {
        options.parameters[name] = value
        return this
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
                val result: T? = execute()
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
    override fun execute(): T? {
        val response: ServerResponse
        try {
            response = client.load(url, options)
        } catch (exception: IOException) {
            //1. Network exceptions, timeouts, etc
            val error: U = errorAdapter.fromException(exception)
            throw error
        }

        val reader = AwareInputStreamReader(response.body, Charset.defaultCharset())
        if (response.isSuccess()) {
            //2. Successful scenario. Response of type T
            val result: T? = resultAdapter.fromJson(reader)
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
