/*
 * RequestFactory.java
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

import androidx.annotation.VisibleForTesting
import com.auth0.android.Auth0Exception
import com.auth0.android.request.Request
import com.auth0.android.request.kt.ErrorAdapter
import com.auth0.android.request.kt.HttpMethod
import com.auth0.android.request.kt.JsonAdapter
import com.auth0.android.request.kt.NetworkingClient
import com.auth0.android.util.Telemetry
import java.io.Reader
import java.util.*

//TODO: Might be better to receive the NetworkingClient here
public open class RequestFactory<U : Auth0Exception>(
    private val client: NetworkingClient,
    private val errorAdapter: ErrorAdapter<U>
) {

    private companion object {
        private const val DEFAULT_LOCALE_IF_MISSING = "en_US"
        private const val USER_AGENT_HEADER = "User-Agent"
        private const val ACCEPT_LANGUAGE_HEADER = "Accept-Language"
        private const val CLIENT_INFO_HEADER = Telemetry.HEADER_NAME

        val defaultLocale: String
            get() {
                val language = Locale.getDefault().toString()
                return if (language.isNotEmpty()) language else DEFAULT_LOCALE_IF_MISSING
            }
    }

    private val baseHeaders = mutableMapOf(Pair(ACCEPT_LANGUAGE_HEADER, defaultLocale))

    public fun <T> post(
        url: String,
        resultAdapter: JsonAdapter<T>
    ): Request<T, U> = setupRequest(HttpMethod.POST, url, resultAdapter, errorAdapter)

    public fun post(url: String): Request<Unit, U> =
        this.post(url, object : JsonAdapter<Unit> {
            override fun fromJson(reader: Reader) {}
        })

    public fun <T> patch(
        url: String,
        resultAdapter: JsonAdapter<T>
    ): Request<T, U> = setupRequest(HttpMethod.PATCH, url, resultAdapter, errorAdapter)

    public fun <T> delete(
        url: String,
        resultAdapter: JsonAdapter<T>
    ): Request<T, U> = setupRequest(HttpMethod.DELETE, url, resultAdapter, errorAdapter)

    public fun <T> get(
        url: String,
        resultAdapter: JsonAdapter<T>
    ): Request<T, U> = setupRequest(HttpMethod.GET, url, resultAdapter, errorAdapter)

    public fun setClientInfo(clientInfo: String) {
        baseHeaders[CLIENT_INFO_HEADER] = clientInfo
    }

    public fun setUserAgent(userAgent: String) {
        baseHeaders[USER_AGENT_HEADER] = userAgent
    }

    @VisibleForTesting
    public open fun <T> createRequest(
        method: HttpMethod,
        url: String,
        client: NetworkingClient,
        resultAdapter: JsonAdapter<T>,
        errorAdapter: ErrorAdapter<U>
    ): Request<T, U> = BaseRequest(method, url, client, resultAdapter, errorAdapter)


    private fun <T> setupRequest(
        method: HttpMethod,
        url: String,
        resultAdapter: JsonAdapter<T>,
        errorAdapter: ErrorAdapter<U>
    ): Request<T, U> {
        val request = createRequest(method, url, client, resultAdapter, errorAdapter)
        baseHeaders.map { request.addHeader(it.key, it.value) }
        return request
    }

}