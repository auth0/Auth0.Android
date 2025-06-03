package com.auth0.android.request.internal

import androidx.annotation.VisibleForTesting
import com.auth0.android.Auth0Exception
import com.auth0.android.request.*
import com.auth0.android.util.Auth0UserAgent
import java.io.Reader
import java.util.*

internal class RequestFactory<U : Auth0Exception> internal constructor(
    private val client: NetworkingClient,
    private val errorAdapter: ErrorAdapter<U>
) {

    private companion object {
        private const val DEFAULT_LOCALE_IF_MISSING = "en_US"
        private const val ACCEPT_LANGUAGE_HEADER = "Accept-Language"
        private const val AUTH0_CLIENT_INFO_HEADER = Auth0UserAgent.HEADER_NAME

        val defaultLocale: String
            get() {
                val language = Locale.getDefault().toString()
                return if (language.isNotEmpty()) language else DEFAULT_LOCALE_IF_MISSING
            }
    }

    private val baseHeaders = mutableMapOf(Pair(ACCEPT_LANGUAGE_HEADER, defaultLocale))

    fun <T> post(
        url: String,
        resultAdapter: JsonAdapter<T>
    ): Request<T, U> = setupRequest(HttpMethod.POST, url, resultAdapter, errorAdapter)

    fun post(url: String): Request<Void?, U> =
        this.post(url, object : JsonAdapter<Void?> {
            override fun fromJson(reader: Reader, metadata: Map<String, Any>): Void? {
                return null
            }
        })

    fun <T> patch(
        url: String,
        resultAdapter: JsonAdapter<T>
    ): Request<T, U> = setupRequest(HttpMethod.PATCH, url, resultAdapter, errorAdapter)

    fun <T> delete(
        url: String,
        resultAdapter: JsonAdapter<T>
    ): Request<T, U> = setupRequest(HttpMethod.DELETE, url, resultAdapter, errorAdapter)

    fun <T> get(
        url: String,
        resultAdapter: JsonAdapter<T>
    ): Request<T, U> = setupRequest(HttpMethod.GET, url, resultAdapter, errorAdapter)

    fun setHeader(name: String, value: String) {
        baseHeaders[name] = value
    }

    fun setAuth0ClientInfo(clientInfo: String) {
        baseHeaders[AUTH0_CLIENT_INFO_HEADER] = clientInfo
    }

    @VisibleForTesting
    fun <T> createRequest(
        method: HttpMethod,
        url: String,
        client: NetworkingClient,
        resultAdapter: JsonAdapter<T>,
        errorAdapter: ErrorAdapter<U>,
        threadSwitcher: ThreadSwitcher
    ): Request<T, U> = BaseRequest(method, url, client, resultAdapter, errorAdapter, threadSwitcher)


    private fun <T> setupRequest(
        method: HttpMethod,
        url: String,
        resultAdapter: JsonAdapter<T>,
        errorAdapter: ErrorAdapter<U>
    ): Request<T, U> {
        val request =
            createRequest(
                method,
                url,
                client,
                resultAdapter,
                errorAdapter,
                CommonThreadSwitcher.getInstance()
            )
        baseHeaders.map { request.addHeader(it.key, it.value) }
        return request
    }

}