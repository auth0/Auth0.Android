package com.auth0.android.request.internal

import com.auth0.android.request.HttpMethod
import com.auth0.android.request.NetworkingClient
import com.auth0.android.request.RequestOptions
import com.auth0.android.request.ServerResponse
import okhttp3.*
import okhttp3.Headers.Companion.toHeaders
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.logging.HttpLoggingInterceptor
import java.io.IOException
import java.util.concurrent.TimeUnit

//TODO: Should this be internal?
private class OkClient : NetworkingClient {
    private var client: OkHttpClient

    /**
     * Creates and executes a networking request blocking
     */
    @Throws(IllegalArgumentException::class, IOException::class)
    override fun load(url: String, options: RequestOptions): ServerResponse {
        val httpUrl = url.toHttpUrl()
        if (!httpUrl.isHttps) {
            throw IllegalArgumentException("The URL must use HTTPS")
        }

        val call = prepareCall(httpUrl, options)
        val response = call.execute()

        return ServerResponse(
            response.code,
            response.body!!.byteStream(),
            response.headers.toMultimap()
        )
    }

    private fun prepareCall(url: HttpUrl, options: RequestOptions): Call {
        val requestBuilder = Request.Builder()
        val urlBuilder = url.newBuilder()

        when (options.method) {
            is HttpMethod.GET -> {
                //add parameters as query
                options.parameters.map { urlBuilder.addQueryParameter(it.key, it.value) }
                requestBuilder.get()
            }
            is HttpMethod.POST -> {
                //add parameters as body
                val body: RequestBody = null!! //TODO() use OkHttp v4 FormBody
                requestBuilder.post(body)
            }
        }
        val request = requestBuilder
            .url(urlBuilder.build())
            .headers(options.headers.toHeaders())
            .build()
        return client.newCall(request)
    }

    init {
        // possible constructor parameters
        val enableLogging = true
        val connectTimeout = DEFAULT_TIMEOUT_SECONDS
        val readTimeout = DEFAULT_TIMEOUT_SECONDS

        // client setup
        val builder = OkHttpClient.Builder()

        // logging
        if (enableLogging) {
            val logger: Interceptor = HttpLoggingInterceptor()
                .setLevel(HttpLoggingInterceptor.Level.BODY)
            builder.addInterceptor(logger)
        }

        // timeouts
        builder.connectTimeout(connectTimeout, TimeUnit.SECONDS)
        builder.readTimeout(readTimeout, TimeUnit.SECONDS)

        client = builder.build()
    }


    private companion object {
        private const val DEFAULT_TIMEOUT_SECONDS: Long = 10
    }

}