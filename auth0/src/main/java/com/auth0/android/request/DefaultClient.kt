package com.auth0.android.request

import com.auth0.android.request.internal.GsonProvider
import com.google.gson.Gson
import okhttp3.*
import okhttp3.Headers.Companion.toHeaders
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.logging.HttpLoggingInterceptor
import java.io.IOException
import java.util.concurrent.TimeUnit

/**
 * Default implementation of a Networking Client.
 */
public class DefaultClient() : NetworkingClient {

    //TODO: receive this via internal constructor parameters
    private val gson: Gson = GsonProvider.buildGson()
    private var client: OkHttpClient

    @Throws(IllegalArgumentException::class, IOException::class)
    override fun load(url: String, options: RequestOptions): ServerResponse {
        val response = prepareCall(url.toHttpUrl(), options).execute()

        //FIXME: Ensure body is being closed
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
                // add parameters as query
                options.parameters.filterValues { it is String }
                    .map { urlBuilder.addQueryParameter(it.key, it.value as String) }
                requestBuilder.method(options.method.toString(), null)
            }
            else -> {
                // add parameters as body
                val body = gson.toJson(options.parameters).toRequestBody(APPLICATION_JSON_UTF8)
                requestBuilder.method(options.method.toString(), body)
            }
        }
        val request = requestBuilder
            .url(urlBuilder.build())
            .headers(options.headers.toHeaders())
            .build()
        return client.newCall(request)
    }

    init {
        // TODO: possible constructor parameters
        val enableLogging = true
        val connectTimeout = DEFAULT_TIMEOUT_SECONDS
        val readTimeout = DEFAULT_TIMEOUT_SECONDS

        // client setup
        val builder = OkHttpClient.Builder()

        // logging
        //TODO: OFF by default!
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
        private val APPLICATION_JSON_UTF8: MediaType =
            "application/json; charset=utf-8".toMediaType()
    }

}