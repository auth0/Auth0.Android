package com.auth0.android.request

import androidx.annotation.VisibleForTesting
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
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.X509TrustManager


/**
 * Default implementation of a Networking Client.
 */
public class DefaultClient @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE) internal constructor(
    connectTimeout: Int,
    readTimeout: Int,
    private val defaultHeaders: Map<String, String>,
    enableLogging: Boolean,
    private val gson: Gson,
    sslSocketFactory: SSLSocketFactory?,
    trustManager: X509TrustManager?
) : NetworkingClient {

    /**
     * Create a new DefaultClient.
     *
     * @param connectTimeout the connection timeout, in seconds, to use when executing requests. Default is ten seconds.
     * @param readTimeout the read timeout, in seconds, to use when executing requests. Default is ten seconds.
     * @param defaultHeaders any headers that should be sent on all requests. If a specific request specifies a header with the same key as any header in the default headers, the header specified on the request will take precedence. Default is an empty map.
     * @param enableLogging whether HTTP request and response info should be logged. This should only be set to `true` for debugging purposes in non-production environments, as sensitive information is included in the logs. Defaults to `false`.
     */
    @JvmOverloads
    public constructor(
        connectTimeout: Int = DEFAULT_TIMEOUT_SECONDS,
        readTimeout: Int = DEFAULT_TIMEOUT_SECONDS,
        defaultHeaders: Map<String, String> = mapOf(),
        enableLogging: Boolean = false,
    ) : this(connectTimeout, readTimeout, defaultHeaders, enableLogging, GsonProvider.gson, null, null)

    @get:VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    internal val okHttpClient: OkHttpClient

    @Throws(IllegalArgumentException::class, IOException::class)
    override fun load(url: String, options: RequestOptions): ServerResponse {
        val response = prepareCall(url.toHttpUrl(), options).execute()

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
        val headers = defaultHeaders.plus(options.headers).toHeaders()
        val request = requestBuilder
            .url(urlBuilder.build())
            .headers(headers)
            .build()
        return okHttpClient.newCall(request)
    }

    init {
        // client setup
        val builder = OkHttpClient.Builder()

        // logging
        if (enableLogging) {
            val logger: Interceptor = HttpLoggingInterceptor()
                .setLevel(HttpLoggingInterceptor.Level.BODY)
            builder.addInterceptor(logger)
        }

        // timeouts
        builder.connectTimeout(connectTimeout.toLong(), TimeUnit.SECONDS)
        builder.readTimeout(readTimeout.toLong(), TimeUnit.SECONDS)

        // testing with ssl hook (internal constructor params visibility only)
        if (sslSocketFactory != null && trustManager != null) {
            builder.sslSocketFactory(sslSocketFactory, trustManager)
        }

        okHttpClient = builder.build()
    }


    internal companion object {
        const val DEFAULT_TIMEOUT_SECONDS: Int = 10
        val APPLICATION_JSON_UTF8: MediaType =
            "application/json; charset=utf-8".toMediaType()
    }

}