package com.auth0.android.request

import androidx.annotation.VisibleForTesting
import com.auth0.android.dpop.DPoPUtil
import com.auth0.android.request.internal.GsonProvider
import com.google.gson.Gson
import okhttp3.Call
import okhttp3.Headers
import okhttp3.Headers.Companion.toHeaders
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.Interceptor
import okhttp3.MediaType
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
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
    ) : this(
        connectTimeout,
        readTimeout,
        defaultHeaders,
        enableLogging,
        GsonProvider.gson,
        null,
        null
    )

    @get:VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    internal val okHttpClient: OkHttpClient

    // Using another client to prevent OkHttp from retrying network calls especially when using DPoP with replay protection mechanism.
    // https://auth0team.atlassian.net/browse/ESD-56048.
    // TODO: This should be replaced with the chain.retryOnConnectionFailure() API when we update to OkHttp 5+
    @get:VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    internal val nonRetryableOkHttpClient: OkHttpClient

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

        // Use non-retryable client for DPoP requests
        val client = if (shouldUseNonRetryableClient(headers)) {
            nonRetryableOkHttpClient
        } else {
            okHttpClient
        }

        return client.newCall(request)
    }

    /**
     * Determines if the request should use the non-retryable OkHttpClient.
     * Returns true for:
     * 1. Requests with DPoP header
     */
    private fun shouldUseNonRetryableClient(
        headers: Headers
    ): Boolean {
        return headers[DPoPUtil.DPOP_HEADER] != null
    }

    init {
        val builder = OkHttpClient.Builder()
        // Add retry interceptor
        builder.addInterceptor(RetryInterceptor())

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

        // Non-retryable client for DPoP requests
        nonRetryableOkHttpClient = okHttpClient.newBuilder()
            .retryOnConnectionFailure(false)
            .build()
    }


    internal companion object {
        const val DEFAULT_TIMEOUT_SECONDS: Int = 10
        val APPLICATION_JSON_UTF8: MediaType =
            "application/json; charset=utf-8".toMediaType()
    }

}