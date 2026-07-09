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
 *
 * Use [DefaultClient.Builder] to create a new instance with custom configuration:
 *
 * ```kotlin
 * val client = DefaultClient.Builder()
 *     .connectTimeout(30)
 *     .readTimeout(30)
 *     .writeTimeout(30)
 *     .enableLogging(true)
 *     .build()
 * ```
 *
 * The legacy constructor-based API is still supported for backward compatibility.
 */
public class DefaultClient private constructor(
    private val defaultHeaders: Map<String, String>,
    private val gson: Gson,
    okHttpClientBuilder: OkHttpClient.Builder
) : NetworkingClient {

    /**
     * Builder for creating a [DefaultClient] instance with custom configuration.
     *
     * Example usage:
     * ```kotlin
     * val client = DefaultClient.Builder()
     *     .connectTimeout(30)
     *     .readTimeout(30)
     *     .writeTimeout(30)
     *     .callTimeout(60)
     *     .defaultHeaders(mapOf("X-Custom" to "value"))
     *     .enableLogging(true)
     *     .logger(myCustomLogger)
     *     .build()
     * ```
     */
    public class Builder {
        private var connectTimeout: Int = DEFAULT_TIMEOUT_SECONDS
        private var readTimeout: Int = DEFAULT_TIMEOUT_SECONDS
        private var writeTimeout: Int = DEFAULT_TIMEOUT_SECONDS
        private var callTimeout: Int = 0
        private var defaultHeaders: Map<String, String> = mapOf()
        private var enableLogging: Boolean = false
        private var logger: HttpLoggingInterceptor.Logger? = null
        private var gson: Gson = GsonProvider.gson
        private var sslSocketFactory: SSLSocketFactory? = null
        private var trustManager: X509TrustManager? = null

        /**
         * Sets the connection timeout, in seconds. Default is 10 seconds.
         */
        public fun connectTimeout(timeout: Int): Builder = apply { this.connectTimeout = timeout }

        /**
         * Sets the read timeout, in seconds. Default is 10 seconds.
         */
        public fun readTimeout(timeout: Int): Builder = apply { this.readTimeout = timeout }

        /**
         * Sets the write timeout, in seconds. Default is 10 seconds.
         */
        public fun writeTimeout(timeout: Int): Builder = apply { this.writeTimeout = timeout }

        /**
         * Sets the call timeout, in seconds. Default is 0 (no timeout).
         * This is an overall timeout that spans the entire call: resolving DNS, connecting,
         * writing the request body, server processing, and reading the response body.
         */
        public fun callTimeout(timeout: Int): Builder = apply { this.callTimeout = timeout }

        /**
         * Sets default headers to include on all requests. If a specific request specifies
         * a header with the same key, the request-level header takes precedence.
         */
        public fun defaultHeaders(headers: Map<String, String>): Builder =
            apply { this.defaultHeaders = headers }

        /**
         * Enables or disables HTTP logging. Should only be set to `true` for debugging
         * in non-production environments, as sensitive information may be logged.
         * Defaults to `false`.
         */
        public fun enableLogging(enable: Boolean): Builder = apply { this.enableLogging = enable }

        /**
         * Sets a custom logger for the HTTP logging interceptor.
         * Only takes effect if [enableLogging] is set to `true`.
         * If not set, the default [HttpLoggingInterceptor.Logger] (which logs to logcat) is used.
         */
        public fun logger(logger: HttpLoggingInterceptor.Logger): Builder =
            apply { this.logger = logger }

        @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
        internal fun gson(gson: Gson): Builder = apply { this.gson = gson }

        @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
        internal fun sslSocketFactory(
            sslSocketFactory: SSLSocketFactory,
            trustManager: X509TrustManager
        ): Builder = apply {
            this.sslSocketFactory = sslSocketFactory
            this.trustManager = trustManager
        }

        /**
         * Builds a new [DefaultClient] instance with the configured options.
         */
        public fun build(): DefaultClient {
            val okBuilder = OkHttpClient.Builder()

            okBuilder.addInterceptor(RetryInterceptor())

            if (enableLogging) {
                val loggingInterceptor = if (logger != null) {
                    HttpLoggingInterceptor(logger!!)
                } else {
                    HttpLoggingInterceptor()
                }
                loggingInterceptor.setLevel(HttpLoggingInterceptor.Level.BODY)
                okBuilder.addInterceptor(loggingInterceptor)
            }

            okBuilder.connectTimeout(connectTimeout.toLong(), TimeUnit.SECONDS)
            okBuilder.readTimeout(readTimeout.toLong(), TimeUnit.SECONDS)
            okBuilder.writeTimeout(writeTimeout.toLong(), TimeUnit.SECONDS)
            okBuilder.callTimeout(callTimeout.toLong(), TimeUnit.SECONDS)

            val ssl = sslSocketFactory
            val tm = trustManager
            if (ssl != null && tm != null) {
                okBuilder.sslSocketFactory(ssl, tm)
            }

            return DefaultClient(defaultHeaders, gson, okBuilder)
        }
    }

    /**
     * Create a new DefaultClient with default configuration.
     *
     * For more configuration options, use [DefaultClient.Builder].
     *
     * @param connectTimeout the connection timeout, in seconds. Default is 10 seconds.
     * @param readTimeout the read timeout, in seconds. Default is 10 seconds.
     * @param defaultHeaders headers to include on all requests. Default is an empty map.
     * @param enableLogging whether to log HTTP request/response info. Defaults to `false`.
     */
    @Deprecated(
        message = "Use DefaultClient.Builder() for more configuration options.",
        replaceWith = ReplaceWith(
            "DefaultClient.Builder()" +
                    ".connectTimeout(connectTimeout)" +
                    ".readTimeout(readTimeout)" +
                    ".defaultHeaders(defaultHeaders)" +
                    ".enableLogging(enableLogging)" +
                    ".build()"
        )
    )
    @JvmOverloads
    public constructor(
        connectTimeout: Int = DEFAULT_TIMEOUT_SECONDS,
        readTimeout: Int = DEFAULT_TIMEOUT_SECONDS,
        defaultHeaders: Map<String, String> = mapOf(),
        enableLogging: Boolean = false,
    ) : this(
        defaultHeaders = defaultHeaders,
        gson = GsonProvider.gson,
        okHttpClientBuilder = OkHttpClient.Builder().apply {
            addInterceptor(RetryInterceptor())
            if (enableLogging) {
                addInterceptor(HttpLoggingInterceptor().setLevel(HttpLoggingInterceptor.Level.BODY))
            }
            connectTimeout(connectTimeout.toLong(), TimeUnit.SECONDS)
            readTimeout(readTimeout.toLong(), TimeUnit.SECONDS)
        }
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
        okHttpClient = okHttpClientBuilder.build()

        // Non-retryable client for DPoP requests — inherits all configuration
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