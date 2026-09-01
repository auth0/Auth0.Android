package com.auth0.android.embedded

import com.auth0.android.Auth0
import com.auth0.android.Auth0Exception
import com.auth0.android.NetworkErrorException
import com.auth0.android.request.ErrorAdapter
import com.auth0.android.request.JsonAdapter
import com.auth0.android.request.Request
import com.auth0.android.request.internal.GsonAdapter
import com.auth0.android.request.internal.GsonAdapter.Companion.forMap
import com.auth0.android.request.internal.GsonProvider
import com.auth0.android.request.internal.RequestFactory
import com.auth0.android.request.internal.ResponseUtils.isNetworkError
import com.google.gson.Gson
import okhttp3.HttpUrl.Companion.toHttpUrl
import java.io.IOException
import java.io.Reader

/**
 * API client for Auth0's embedded authentication API.
 *
 * ```
 * val auth0 = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN")
 * val client = EmbeddedAuthClient(auth0)
 * ```
 *
 */
public class EmbeddedAuthClient(private val auth0: Auth0) {

    private val factory: RequestFactory<EmbeddedAuthException> =
        RequestFactory(auth0.networkingClient, createErrorAdapter())

    private val gson: Gson = GsonProvider.gson

    private val clientId: String
        get() = auth0.clientId

    /**
     *
     * Fetches the list of login grant types enabled for the client
     *
     * Example usage:
     *
     * ```
     * client.discover("my-connection")
     *     .start(object : Callback<DiscoveryResult, EmbeddedAuthException> {
     *         override fun onSuccess(result: DiscoveryResult) { }
     *         override fun onFailure(error: EmbeddedAuthException) { }
     *     })
     * ```
     *
     * @param connection name of the connection to limit the results to. When omitted, all the
     * client's enabled connections are considered.
     * @return a request to configure and start that will yield a [DiscoveryResult]
     */
    @JvmOverloads
    public fun discover(connection: String? = null): Request<DiscoveryResult, EmbeddedAuthException> {
        val url = auth0.getDomainUrl().toHttpUrl().newBuilder()
            .addPathSegment(EMBEDDED_PATH)
            .addPathSegment(DISCOVERY_PATH)
            .addQueryParameter(CLIENT_ID_KEY, clientId)
            .apply { connection?.let { addQueryParameter(CONNECTION_KEY, it) } }
            .build()

        return factory.get(url.toString(), discoveryAdapter(gson))
    }

    private companion object {
        private const val EMBEDDED_PATH = "e"
        private const val DISCOVERY_PATH = "discovery"
        private const val CLIENT_ID_KEY = "client_id"
        private const val CONNECTION_KEY = "connection"
        private const val ERROR_KEY = "error"
        private const val ERROR_DESCRIPTION_KEY = "error_description"
        private const val DEFAULT_DESCRIPTION =
            "An error occurred when trying to authenticate with the server."

        /**
         * Parses the wire payload and translates it into the public [DiscoveryResult].
         */
        private fun discoveryAdapter(gson: Gson): JsonAdapter<DiscoveryResult> {
            val adapter = GsonAdapter(DiscoveryResponse::class.java, gson)
            return object : JsonAdapter<DiscoveryResult> {
                @Throws(IOException::class)
                override fun fromJson(
                    reader: Reader,
                    metadata: Map<String, Any>
                ): DiscoveryResult = adapter.fromJson(reader, metadata).toDiscoveryResult()
            }
        }

        private fun createErrorAdapter(): ErrorAdapter<EmbeddedAuthException> {
            val mapAdapter = forMap(GsonProvider.gson)
            return object : ErrorAdapter<EmbeddedAuthException> {
                /**
                 * The response body was not JSON. Notably the case for the `404` returned when
                 * embedded authentication is not enabled for the tenant, whose body is empty.
                 */
                override fun fromRawResponse(
                    statusCode: Int,
                    bodyText: String,
                    headers: Map<String, List<String>>
                ): EmbeddedAuthException {
                    return if (bodyText.isBlank()) EmbeddedAuthException(
                        Auth0Exception.EMPTY_BODY_ERROR,
                        Auth0Exception.EMPTY_RESPONSE_BODY_DESCRIPTION,
                        statusCode
                    ) else EmbeddedAuthException(
                        Auth0Exception.NON_JSON_ERROR,
                        bodyText,
                        statusCode
                    )
                }

                @Throws(IOException::class)
                override fun fromJsonResponse(
                    statusCode: Int,
                    reader: Reader
                ): EmbeddedAuthException {
                    val values = mapAdapter.fromJson(reader)
                    return EmbeddedAuthException(
                        values[ERROR_KEY] as? String ?: Auth0Exception.UNKNOWN_ERROR,
                        values[ERROR_DESCRIPTION_KEY] as? String ?: DEFAULT_DESCRIPTION,
                        statusCode
                    )
                }

                override fun fromException(cause: Throwable): EmbeddedAuthException {
                    return if (isNetworkError(cause)) EmbeddedAuthException(
                        Auth0Exception.UNKNOWN_ERROR,
                        "Failed to execute the network request",
                        cause = NetworkErrorException(cause)
                    ) else EmbeddedAuthException(
                        Auth0Exception.UNKNOWN_ERROR,
                        DEFAULT_DESCRIPTION,
                        cause = Auth0Exception(DEFAULT_DESCRIPTION, cause)
                    )
                }
            }
        }
    }

    init {
        factory.setAuth0ClientInfo(auth0.auth0UserAgent.value)
    }
}
