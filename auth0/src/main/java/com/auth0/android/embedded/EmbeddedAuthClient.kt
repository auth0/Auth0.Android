package com.auth0.android.embedded

import androidx.annotation.VisibleForTesting
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
 * ## Availability
 *
 * Embedded authentication is under development and is gated per tenant and per client. Calls against
 * a tenant or an application that has not been opted in will fail.
 */
public class EmbeddedAuthClient @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE) internal constructor(
    private val auth0: Auth0,
    private val factory: RequestFactory<EmbeddedAuthException>,
    private val gson: Gson
) {

    /**
     * Creates a new API client instance providing Auth0 account info.
     *
     * Example usage:
     *
     * ```
     * val auth0 = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN")
     * val client = EmbeddedAuthClient(auth0)
     * ```
     * @param auth0 account information
     */
    public constructor(auth0: Auth0) : this(
        auth0,
        RequestFactory<EmbeddedAuthException>(
            // Answers discovery locally until the server derives the response. See FakeDiscoveryClient.
            FakeDiscoveryClient(auth0.networkingClient),
            createErrorAdapter()
        ),
        GsonProvider.gson
    )

    private val clientId: String
        get() = auth0.clientId

    /**
     * Fetches the ways this client is currently able to authenticate, so a login screen can be
     * composed from real tenant configuration instead of assumptions made at build time.
     *
     * The request carries no client authentication: the response describes tenant, client, and
     * connection configuration rather than the caller's identity.
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
     * Or, with coroutines:
     *
     * ```
     * val discovery = client.discover("my-connection").await()
     * ```
     *
     * **Note:** the server does not yet derive the response, so this currently yields canned data
     * from [FakeDiscoveryData] rather than calling the endpoint. The request is still built in full,
     * and everything from the response body onwards runs for real. See [FakeDiscoveryClient].
     *
     * @param connection name of the connection to limit the results to. When omitted, all of the
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
