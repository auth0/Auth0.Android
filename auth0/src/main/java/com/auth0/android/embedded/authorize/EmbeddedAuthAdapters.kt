package com.auth0.android.embedded.authorize

import com.auth0.android.Auth0Exception
import com.auth0.android.NetworkErrorException
import com.auth0.android.embedded.EmbeddedAuthException
import com.auth0.android.embedded.discovery.DiscoveryResponse
import com.auth0.android.embedded.discovery.DiscoveryResult
import com.auth0.android.embedded.discovery.toDiscoveryResult
import com.auth0.android.request.ErrorAdapter
import com.auth0.android.request.JsonAdapter
import com.auth0.android.request.internal.GsonAdapter
import com.auth0.android.request.internal.GsonAdapter.Companion.forMap
import com.auth0.android.request.internal.GsonProvider
import com.auth0.android.request.internal.ResponseUtils.isNetworkError
import com.google.gson.Gson
import java.io.IOException
import java.io.Reader

private const val ERROR_KEY = "error"
private const val ERROR_DESCRIPTION_KEY = "error_description"
private const val NEXT_KEY = "next"
private const val AUTH_SESSION_KEY = "auth_session"
private const val DEFAULT_DESCRIPTION =
    "An error occurred when trying to authenticate with the server."

/** Parses the discovery payload and translates it into the public [DiscoveryResult]. */
internal fun discoveryAdapter(gson: Gson): JsonAdapter<DiscoveryResult> {
    val adapter = GsonAdapter(DiscoveryResponse::class.java, gson)
    return object : JsonAdapter<DiscoveryResult> {
        @Throws(IOException::class)
        override fun fromJson(
            reader: Reader,
            metadata: Map<String, Any>
        ): DiscoveryResult = adapter.fromJson(reader, metadata).toDiscoveryResult()
    }
}

/** Parses the `200` body of `/e/authorize` into the code to exchange for tokens. */
internal fun authorizeCodeAdapter(gson: Gson): JsonAdapter<AuthorizeCode> =
    GsonAdapter(AuthorizeCode::class.java, gson)

/** Translates every embedded-authentication error response into an [EmbeddedAuthException]. */
internal fun embeddedAuthErrorAdapter(): ErrorAdapter<EmbeddedAuthException> {
    val mapAdapter = forMap(GsonProvider.gson)
    return object : ErrorAdapter<EmbeddedAuthException> {

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
            @Suppress("UNCHECKED_CAST")
            val nextRaw = values[NEXT_KEY] as? List<Map<String, Any>> ?: emptyList()
            return EmbeddedAuthException(
                values[ERROR_KEY] as? String ?: Auth0Exception.UNKNOWN_ERROR,
                values[ERROR_DESCRIPTION_KEY] as? String ?: DEFAULT_DESCRIPTION,
                statusCode,
                nextActions = nextRaw.toNextActions(),
                authSession = values[AUTH_SESSION_KEY] as? String
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
