package com.auth0.android.embedded

import android.util.Log
import com.auth0.android.request.NetworkingClient
import com.auth0.android.request.RequestOptions
import com.auth0.android.request.ServerResponse

/**
 * Networking client that answers `GET /e/discovery` with [FakeDiscoveryData] instead of calling it.
 *
 * The endpoint currently hardcodes `{"alternatives": []}` (EMBL-1301 has not landed) and is gated
 * behind a tenant flag, so calling it for real yields either an empty result or a `404`.
 *
 * Intercepting here rather than in the result adapter keeps the request fully constructed and the
 * canned payload an ordinary `200` body, so the JSON adapter, the mapping to [DiscoveryResult], and
 * the error adapter all run as they will against the real server. Any other request is delegated
 * untouched.
 *
 * Delete this class once the server derives the response, and pass `auth0.networkingClient` straight
 * to the request factory in [EmbeddedAuthClient].
 *
 * @param delegate the client to hand every non-discovery request to.
 */
internal class FakeDiscoveryClient(private val delegate: NetworkingClient) : NetworkingClient {

    override fun load(url: String, options: RequestOptions): ServerResponse {
        if (!url.substringBefore('?').endsWith(DISCOVERY_PATH_SUFFIX)) {
            return delegate.load(url, options)
        }
        Log.d(TAG, "Answering ${options.method} $url with canned discovery data")
        return ServerResponse(
            HTTP_OK,
            FakeDiscoveryData.SUCCESS_RESPONSE.byteInputStream(),
            mapOf(CONTENT_TYPE_HEADER to listOf(APPLICATION_JSON))
        )
    }

    private companion object {
        private const val TAG = "FakeDiscoveryClient"
        private const val DISCOVERY_PATH_SUFFIX = "/e/discovery"
        private const val HTTP_OK = 200
        private const val CONTENT_TYPE_HEADER = "Content-Type"
        private const val APPLICATION_JSON = "application/json"
    }
}
