package com.auth0.android.provider

import android.net.Uri
import com.auth0.android.Auth0
import com.auth0.android.authentication.AuthenticationException
import androidx.core.net.toUri

/**
 * Shared utilities for PAR (Pushed Authorization Request) flows.
 */
internal object PARUtils {

    internal const val REQUEST_URI_PREFIX = "urn:ietf:params:oauth:request_uri:"

    /**
     * Validates that the request_uri conforms to the expected format.
     * @return true if valid, false otherwise.
     */
    fun isValidRequestUri(requestUri: String): Boolean {
        return requestUri.startsWith(REQUEST_URI_PREFIX)
    }

    /**
     * Builds a minimal /authorize URI for PAR flows containing only client_id and request_uri,
     * plus any additional query parameters.
     */
    fun buildAuthorizeUri(
        account: Auth0,
        requestUri: String,
        additionalParameters: Map<String, String> = emptyMap()
    ): Uri {
        val builder = account.authorizeUrl.toUri().buildUpon()
            .appendQueryParameter("client_id", account.clientId)
            .appendQueryParameter("request_uri", requestUri)
        for ((key, value) in additionalParameters) {
            builder.appendQueryParameter(key, value)
        }
        return builder.build()
    }
}
