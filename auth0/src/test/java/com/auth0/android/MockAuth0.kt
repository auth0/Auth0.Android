package com.auth0.android

import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull

/**
 * Mock implementation of [Auth0] for tests.
 * This implementation does not enforce HTTPS, and should be removed after tests are able
 * to run with the MockWebServer using HTTPS.
 */
internal class MockAuth0 @JvmOverloads constructor(
    clientId: String,
    domain: String,
    configurationDomain: String? = null
) : Auth0(clientId, domain, configurationDomain) {
    /**
     * Returns the result of calling of [HttpUrl.parse] on the provided string.
     * Overriden to not enforce HTTPS for tests.
     *
     * @param url The URL to parse
     * @return The parsed URL, or null if the `url` parameter was null.
     */
    override fun ensureValidUrl(url: String?): HttpUrl? {
        /*
        TODO [SDK-2221]: get MockWebServer running with HTTPS and remove this class. Should be done
         after updating to more recent versions of OkHttp
         */
        return url?.toHttpUrlOrNull()
    }
}