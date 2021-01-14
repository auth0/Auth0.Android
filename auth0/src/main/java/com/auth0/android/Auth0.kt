/*
 * Auth0.java
 *
 * Copyright (c) 2016 Auth0 (http://auth0.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package com.auth0.android

import android.content.Context
import androidx.annotation.VisibleForTesting
import com.auth0.android.request.DefaultClient
import com.auth0.android.util.Auth0UserAgent
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import java.util.*

/**
 * Represents your Auth0 account information (clientId &amp; domain),
 * and it's used to obtain clients for Auth0's APIs.
 *
 * ```
 * val auth0 = Auth0("YOUR_CLIENT_ID", "YOUR_DOMAIN")
 *```
 *
 * This SDK only supports OIDC-Conformant clients, and will use Auth0's current authentication pipeline.
 * For more information, please see the [OIDC adoption guide](https://auth0.com/docs/api-auth/tutorials/adoption).
 */
public open class Auth0 @JvmOverloads constructor(
    /**
     * @return your Auth0 application client identifier
     */
    public val clientId: String, domain: String, configurationDomain: String? = null
) {
    private val domainUrl: HttpUrl?
    private val configurationUrl: HttpUrl

    /**
     * @return Auth0 user agent info sent in every request
     */
    public var auth0UserAgent: Auth0UserAgent? = null
        private set
    /**
     * Whether HTTP request and response info should be logged.
     * This should only be set to `true` for debugging purposes in non-production environments, as sensitive information is included in the logs.
     * Defaults to `false`.
     */
    @Deprecated(
        "Create a DefaultClient and specify enableLogging = true|false instead. This can then be included when creating the WebAuthProvider or the API clients"
    )
    public var isLoggingEnabled: Boolean = false
    /**
     * Getter for whether TLS 1.2 is enforced on devices with API 16-21.
     *
     * @return whether TLS 1.2 is enforced on devices with API 16-21.
     */
    /**
     * Set whether to enforce TLS 1.2 on devices with API 16-21.
     *
     * @param enforced whether TLS 1.2 is enforced on devices with API 16-21.
     */
    public var isTLS12Enforced: Boolean = false

    /**
     * The connection timeout for network requests, in seconds. Defaults to 10 seconds.
     */
    @Deprecated(
        "Create a DefaultClient and specify the connectTimeout instead. This can then be included when creating the WebAuthProvider or the API clients"
    )
    public var connectTimeoutInSeconds: Int = DefaultClient.DEFAULT_TIMEOUT_SECONDS

    /**
     * The read timeout, in seconds, to use when executing requests. Default is ten seconds.
     */
    @Deprecated(
        "Create a DefaultClient and specify the readTimeout instead. This can then be included when creating the WebAuthProvider or the API clients"
    )
    public var readTimeoutInSeconds: Int = DefaultClient.DEFAULT_TIMEOUT_SECONDS

    /**
     * @return Auth0 request writeTimeoutInSeconds
     */
    /**
     * Set the write timeout for network requests.
     * By default, this value is 10 seconds.
     *
     * @param timeout the new timeout value in seconds
     */
    // TODO - remove this, only expose connect and read timeouts
    public var writeTimeoutInSeconds: Int = 0

    /**
     * Creates a new Auth0 instance with the 'com_auth0_client_id' and 'com_auth0_domain' values
     * defined in the project String resources file.
     * If the values are not found, IllegalArgumentException will raise.
     *
     * @param context a valid context
     */
    public constructor(context: Context) : this(
        getResourceFromContext(context, "com_auth0_client_id"),
        getResourceFromContext(context, "com_auth0_domain")
    )

    /**
     * @return your Auth0 account domain url
     */
    public fun getDomainUrl(): String {
        return domainUrl.toString()
    }

    /**
     * @return your account configuration url
     */
    public fun getConfigurationUrl(): String {
        return configurationUrl.toString()
    }

    /**
     * Obtain the authorize URL for the current domain
     *
     * @return Url to call to perform the web flow of OAuth
     */
    public val authorizeUrl: String
        get() = domainUrl!!.newBuilder()
            .addEncodedPathSegment("authorize")
            .build()
            .toString()

    /**
     * Obtain the logout URL for the current domain
     *
     * @return Url to call to perform the web logout
     */
    public val logoutUrl: String
        get() = domainUrl!!.newBuilder()
            .addEncodedPathSegment("v2")
            .addEncodedPathSegment("logout")
            .build()
            .toString()

    /**
     * Setter for the user agent info to send in every request to Auth0.
     *
     * @param auth0UserAgent to send in every request to Auth0.
     */
    public fun setAuth0UserAgent(auth0UserAgent: Auth0UserAgent) {
        this.auth0UserAgent = auth0UserAgent
    }

    private fun resolveConfiguration(configurationDomain: String?, domainUrl: HttpUrl): HttpUrl {
        var url = ensureValidUrl(configurationDomain)
        if (url == null) {
            val host = domainUrl.host
            url = if (host.endsWith(DOT_AUTH0_DOT_COM)) {
                val parts = host.split(".").toTypedArray()
                if (parts.size > 3) {
                    ("https://cdn." + parts[parts.size - 3] + DOT_AUTH0_DOT_COM).toHttpUrl()
                } else {
                    AUTH0_US_CDN_URL.toHttpUrl()
                }
            } else {
                domainUrl
            }
        }
        return url
    }

    @VisibleForTesting
    internal open fun ensureValidUrl(url: String?): HttpUrl? {
        if (url == null) {
            return null
        }
        val normalizedUrl = url.toLowerCase(Locale.ROOT)
        require(!normalizedUrl.startsWith("http://")) { "Invalid domain url: '$url'. Only HTTPS domain URLs are supported. If no scheme is passed, HTTPS will be used." }
        val safeUrl =
            if (normalizedUrl.startsWith("https://")) normalizedUrl else "https://$normalizedUrl"
        return safeUrl.toHttpUrlOrNull()
    }

    private companion object {
        private const val AUTH0_US_CDN_URL = "https://cdn.auth0.com"
        private const val DOT_AUTH0_DOT_COM = ".auth0.com"
        private fun getResourceFromContext(context: Context, resName: String): String {
            val stringRes = context.resources.getIdentifier(resName, "string", context.packageName)
            require(stringRes != 0) {
                String.format(
                    "The 'R.string.%s' value it's not defined in your project's resources file.",
                    resName
                )
            }
            return context.getString(stringRes)
        }
    }
    /**
     * Creates a new object using clientId, domain and configuration domain.
     * Useful when using a on-premise auth0 server that is not in the public cloud,
     * otherwise we recommend using the constructor [.Auth0]
     *
     * @param clientId            of your Auth0 application
     * @param domain              of your Auth0 account
     * @param configurationDomain where Auth0's configuration will be fetched. By default is Auth0 public cloud
     */
    /**
     * Creates a new object using the Application's clientId &amp; domain
     *
     * @param clientId of your Auth0 application
     * @param domain   of your Auth0 account
     */
    init {
        domainUrl = ensureValidUrl(domain)
        requireNotNull(domainUrl) { String.format("Invalid domain url: '%s'", domain) }
        configurationUrl = resolveConfiguration(configurationDomain, domainUrl)
        auth0UserAgent = Auth0UserAgent()
    }
}