package com.auth0.android

import android.content.Context
import com.auth0.android.request.DefaultClient
import com.auth0.android.request.NetworkingClient
import com.auth0.android.util.Auth0UserAgent
import okhttp3.HttpUrl
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
 *
 * @param clientId            of your Auth0 application
 * @param domain              of your Auth0 account
 * @param configurationDomain where Auth0's configuration will be fetched, change it if using an on-premise Auth0 server. By default is Auth0 public cloud.
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
     * @return Auth0 user agent information sent in every request
     */
    public var auth0UserAgent: Auth0UserAgent

    /**
     * The networking client instance used to make HTTP requests.
     */
    public var networkingClient: NetworkingClient = DefaultClient()

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
    public open val authorizeUrl: String
        get() = domainUrl!!.newBuilder()
            .addEncodedPathSegment("authorize")
            .build()
            .toString()

    /**
     * Obtain the logout URL for the current domain
     *
     * @return Url to call to perform the web logout
     */
    public open val logoutUrl: String
        get() = domainUrl!!.newBuilder()
            .addEncodedPathSegment("v2")
            .addEncodedPathSegment("logout")
            .build()
            .toString()

    private fun ensureValidUrl(url: String?): HttpUrl? {
        if (url == null) {
            return null
        }
        val normalizedUrl = url.lowercase(Locale.ROOT)
        require(!normalizedUrl.startsWith("http://")) { "Invalid domain url: '$url'. Only HTTPS domain URLs are supported. If no scheme is passed, HTTPS will be used." }
        val safeUrl =
            if (normalizedUrl.startsWith("https://")) normalizedUrl else "https://$normalizedUrl"
        return safeUrl.toHttpUrlOrNull()
    }

    private companion object {
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

    init {
        domainUrl = ensureValidUrl(domain)
        requireNotNull(domainUrl) { String.format("Invalid domain url: '%s'", domain) }
        configurationUrl = ensureValidUrl(configurationDomain) ?: domainUrl
        auth0UserAgent = Auth0UserAgent()
    }
}