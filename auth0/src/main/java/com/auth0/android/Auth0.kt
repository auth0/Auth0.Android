package com.auth0.android

import android.content.Context
import com.auth0.android.request.DefaultClient
import com.auth0.android.request.NetworkingClient
import com.auth0.android.util.Auth0UserAgent
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import java.util.*
import java.util.concurrent.Executor
import java.util.concurrent.Executors

/**
 * Represents your Auth0 account information (clientId &amp; domain),
 * and it's used to obtain clients for Auth0's APIs.
 *
 * ```
 * val auth0 = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN")
 *```
 *
 * This SDK only supports OIDC-Conformant clients, and will use Auth0's current authentication pipeline.
 * For more information, please see the [OIDC adoption guide](https://auth0.com/docs/api-auth/tutorials/adoption).
 *
 * @param clientId            of your Auth0 application
 * @param domainUrl           of your Auth0 account
 * @param configurationDomain where Auth0's configuration will be fetched, change it if using an on-premise Auth0 server. By default is Auth0 public cloud.
 */
public open class Auth0 private constructor(
    /**
     * @return your Auth0 application client identifier
     */
    public val clientId: String,
    private val domainUrl: HttpUrl,
    public val configurationDomain: String? = null,
) {
    public val domain: String = domainUrl.host
    private val configurationUrl: HttpUrl = ensureValidUrl(configurationDomain) ?: domainUrl

    /**
     * @return Auth0 user agent information sent in every request
     */
    public var auth0UserAgent: Auth0UserAgent = Auth0UserAgent()

    /**
     * The networking client instance used to make HTTP requests.
     */
    public var networkingClient: NetworkingClient = DefaultClient()


    /**
     * The single thread executor used to run tasks in the background throughout this Auth0 instance.
     */
    public val executor: Executor = Executors.newSingleThreadExecutor()

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
        get() = buildAuthorizeUrl()

    /**
     * Builds the authorize URL for the current domain.
     *
     * This function constructs the URL used for the OAuth 2.0 authorization flow.  Subclasses
     * can override this function to modify the URL generation logic, for example, to use a
     * different endpoint or add custom query parameters.
     *
     * @return The URL to call to perform the web flow of OAuth.
     */
    public open fun buildAuthorizeUrl(): String { // Function instead of property
        return domainUrl.newBuilder()
            .addEncodedPathSegment("authorize")
            .build()
            .toString()
    }

    /**
     * Obtain the logout URL for the current domain
     *
     * @return Url to call to perform the web logout
     */
    public open val logoutUrl: String
        get() = buildLogoutUrl()

    /**
     * Builds the logout URL for the current domain.
     *
     * This function constructs the URL used for the logout process. Subclasses can override
     * this function to modify the URL generation logic, for example, to use a different
     * endpoint or add custom query parameters.
     *
     * @return The URL to call to perform the web logout.
     */
    public open fun buildLogoutUrl(): String {  // Function instead of property
        return domainUrl.newBuilder()
            .addEncodedPathSegment("v2")
            .addEncodedPathSegment("logout")
            .build()
            .toString()
    }


    public companion object {

        private var instance: Auth0? = null

        /**
         * Creates a new Auth0 instance with the 'com_auth0_client_id' and 'com_auth0_domain' values
         * defined in the project String resources file, if the instance with the same values doesn't exist yet and returns it.
         * If it already exists, it will return the existing instance.
         * If the values 'com_auth0_client_id' and 'com_auth0_domain' are not found in project String resources file, IllegalArgumentException will raise.
         *
         * @param context a valid context
         */
        @JvmStatic
        public fun getInstance(context: Context): Auth0 {
            val clientId = getResourceFromContext(context, "com_auth0_client_id")
            val domain = getResourceFromContext(context, "com_auth0_domain")
            return getInstance(clientId, domain)
        }

        /**
         * Creates a new Auth0 instance with the given clientId and domain, if it doesn't exist yet and returns it.
         * If it already exists, it will return the existing instance.
         */
        @JvmStatic
        public fun getInstance(
            clientId: String,
            domain: String
        ): Auth0 {
            return getInstance(clientId, domain, null)
        }


        /**
         * Creates a new Auth0 instance with the given clientId, domain and configurationDomain, if it doesn't exist yet and returns it.
         * If it already exists, it will return the existing instance.
         */
        @JvmStatic
        public fun getInstance(
            clientId: String,
            domain: String,
            configurationDomain: String?
        ): Auth0 {
            val domainUrl = ensureValidUrl(domain)
            requireNotNull(domainUrl) { String.format("Invalid domain url: '%s'", domain) }
            if (instance == null || instance?.clientId != clientId || instance?.domainUrl?.host != domainUrl.host || instance?.configurationDomain != configurationDomain) {
                instance = Auth0(clientId, domainUrl, configurationDomain)
            }
            return instance!!
        }

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
    }
}
