/*
 * WebAuthProvider.java
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
package com.auth0.android.provider

import android.content.Context
import android.content.Intent
import android.util.Log
import androidx.annotation.VisibleForTesting
import com.auth0.android.Auth0
import com.auth0.android.authentication.AuthenticationException
import com.auth0.android.callback.Callback
import com.auth0.android.request.NetworkingClient
import com.auth0.android.result.Credentials
import java.util.*

/**
 * OAuth2 Web Authentication Provider.
 *
 *
 * It uses an external browser by sending the [android.content.Intent.ACTION_VIEW] intent.
 */
public object WebAuthProvider {
    private val TAG: String? = WebAuthProvider::class.simpleName

    @JvmStatic
    @get:VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    internal var managerInstance: ResumableManager? = null
        private set

    // Public methods
    /**
     * Initialize the WebAuthProvider instance for logging out the user using an account. Additional settings can be configured
     * in the LogoutBuilder, like changing the scheme of the return to URL.
     *
     * @param account to use for authentication
     * @return a new Builder instance to customize.
     */
    @JvmStatic
    public fun logout(account: Auth0): LogoutBuilder {
        return LogoutBuilder(account)
    }

    /**
     * Initialize the WebAuthProvider instance for authenticating the user using an account. Additional settings can be configured
     * in the Builder, like setting the connection name or authentication parameters.
     *
     * @param account to use for authentication
     * @return a new Builder instance to customize.
     */
    @JvmStatic
    public fun login(account: Auth0): Builder {
        return Builder(account)
    }

    /**
     * Finishes the authentication or log out flow by passing the data received in the activity's onNewIntent() callback.
     * The final result will be delivered to the callback specified when calling start().
     *
     *
     * This is no longer required to be called, the authentication is handled internally as long as you've correctly setup the intent-filter.
     *
     * @param intent the data received on the onNewIntent() call. When null is passed, the authentication will be considered canceled.
     * @return true if a result was expected and has a valid format, or false if not. When true is returned a call on the callback is expected.
     */
    @JvmStatic
    public fun resume(intent: Intent?): Boolean {
        if (managerInstance == null) {
            Log.w(TAG, "There is no previous instance of this provider.")
            return false
        }
        val result = AuthorizeResult(intent)
        val success = managerInstance!!.resume(result)
        if (success) {
            resetManagerInstance()
        }
        return success
    }

    @JvmStatic
    @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    internal fun resetManagerInstance() {
        managerInstance = null
    }

    public class LogoutBuilder internal constructor(private val account: Auth0) {
        private var scheme = "https"
        private var returnToUrl: String? = null
        private var ctOptions: CustomTabsOptions = CustomTabsOptions.newBuilder().build()

        /**
         * When using a Custom Tabs compatible Browser, apply these customization options.
         *
         * @param options the Custom Tabs customization options
         * @return the current builder instance
         */
        public fun withCustomTabsOptions(options: CustomTabsOptions): LogoutBuilder {
            ctOptions = options
            return this
        }

        /**
         * Specify a custom Scheme to use on the Return To URL. Default scheme is 'https'.
         *
         * @param scheme to use in the Return To URL.
         * @return the current builder instance
         */
        public fun withScheme(scheme: String): LogoutBuilder {
            val lowerCase = scheme.toLowerCase(Locale.ROOT)
            if (scheme != lowerCase) {
                Log.w(
                    TAG,
                    "Please provide the scheme in lowercase and make sure it's the same configured in the intent filter. Android expects the scheme to be lowercase."
                )
            }
            this.scheme = scheme
            return this
        }

        /**
         * Specify a custom Redirect To URL to use to invoke the app on redirection.
         * Normally, you wouldn't need to call this method manually as the default value is autogenerated for you.
         * The [LogoutBuilder.withScheme] configuration is ignored when this method is called. It is your responsibility to pass a well-formed URL.
         *
         * @param returnToUrl to use to invoke the app on redirection.
         * @return the current builder instance
         */
        public fun withReturnToUrl(returnToUrl: String): LogoutBuilder {
            this.returnToUrl = returnToUrl
            return this
        }

        /**
         * Request the user session to be cleared. When successful, the callback will get invoked.
         * An error is raised if there are no browser applications installed in the device.
         *
         * @param context  to run the log out
         * @param callback to invoke when log out is successful
         * @see AuthenticationException.isBrowserAppNotAvailable
         */
        public fun start(context: Context, callback: VoidCallback) {
            resetManagerInstance()
            if (!ctOptions.hasCompatibleBrowser(context.packageManager)) {
                val ex = AuthenticationException(
                    "a0.browser_not_available",
                    "No compatible Browser application is installed."
                )
                callback.onFailure(ex)
                return
            }
            if (returnToUrl == null) {
                returnToUrl = CallbackHelper.getCallbackUri(
                    scheme,
                    context.applicationContext.packageName,
                    account.getDomainUrl()
                )
            }
            val logoutManager = LogoutManager(account, callback, returnToUrl!!, ctOptions)
            managerInstance = logoutManager
            logoutManager.startLogout(context)
        }
    }

    public class Builder internal constructor(private val account: Auth0) {
        private val values: MutableMap<String, String> = mutableMapOf()
        private val headers: MutableMap<String, String> = mutableMapOf()
        private var pkce: PKCE? = null
        private var networkingClient: NetworkingClient? = null
        private var issuer: String? = null
        private var scheme: String = "https"
        private var redirectUri: String? = null
        private var ctOptions: CustomTabsOptions = CustomTabsOptions.newBuilder().build()
        private var leeway: Int? = null

        /**
         * Use a custom networking client to handle the API calls.
         *
         * @param networkingClient to use in the requests
         * @return the current builder instance
         */
        public fun withNetworkingClient(networkingClient: NetworkingClient): Builder {
            this.networkingClient = networkingClient
            return this
        }

        /**
         * Use a custom state in the requests
         *
         * @param state to use in the requests
         * @return the current builder instance
         */
        public fun withState(state: String): Builder {
            if (state.isNotEmpty()) {
                values[OAuthManager.KEY_STATE] = state
            }
            return this
        }

        /**
         * Specify a custom nonce value to avoid replay attacks. It will be sent in the auth request that will be returned back as a claim in the id_token
         *
         * @param nonce to use in the requests
         * @return the current builder instance
         */
        public fun withNonce(nonce: String): Builder {
            if (nonce.isNotEmpty()) {
                values[OAuthManager.KEY_NONCE] = nonce
            }
            return this
        }

        /**
         * Set the max age value for the authentication.
         *
         * @param maxAge to use in the requests
         * @return the current builder instance
         */
        public fun withMaxAge(maxAge: Int): Builder {
            values[OAuthManager.KEY_MAX_AGE] = maxAge.toString()
            return this
        }

        /**
         * Set the leeway or clock skew to be used for ID Token verification.
         * Defaults to 60 seconds.
         *
         * @param leeway to use for ID token verification, in seconds.
         * @return the current builder instance
         */
        public fun withIdTokenVerificationLeeway(leeway: Int): Builder {
            this.leeway = leeway
            return this
        }

        /**
         * Set the expected issuer to be used for ID Token verification.
         * Defaults to the value returned by [Auth0.getDomainUrl].
         *
         * @param issuer to use for ID token verification.
         * @return the current builder instance
         */
        public fun withIdTokenVerificationIssuer(issuer: String): Builder {
            this.issuer = issuer
            return this
        }

        /**
         * Use a custom audience in the requests
         *
         * @param audience to use in the requests
         * @return the current builder instance
         */
        public fun withAudience(audience: String): Builder {
            values[KEY_AUDIENCE] = audience
            return this
        }

        /**
         * Specify a custom Scheme to use on the Redirect URI. Default scheme is 'https'.
         *
         * @param scheme to use in the Redirect URI.
         * @return the current builder instance
         */
        public fun withScheme(scheme: String): Builder {
            val lowerCase = scheme.toLowerCase(Locale.ROOT)
            if (scheme != lowerCase) {
                Log.w(
                    TAG,
                    "Please provide the scheme in lowercase and make sure it's the same configured in the intent filter. Android expects the scheme to be lowercase."
                )
            }
            this.scheme = scheme
            return this
        }

        /**
         * Specify a custom Redirect URI to use to invoke the app on redirection.
         * Normally, you wouldn't need to call this method manually as the default value is autogenerated for you.
         * The [Builder.withScheme] configuration is ignored when this method is called. It is your responsibility to pass a well-formed URI.
         *
         * @param redirectUri to use to invoke the app on redirection.
         * @return the current builder instance
         */
        public fun withRedirectUri(redirectUri: String): Builder {
            this.redirectUri = redirectUri
            return this
        }

        /**
         * Give a scope for this request.
         *
         * @param scope to request.
         * @return the current builder instance
         */
        public fun withScope(scope: String): Builder {
            values[KEY_SCOPE] = scope
            return this
        }

        /**
         * Add custom headers for PKCE token request.
         *
         * @param headers for token request.
         * @return the current builder instance
         */
        public fun withHeaders(headers: Map<String, String>): Builder {
            this.headers.putAll(headers)
            return this
        }

        /**
         * Give a connection scope for this request.
         *
         * @param connectionScope to request.
         * @return the current builder instance
         */
        public fun withConnectionScope(vararg connectionScope: String): Builder {
            val sb = StringBuilder()
            for (s in connectionScope) {
                sb.append(s.trim { it <= ' ' }).append(",")
            }
            if (sb.length > 0) {
                sb.deleteCharAt(sb.length - 1)
                values[KEY_CONNECTION_SCOPE] = sb.toString()
            }
            return this
        }

        /**
         * Use extra parameters on the request.
         *
         * @param parameters to add
         * @return the current builder instance
         */
        public fun withParameters(parameters: Map<String, Any?>): Builder {
            for ((key, value) in parameters) {
                if (value != null) {
                    values[key] = value.toString()
                }
            }
            return this
        }

        /**
         * Use the given connection. By default no connection is specified, so the login page will be displayed.
         *
         * @param connectionName to use
         * @return the current builder instance
         */
        public fun withConnection(connectionName: String): Builder {
            values[OAuthManager.KEY_CONNECTION] = connectionName
            return this
        }

        /**
         * When using a Custom Tabs compatible Browser, apply these customization options.
         *
         * @param options the Custom Tabs customization options
         * @return the current builder instance
         */
        public fun withCustomTabsOptions(options: CustomTabsOptions): Builder {
            ctOptions = options
            return this
        }

        @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
        internal fun withPKCE(pkce: PKCE): Builder {
            this.pkce = pkce
            return this
        }

        /**
         * Request user Authentication. The result will be received in the callback.
         * An error is raised if there are no browser applications installed in the device, or if
         * device does not support the necessary algorithms to support Proof of Key Exchange (PKCE)
         * (this is not expected).
         *
         * @param context context to run the authentication
         * @param callback to receive the parsed results
         * @see AuthenticationException.isBrowserAppNotAvailable
         * @see AuthenticationException.isPKCENotAvailable
         */
        public fun start(
            context: Context,
            callback: Callback<Credentials, AuthenticationException>
        ) {
            resetManagerInstance()
            if (!ctOptions.hasCompatibleBrowser(context.packageManager)) {
                val ex = AuthenticationException(
                    "a0.browser_not_available",
                    "No compatible Browser application is installed."
                )
                callback.onFailure(ex)
                return
            }
            val manager = OAuthManager(account, callback, values, ctOptions, networkingClient)
            manager.setHeaders(headers)
            manager.setPKCE(pkce)
            manager.setIdTokenVerificationLeeway(leeway)
            manager.setIdTokenVerificationIssuer(issuer)
            managerInstance = manager
            if (redirectUri == null) {
                redirectUri = CallbackHelper.getCallbackUri(
                    scheme,
                    context.applicationContext.packageName,
                    account.getDomainUrl()
                )
            }
            manager.startAuthentication(context, redirectUri!!, 110)
        }

        private companion object {
            private const val KEY_AUDIENCE = "audience"
            private const val KEY_SCOPE = "scope"
            private const val KEY_CONNECTION_SCOPE = "connection_scope"
            private const val DEFAULT_SCOPE = "openid"
            private const val DEFAULT_SCHEME = "https"
        }

        init {
            withScope(DEFAULT_SCOPE)
        }
    }
}