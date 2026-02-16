package com.auth0.android.provider

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Log
import androidx.annotation.VisibleForTesting
import com.auth0.android.Auth0
import com.auth0.android.authentication.AuthenticationException
import com.auth0.android.callback.Callback
import com.auth0.android.dpop.DPoP
import com.auth0.android.dpop.SenderConstraining
import com.auth0.android.result.Credentials
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import java.util.Locale
import java.util.concurrent.CopyOnWriteArraySet
import kotlin.coroutines.CoroutineContext
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * OAuth2 Web Authentication Provider.
 *
 *
 * It uses an external browser by sending the [android.content.Intent.ACTION_VIEW] intent.
 */
public object WebAuthProvider {
    private val TAG: String? = WebAuthProvider::class.simpleName
    private const val KEY_BUNDLE_OAUTH_MANAGER_STATE = "oauth_manager_state"

    private val callbacks = CopyOnWriteArraySet<Callback<Credentials, AuthenticationException>>()

    @JvmStatic
    @get:VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    internal var managerInstance: ResumableManager? = null
        private set

    @JvmStatic
    public fun addCallback(callback: Callback<Credentials, AuthenticationException>) {
        callbacks += callback
    }

    @JvmStatic
    public fun removeCallback(callback: Callback<Credentials, AuthenticationException>) {
        callbacks -= callback
    }

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

    internal fun failure(exception: AuthenticationException) {
        if (managerInstance == null) {
            Log.w(TAG, "There is no previous instance of this provider.")
            return
        }
        managerInstance!!.failure(exception)
    }

    internal fun onSaveInstanceState(bundle: Bundle) {
        val manager = managerInstance
        if (manager is OAuthManager) {
            val managerState = manager.toState()
            bundle.putString(KEY_BUNDLE_OAUTH_MANAGER_STATE, managerState.serializeToJson())
        }
    }

    internal fun onRestoreInstanceState(bundle: Bundle) {
        if (managerInstance == null) {
            val stateJson = bundle.getString(KEY_BUNDLE_OAUTH_MANAGER_STATE).orEmpty()
            if (stateJson.isNotBlank()) {
                val state = OAuthManagerState.deserializeState(stateJson)
                managerInstance = OAuthManager.fromState(
                    state,
                    object : Callback<Credentials, AuthenticationException> {
                        override fun onSuccess(result: Credentials) {
                            for (callback in callbacks) {
                                callback.onSuccess(result)
                            }
                        }

                        override fun onFailure(error: AuthenticationException) {
                            for (callback in callbacks) {
                                callback.onFailure(error)
                            }
                        }
                    }
                )
            }
        }
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
        private var federated: Boolean = false
        private var launchAsTwa: Boolean = false
        private var customLogoutUrl: String? = null

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
         * Although not a common practice, you can force the user to log out of their identity provider.
         * Think of the user experience before you use this parameter.
         *
         * This feature is not supported by every identity provider. Read more about the limitations in
         * the [Log Users Out of Identity Provider](https://auth0.com/docs/logout/log-users-out-of-idps) article.
         *
         * @return the current builder instance
         */
        public fun withFederated(): LogoutBuilder {
            this.federated = true
            return this
        }

        /**
         * Launches the Logout experience with a native feel (without address bar). For this to work,
         * you have to setup the app as trusted following the steps mentioned [here](https://github.com/auth0/Auth0.Android/blob/main/EXAMPLES.md#trusted-web-activity-experimental).
         *
         */
        public fun withTrustedWebActivity(): LogoutBuilder {
            launchAsTwa = true
            return this
        }

        /**
         * Specifies a custom Logout URL to use for this logout request, overriding the default
         * generated from the Auth0 domain (account.logoutUrl).
         *
         * @param logoutUrl the custom logout URL.
         * @return the current builder instance
         */
        public fun withLogoutUrl(logoutUrl: String): LogoutBuilder {
            this.customLogoutUrl = logoutUrl
            return this
        }

        /**
         * Request the user session to be cleared. When successful, the callback will get invoked.
         * An error is raised if there are no browser applications installed in the device or if
         * the user closed the browser before completing the logout.
         *
         * @param context  An activity context to run the log out. Passing any other context can cause a crash while starting the [AuthenticationActivity]
         * @param callback to invoke when log out is successful
         * @see AuthenticationException.isBrowserAppNotAvailable
         * @see AuthenticationException.isAuthenticationCanceled
         */
        public fun start(context: Context, callback: Callback<Void?, AuthenticationException>) {
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
            val logoutManager = LogoutManager(
                account,
                callback,
                returnToUrl!!,
                ctOptions,
                federated,
                launchAsTwa,
                customLogoutUrl
            )
            managerInstance = logoutManager
            logoutManager.startLogout(context)
        }

        @JvmSynthetic
        @Throws(AuthenticationException::class)
        public suspend fun await(context: Context) {
            return await(context, Dispatchers.Main.immediate)
        }

        /**
         * Used internally so that [CoroutineContext] can be injected for testing purpose
         */
        internal suspend fun await(
            context: Context,
            coroutineContext: CoroutineContext
        ) {
            return withContext(coroutineContext) {
                suspendCancellableCoroutine { continuation ->
                    start(context, object : Callback<Void?, AuthenticationException> {
                        override fun onSuccess(result: Void?) {
                            continuation.resume(Unit)
                        }

                        override fun onFailure(error: AuthenticationException) {
                            continuation.resumeWithException(error)
                        }
                    })
                }
            }
        }
    }

    public class Builder internal constructor(private val account: Auth0) : SenderConstraining<Builder> {
        private val values: MutableMap<String, String> = mutableMapOf()
        private val headers: MutableMap<String, String> = mutableMapOf()
        private var pkce: PKCE? = null
        private var issuer: String? = null
        private var scheme: String = "https"
        private var redirectUri: String? = null
        private var invitationUrl: String? = null
        private var dPoP: DPoP? = null
        private var ctOptions: CustomTabsOptions = CustomTabsOptions.newBuilder().build()
        private var leeway: Int? = null
        private var launchAsTwa: Boolean = false
        private var customAuthorizeUrl: String? = null

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
         * @param maxAge to use in the requests in seconds
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
         * Specify an invitation URL to join an organization.
         * When called in combination with WebAuthProvider#withOrganization, the invitation URL
         * will take precedence.
         *
         * @param invitationUrl the organization invitation URL
         * @return the current builder instance
         * @see withOrganization
         */
        public fun withInvitationUrl(invitationUrl: String): Builder {
            this.invitationUrl = invitationUrl
            return this
        }

        /**
         * Specify the ID of an organization to join.
         *
         * @param organization the ID of the organization to join
         * @return the current builder instance
         * @see withInvitationUrl
         */
        public fun withOrganization(organization: String): Builder {
            values[OAuthManager.KEY_ORGANIZATION] = organization
            return this
        }

        /**
         * Give a scope for this request. The default scope used is "openid profile email".
         * Regardless of the scopes passed, the "openid" scope is always enforced.
         *
         * @param scope to request.
         * @return the current builder instance
         */
        public fun withScope(scope: String): Builder {
            values[OAuthManager.KEY_SCOPE] = scope
            return this
        }

        /**
         * Add custom headers for PKCE token request.
         *
         * @param headers for token request.
         * @return the current builder instance
         */
        @Suppress("unused")
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
            values[KEY_CONNECTION_SCOPE] =
                connectionScope.joinToString(separator = ",") { it.trim() }
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

        /**
         * Launches the Login experience with a native feel (without address bar). For this to work,
         * you have to setup the app as trusted following the steps mentioned [here](https://github.com/auth0/Auth0.Android/blob/main/EXAMPLES.md#trusted-web-activity-experimental).
         *
         */
        public fun withTrustedWebActivity(): Builder {
            launchAsTwa = true
            return this
        }

        /**
         * Specifies a custom Authorize URL to use for this login request, overriding the default
         * generated from the Auth0 domain (account.authorizeUrl).
         *
         * @param authorizeUrl the custom authorize URL.
         * @return the current builder instance
         */
        public fun withAuthorizeUrl(authorizeUrl: String): Builder {
            this.customAuthorizeUrl = authorizeUrl
            return this
        }

        @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
        internal fun withPKCE(pkce: PKCE): Builder {
            this.pkce = pkce
            return this
        }

        /**
         * Enable DPoP (Demonstrating Proof-of-Possession) for this authentication request.
         * DPoP binds access tokens to the client's cryptographic key, providing enhanced security.
         *
         * @param context the Android context used to access the keystore for DPoP key management
         * @return the current builder instance
         */
        public override fun useDPoP(context: Context): Builder {
            dPoP = DPoP(context)
            return this
        }

        /**
         * Request user Authentication. The result will be received in the callback.
         * An error is raised if there are no browser applications installed in the device, or if
         * device does not support the necessary algorithms to support Proof of Key Exchange (PKCE)
         * (this is not expected), or if the user closed the browser before completing the authentication.
         *
         * @param context  An Activity context to run the authentication. Passing any other context can cause a crash while starting the [AuthenticationActivity]
         * @param callback to receive the parsed results
         * @see AuthenticationException.isBrowserAppNotAvailable
         * @see AuthenticationException.isPKCENotAvailable
         * @see AuthenticationException.isAuthenticationCanceled
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
            invitationUrl?.let {
                val url = Uri.parse(it)
                val organizationId = url.getQueryParameter(OAuthManager.KEY_ORGANIZATION)
                val invitationId = url.getQueryParameter(OAuthManager.KEY_INVITATION)
                if (organizationId.isNullOrBlank() || invitationId.isNullOrBlank()) {
                    val ex = AuthenticationException(
                        "a0.invalid_invitation_url",
                        "The invitation URL provided doesn't contain the 'organization' or 'invitation' values."
                    )
                    callback.onFailure(ex)
                    return
                }
                values[OAuthManager.KEY_ORGANIZATION] = organizationId
                values[OAuthManager.KEY_INVITATION] = invitationId
            }
            val manager = OAuthManager(
                account, callback, values, ctOptions, launchAsTwa,
                customAuthorizeUrl, dPoP
            )
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

        /**
         * Request user Authentication. An error is thrown if there are no browser applications installed in the device, or if
         * device does not support the necessary algorithms to support Proof of Key Exchange (PKCE)
         * (this is not expected), or if the user closed the browser before completing the authentication.
         *
         * @param context An Activity context to run the authentication. Passing any other context can cause a crash while starting the [AuthenticationActivity]
         */
        @JvmSynthetic
        @Throws(AuthenticationException::class)
        public suspend fun await(context: Context): Credentials {
            return await(context, Dispatchers.Main.immediate)
        }

        /**
         * Used internally so that [CoroutineContext] can be injected for testing purpose
         */
        internal suspend fun await(
            context: Context,
            coroutineContext: CoroutineContext
        ): Credentials {
            return withContext(coroutineContext) {
                suspendCancellableCoroutine { continuation ->
                    start(context, object : Callback<Credentials, AuthenticationException> {
                        override fun onSuccess(result: Credentials) {
                            continuation.resume(result)
                        }

                        override fun onFailure(error: AuthenticationException) {
                            continuation.resumeWithException(error)
                        }
                    })
                }
            }
        }

        private companion object {
            private const val KEY_AUDIENCE = "audience"
            private const val KEY_CONNECTION_SCOPE = "connection_scope"
        }
    }
}
