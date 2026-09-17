package com.auth0.android.embedded

import com.auth0.android.Auth0
import com.auth0.android.embedded.authorize.AdvancingRequest
import com.auth0.android.embedded.authorize.AuthorizeCode
import com.auth0.android.embedded.authorize.EmbeddedAction
import com.auth0.android.embedded.authorize.EmbeddedAuthState
import com.auth0.android.embedded.authorize.FailedRequest
import com.auth0.android.embedded.authorize.OtpType
import com.auth0.android.embedded.authorize.StepRequest
import com.auth0.android.embedded.authorize.authorizeCodeAdapter
import com.auth0.android.embedded.authorize.discoveryAdapter
import com.auth0.android.embedded.authorize.embeddedAuthErrorAdapter
import com.auth0.android.embedded.discovery.DiscoveryResult
import com.auth0.android.request.Request
import com.auth0.android.request.internal.GsonAdapter
import com.auth0.android.request.internal.GsonProvider
import com.auth0.android.request.internal.RequestFactory
import com.auth0.android.result.Credentials
import com.google.gson.Gson
import okhttp3.HttpUrl.Companion.toHttpUrl

/**
 * API client for Auth0's embedded authentication API.
 *
 * ```
 * val auth0 = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN")
 * val client = EmbeddedAuthClient(auth0)
 * ```
 *
 */
public class EmbeddedAuthClient(private val auth0: Auth0) {

    private val factory: RequestFactory<EmbeddedAuthException> =
        RequestFactory(auth0.networkingClient, embeddedAuthErrorAdapter())

    private val gson: Gson = GsonProvider.gson

    private val clientId: String
        get() = auth0.clientId

    private var transactionState: EmbeddedAuthState? = null

    /**
     *
     * Returns the grant types a client can use, derived from the client's enabled grants,
     * its enabled connections, and each connection's configured authentication methods.
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
     * @param connection name of the connection to limit the results to. When omitted, all the
     * client's enabled connections are considered.
     * @return a request to configure and start that will yield a [com.auth0.android.embedded.discovery.DiscoveryResult]
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

    /**
     * Begins an embedded authorization flow, abandoning any flow already in progress.
     *
     * This call never resolves successfully: the server always answers with a continuation, so the
     * request completes through [EmbeddedAuthException]. Inspect
     * [EmbeddedAuthException.isInsufficientAuthorization] and [EmbeddedAuthException.nextActions] to
     * learn which step to call next. A terminal error is reported on the same failure channel.
     */
    @JvmOverloads
    public fun authorize(
        connection: String? = null,
        capabilities: Set<EmbeddedAction> = DEFAULT_CAPABILITIES
    ): Request<Void?, EmbeddedAuthException> {
        transactionState = null
        val request = factory.post(authorizeUrl())
            .addParameters(buildMap {
                put(CLIENT_ID_KEY, clientId)
                connection?.let { put(CONNECTION_KEY, it) }
            })
            .addParameter(CAPABILITIES_KEY, capabilities.map { it.value })
        return stepping(request)
    }

    /**
     * Continues the flow by submitting an email identifier.
     *
     * This call never resolves successfully; it completes through [EmbeddedAuthException] whose
     * [EmbeddedAuthException.nextActions] carry the next step to call.
     */
    public fun identifyEmail(email: String): Request<Void?, EmbeddedAuthException> =
        continueStep(EmbeddedAction.IDENTIFY_EMAIL) { addParameter(EMAIL_KEY, email) }

    /**
     * Continues the flow by submitting a phone identifier.
     *
     * This call never resolves successfully; it completes through [EmbeddedAuthException] whose
     * [EmbeddedAuthException.nextActions] carry the next step to call.
     */
    public fun identifyPhone(phone: String): Request<Void?, EmbeddedAuthException> =
        continueStep(EmbeddedAction.IDENTIFY_PHONE) { addParameter(PHONE_KEY, phone) }

    /**
     * Continues the flow by requesting an email challenge for the authenticator at [index].
     *
     * This call never resolves successfully; it completes through [EmbeddedAuthException] whose
     * [EmbeddedAuthException.nextActions] carry the next step to call.
     */
    @JvmOverloads
    public fun challengeEmail(index: Int = 0): Request<Void?, EmbeddedAuthException> =
        continueStep(EmbeddedAction.CHALLENGE_EMAIL) {
            addParameter(INDEX_KEY, index)
        }

    /**
     * Verifies a one-time [code] of the given [type]. This is the terminal step of the flow.
     *
     * On success it yields the [Credentials]. If the server requires further steps the request
     * completes through [EmbeddedAuthException] instead, with the next step on
     * [EmbeddedAuthException.nextActions].
     */
    @JvmOverloads
    public fun verifyOtp(
        code: String,
        type: OtpType = OtpType.OOB
    ): Request<Credentials, EmbeddedAuthException> {
        val session = transactionState?.authSession ?: return noActiveSession()
        val request = factory.post(authorizeUrl(), authorizeCodeAdapter(gson))
            .addParameters(
                mapOf(
                    AUTH_SESSION_KEY to session,
                    ACTION_KEY to EmbeddedAction.VERIFY_OTP.value,
                    CLIENT_ID_KEY to clientId
                )
            )
            .addParameter(OTP_KEY, code)
            .addParameter(TYPE_KEY, type.value)
        return advancing(request)
    }

    private fun continueStep(
        action: EmbeddedAction,
        addPayload: Request<Void?, EmbeddedAuthException>.() -> Unit = {}
    ): Request<Void?, EmbeddedAuthException> {
        val session = transactionState?.authSession ?: return noActiveSession()
        val request = factory.post(authorizeUrl())
            .addParameters(
                mapOf(
                    AUTH_SESSION_KEY to session,
                    ACTION_KEY to action.value,
                    CLIENT_ID_KEY to clientId
                )
            )
        request.addPayload()
        return stepping(request)
    }

    private fun <T> noActiveSession(): Request<T, EmbeddedAuthException> = FailedRequest<T>(
        EmbeddedAuthException(
            NO_ACTIVE_SESSION_ERROR,
            "No embedded authentication flow is in progress. Call authorize() first."
        )
    )

    private fun stepping(
        request: Request<Void?, EmbeddedAuthException>
    ): Request<Void?, EmbeddedAuthException> = StepRequest(request, ::updateSessionFromFailure)

    private fun advancing(
        request: Request<AuthorizeCode, EmbeddedAuthException>
    ): Request<Credentials, EmbeddedAuthException> = AdvancingRequest(
        authorize = request,
        exchange = ::exchange,
        onStepFailure = ::updateSessionFromFailure,
        onFlowComplete = { transactionState = null }
    )

    private fun exchange(authorizationCode: String): Request<Credentials, EmbeddedAuthException> {
        val url = auth0.getDomainUrl().toHttpUrl().newBuilder()
            .addPathSegment(OAUTH_PATH)
            .addPathSegment(TOKEN_PATH)
            .build()
        return factory.post(url.toString(), GsonAdapter(Credentials::class.java, gson))
            .addParameters(
                mapOf(
                    CLIENT_ID_KEY to clientId,
                    GRANT_TYPE_KEY to GRANT_TYPE_AUTHORIZATION_CODE,
                    CODE_KEY to authorizationCode
                )
            )
    }

    private fun authorizeUrl(): String = auth0.getDomainUrl().toHttpUrl().newBuilder()
        .addPathSegment(EMBEDDED_PATH)
        .addPathSegment(AUTHORIZE_PATH)
        .build()
        .toString()

    private fun updateSessionFromFailure(error: EmbeddedAuthException) {
        transactionState = if (error.isInsufficientAuthorization && error.authSession != null) {
            EmbeddedAuthState(error.authSession)
        } else {
            null
        }
    }

    private companion object {
        private const val EMBEDDED_PATH = "e"
        private const val DISCOVERY_PATH = "discovery"
        private const val AUTHORIZE_PATH = "authorize"
        private const val OAUTH_PATH = "oauth"
        private const val TOKEN_PATH = "token"

        private const val CLIENT_ID_KEY = "client_id"
        private const val CONNECTION_KEY = "connection"
        private const val CAPABILITIES_KEY = "capabilities"
        private const val AUTH_SESSION_KEY = "auth_session"
        private const val ACTION_KEY = "action"
        private const val EMAIL_KEY = "email"
        private const val PHONE_KEY = "phone"
        private const val OTP_KEY = "otp"
        private const val INDEX_KEY = "index"
        private const val TYPE_KEY = "type"
        private const val GRANT_TYPE_KEY = "grant_type"
        private const val CODE_KEY = "code"
        private const val GRANT_TYPE_AUTHORIZATION_CODE = "authorization_code"
        private const val NO_ACTIVE_SESSION_ERROR = "no_active_session"

        private val DEFAULT_CAPABILITIES: Set<EmbeddedAction> =
            EmbeddedAction.entries.toSet() - EmbeddedAction.UNKNOWN
    }

    init {
        factory.setAuth0ClientInfo(auth0.auth0UserAgent.value)
    }
}
