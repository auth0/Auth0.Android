package com.auth0.android.embedded

import com.auth0.android.Auth0
import com.auth0.android.Auth0Exception
import com.auth0.android.NetworkErrorException
import com.auth0.android.callback.Callback
import com.auth0.android.request.ErrorAdapter
import com.auth0.android.request.JsonAdapter
import com.auth0.android.request.Request
import com.auth0.android.request.internal.GsonAdapter
import com.auth0.android.request.internal.GsonAdapter.Companion.forMap
import com.auth0.android.request.internal.GsonProvider
import com.auth0.android.request.internal.RequestFactory
import com.auth0.android.request.internal.ResponseUtils.isNetworkError
import com.auth0.android.result.Credentials
import com.google.gson.Gson
import com.google.gson.annotations.SerializedName
import okhttp3.HttpUrl.Companion.toHttpUrl
import java.io.IOException
import java.io.Reader

/**
 * API client for Auth0's embedded authentication API.
 *
 * ```
 * val auth0 = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN")
 * val client = EmbeddedAuthClient(auth0)
 * ```
 *
 * ### Embedded authorization loop
 *
 * [authorize] begins a server-driven, multi-step flow. Each step that does not complete the flow
 * fails with an [EmbeddedAuthException] whose [EmbeddedAuthException.isInsufficientAuthorization] is
 * `true` and whose [EmbeddedAuthException.nextActions] lists the actions the server
 * will accept next — act on one by calling [identifyEmail], [identifyPhone], [challenge] or
 * [verifyOtp]. The `auth_session` threading those calls together is managed internally; the flow
 * ends when a step succeeds with [Credentials] or fails terminally (e.g. `access_denied`).
 *
 * A client tracks a single in-progress flow: calling [authorize] again abandons any previous one, so
 * a new sign-in never reuses a stale session.
 */
public class EmbeddedAuthClient(private val auth0: Auth0) {

    private val factory: RequestFactory<EmbeddedAuthException> =
        RequestFactory(auth0.networkingClient, createErrorAdapter())

    private val gson: Gson = GsonProvider.gson

    private val clientId: String
        get() = auth0.clientId

    /** State of the current in-progress flow; `null` when no flow is active. Main-thread confined. */
    private var transactionState: EmbeddedAuthState? = null

    /**
     *
     * Fetches the list of login grant types enabled for the client
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
     * @return a request to configure and start that will yield a [DiscoveryResult]
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
     * On success yields [Credentials]; more commonly the first step fails with an
     * `insufficient_authorization` [EmbeddedAuthException] whose [EmbeddedAuthException.nextActions]
     * tells you which of [identifyEmail] / [identifyPhone] / [challenge] / [verifyOtp] to call next.
     *
     * @param connection the connection to authenticate against, or `null` to let the server resolve
     * it.
     * @param capabilities the actions this client can perform, advertised to the server. Defaults to
     * every action this SDK version models.
     * @return a request to configure and start that will yield [Credentials] once the flow completes.
     */
    @JvmOverloads
    public fun authorize(
        connection: String? = null,
        capabilities: Set<EmbeddedAction> = DEFAULT_CAPABILITIES
    ): Request<Credentials, EmbeddedAuthException> {
        transactionState = null
        val request = factory.post(authorizeUrl(), authorizeCodeAdapter(gson))
            .addParameters(buildMap {
                put(CLIENT_ID_KEY, clientId)
                connection?.let { put(CONNECTION_KEY, it) }
            })
            .addParameter(CAPABILITIES_KEY, capabilities.map { it.value })
        return AdvancingRequest(request)
    }

    /**
     * Continues the flow by submitting an email identifier. Valid when the current
     * [EmbeddedAuthException.nextActions] offers [NextAction.IdentifyEmail].
     */
    public fun identifyEmail(email: String): Request<Credentials, EmbeddedAuthException> =
        continueWith(EmbeddedAction.IDENTIFY_EMAIL, mapOf(EMAIL_KEY to email))

    /**
     * Continues the flow by submitting a phone identifier. Valid when the current
     * [EmbeddedAuthException.nextActions] offers [NextAction.IdentifyPhone].
     */
    public fun identifyPhone(phone: String): Request<Credentials, EmbeddedAuthException> =
        continueWith(EmbeddedAction.IDENTIFY_PHONE, mapOf(PHONE_KEY to phone))

    /**
     * Continues the flow by requesting an email challenge. Valid when the current
     * [EmbeddedAuthException.nextActions] offers [NextAction.ChallengeEmail].
     */
    public fun challengeEmail(): Request<Credentials, EmbeddedAuthException> =
        continueWith(EmbeddedAction.CHALLENGE_EMAIL, emptyMap())

    /**
     * Continues the flow by verifying a one-time code. Valid when the current
     * [EmbeddedAuthException.nextActions] offers [NextAction.VerifyOtp].
     */
    public fun verifyOtp(code: String): Request<Credentials, EmbeddedAuthException> =
        continueWith(EmbeddedAction.VERIFY_OTP, mapOf(OTP_KEY to code))

    /**
     * Builds a continuation request for [action], attaching the current session token. If no flow is
     * in progress the returned request fails immediately — continuation methods are only valid after
     * [authorize] has yielded a continuation.
     */
    private fun continueWith(
        action: EmbeddedAction,
        payload: Map<String, String>
    ): Request<Credentials, EmbeddedAuthException> {
        val session = transactionState?.authSession ?: return FailedRequest(
            EmbeddedAuthException(
                NO_ACTIVE_SESSION_ERROR,
                "No embedded authentication flow is in progress. Call authorize() first."
            )
        )
        val request = factory.post(authorizeUrl(), authorizeCodeAdapter(gson))
            .addParameters(buildMap {
                put(AUTH_SESSION_KEY, session)
                put(ACTION_KEY, action.value)
                putAll(payload)
            })
        return AdvancingRequest(request)
    }

    /** Exchanges the authorization code returned by a completed flow for [Credentials]. */
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

    /**
     * Updates the flow's session after a step fails: on a continuation
     * ([EmbeddedAuthException.isInsufficientAuthorization]) the rotated `auth_session` becomes the
     * active session so the next step can proceed; on any terminal failure the session is cleared so
     * a stray continuation call is rejected locally rather than sent with a dead session.
     */
    private fun updateSessionFromFailure(error: EmbeddedAuthException) {
        transactionState = if (error.code == INSUFFICIENT_AUTHORIZATION && error.authSession != null) {
            EmbeddedAuthState(error.authSession)
        } else {
            null
        }
    }

    /**
     * Runs one step of the flow as a single [Request]. On a step failure the session is rotated
     * (continuation) or cleared (terminal); on the `200` that ends `/e/authorize` the authorization
     * code is exchanged for [Credentials], and only once that succeeds is the session cleared — so a
     * failed token exchange leaves the session intact for the caller to retry.
     */
    private inner class AdvancingRequest(
        private val authorize: Request<AuthorizeCode, EmbeddedAuthException>
    ) : Request<Credentials, EmbeddedAuthException> {

        override fun start(callback: Callback<Credentials, EmbeddedAuthException>) {
            authorize.start(object : Callback<AuthorizeCode, EmbeddedAuthException> {
                override fun onSuccess(result: AuthorizeCode) {
                    exchange(result.authorizationCode).start(object : Callback<Credentials, EmbeddedAuthException> {
                        override fun onSuccess(result: Credentials) {
                            transactionState = null
                            callback.onSuccess(result)
                        }

                        override fun onFailure(error: EmbeddedAuthException) = callback.onFailure(error)
                    })
                }

                override fun onFailure(error: EmbeddedAuthException) {
                    updateSessionFromFailure(error)
                    callback.onFailure(error)
                }
            })
        }

        @Throws(Auth0Exception::class)
        override suspend fun await(): Credentials {
            val code = try {
                authorize.await()
            } catch (error: EmbeddedAuthException) {
                updateSessionFromFailure(error)
                throw error
            }
            return exchange(code.authorizationCode).await().also { transactionState = null }
        }

        @Throws(Auth0Exception::class)
        override fun execute(): Credentials {
            val code = try {
                authorize.execute()
            } catch (error: EmbeddedAuthException) {
                updateSessionFromFailure(error)
                throw error
            }
            return exchange(code.authorizationCode).execute().also { transactionState = null }
        }

        override fun addParameters(parameters: Map<String, String>): Request<Credentials, EmbeddedAuthException> {
            authorize.addParameters(parameters)
            return this
        }

        override fun addParameter(name: String, value: String): Request<Credentials, EmbeddedAuthException> {
            authorize.addParameter(name, value)
            return this
        }

        override fun addHeader(name: String, value: String): Request<Credentials, EmbeddedAuthException> {
            authorize.addHeader(name, value)
            return this
        }
    }

    /** A request that has already failed — used to report calling a continuation with no flow active. */
    private class FailedRequest<T>(
        private val error: EmbeddedAuthException
    ) : Request<T, EmbeddedAuthException> {
        override fun start(callback: Callback<T, EmbeddedAuthException>): Unit = callback.onFailure(error)

        @Throws(Auth0Exception::class)
        override suspend fun await(): T = throw error

        @Throws(Auth0Exception::class)
        override fun execute(): T = throw error

        override fun addParameters(parameters: Map<String, String>): Request<T, EmbeddedAuthException> = this
        override fun addParameter(name: String, value: String): Request<T, EmbeddedAuthException> = this
        override fun addParameter(name: String, value: Any): Request<T, EmbeddedAuthException> = this
        override fun addHeader(name: String, value: String): Request<T, EmbeddedAuthException> = this
    }

    /** The `200` body of `/e/authorize`: the code to exchange for tokens. */
    private class AuthorizeCode(
        @SerializedName("authorization_code") val authorizationCode: String
    )

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
        private const val GRANT_TYPE_KEY = "grant_type"
        private const val CODE_KEY = "code"
        private const val GRANT_TYPE_AUTHORIZATION_CODE = "authorization_code"

        private const val ERROR_KEY = "error"
        private const val ERROR_DESCRIPTION_KEY = "error_description"
        private const val NEXT_KEY = "next"
        private const val INSUFFICIENT_AUTHORIZATION = "insufficient_authorization"
        private const val NO_ACTIVE_SESSION_ERROR = "no_active_session"
        private const val DEFAULT_DESCRIPTION =
            "An error occurred when trying to authenticate with the server."

        private val DEFAULT_CAPABILITIES: Set<EmbeddedAction> =
            EmbeddedAction.entries.toSet() - EmbeddedAction.UNKNOWN

        /**
         * Parses the wire payload and translates it into the public [DiscoveryResult].
         */
        private fun discoveryAdapter(gson: Gson): JsonAdapter<DiscoveryResult> {
            val adapter = GsonAdapter(DiscoveryResponse::class.java, gson)
            return object : JsonAdapter<DiscoveryResult> {
                @Throws(IOException::class)
                override fun fromJson(
                    reader: Reader,
                    metadata: Map<String, Any>
                ): DiscoveryResult = adapter.fromJson(reader, metadata).toDiscoveryResult()
            }
        }

        private fun authorizeCodeAdapter(gson: Gson): JsonAdapter<AuthorizeCode> =
            GsonAdapter(AuthorizeCode::class.java, gson)

        private fun createErrorAdapter(): ErrorAdapter<EmbeddedAuthException> {
            val mapAdapter = forMap(GsonProvider.gson)
            return object : ErrorAdapter<EmbeddedAuthException> {
                /**
                 * The response body was not JSON. Notably the case for the `404` returned when
                 * embedded authentication is not enabled for the tenant, whose body is empty.
                 */
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
    }

    init {
        factory.setAuth0ClientInfo(auth0.auth0UserAgent.value)
    }
}
