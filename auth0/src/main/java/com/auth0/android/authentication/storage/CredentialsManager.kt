package com.auth0.android.authentication.storage

import android.text.TextUtils
import android.util.Log
import androidx.annotation.VisibleForTesting
import com.auth0.android.authentication.AuthenticationAPIClient
import com.auth0.android.authentication.AuthenticationException
import com.auth0.android.callback.Callback
import com.auth0.android.request.internal.GsonProvider
import com.auth0.android.request.internal.Jwt
import com.auth0.android.result.APICredentials
import com.auth0.android.result.Credentials
import com.auth0.android.result.SSOCredentials
import com.auth0.android.result.UserProfile
import com.auth0.android.result.toAPICredentials
import com.google.gson.Gson
import kotlinx.coroutines.suspendCancellableCoroutine
import java.util.Date
import java.util.Locale
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Class that handles credentials and allows to save and retrieve them.
 */
public class CredentialsManager @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE) internal constructor(
    authenticationClient: AuthenticationAPIClient,
    storage: Storage,
    jwtDecoder: JWTDecoder,
    private val serialExecutor: Executor
) : BaseCredentialsManager(authenticationClient, storage, jwtDecoder) {

    private val gson: Gson = GsonProvider.gson

    /**
     * Creates a new instance of the manager that will store the credentials in the given Storage.
     *
     * @param authenticationClient the Auth0 Authentication client to refresh credentials with.
     * @param storage              the storage to use for the credentials.
     */
    public constructor(authenticationClient: AuthenticationAPIClient, storage: Storage) : this(
        authenticationClient,
        storage,
        JWTDecoder(),
        Executors.newSingleThreadExecutor()
    )

    public override val userProfile: UserProfile?
        get() {
            val idToken = storage.retrieveString(KEY_ID_TOKEN)

            if (idToken.isNullOrBlank()) {
                return null
            }
            val (_, payload) = Jwt.splitToken(idToken)
            val gson = GsonProvider.gson
            return gson.fromJson(Jwt.decodeBase64(payload), UserProfile::class.java)
        }

    /**
     * Stores the given credentials in the storage. Must have an access_token or id_token and a expires_in value.
     *
     * @param credentials the credentials to save in the storage.
     */
    override fun saveCredentials(credentials: Credentials) {
        if (TextUtils.isEmpty(credentials.accessToken) && TextUtils.isEmpty(credentials.idToken)) {
            throw CredentialsManagerException.INVALID_CREDENTIALS
        }
        storage.store(KEY_ACCESS_TOKEN, credentials.accessToken)
        storage.store(KEY_REFRESH_TOKEN, credentials.refreshToken)
        storage.store(KEY_ID_TOKEN, credentials.idToken)
        storage.store(KEY_TOKEN_TYPE, credentials.type)
        storage.store(KEY_EXPIRES_AT, credentials.expiresAt.time)
        storage.store(KEY_SCOPE, credentials.scope)
        storage.store(LEGACY_KEY_CACHE_EXPIRES_AT, credentials.expiresAt.time)
    }

    /**
     * Stores the given [APICredentials] in the storage for the given audience.
     * @param apiCredentials the API Credentials to be stored
     * @param audience the audience for which the credentials are stored
     */
    override fun saveApiCredentials(apiCredentials: APICredentials, audience: String) {
        gson.toJson(apiCredentials).let {
            storage.store(audience, it)
        }
    }

    /**
     * Creates a new request to exchange a refresh token for a session transfer token that can be used to perform web single sign-on.
     *
     * When opening your website on any browser or web view, add the session transfer token to the URL as a query
     * parameter. Then your website can redirect the user to Auth0's `/authorize` endpoint, passing along the query
     * parameter with the session transfer token. For example,
     *  `https://example.com/login?session_transfer_token=THE_TOKEN`.
     *
     * ## Availability
     *
     * This feature is currently available in
     * [Early Access](https://auth0.com/docs/troubleshoot/product-lifecycle/product-release-stages#early-access).
     * Please reach out to Auth0 support to get it enabled for your tenant.
     *
     * It will fail with [CredentialsManagerException] if the existing refresh_token is null or no longer valid.
     * This method will handle saving the refresh_token, if a new one is issued.
     */
    override fun getSsoCredentials(callback: Callback<SSOCredentials, CredentialsManagerException>) {
        getSsoCredentials(emptyMap(), callback)
    }

    /**
     * Creates a new request to exchange a refresh token for a session transfer token that can be used to perform web single sign-on.
     *
     * When opening your website on any browser or web view, add the session transfer token to the URL as a query
     * parameter. Then your website can redirect the user to Auth0's `/authorize` endpoint, passing along the query
     * parameter with the session transfer token. For example,
     *  `https://example.com/login?session_transfer_token=THE_TOKEN`.
     *
     * ## Availability
     *
     * This feature is currently available in
     * [Early Access](https://auth0.com/docs/troubleshoot/product-lifecycle/product-release-stages#early-access).
     * Please reach out to Auth0 support to get it enabled for your tenant.
     *
     * It will fail with [CredentialsManagerException] if the existing refresh_token is null or no longer valid.
     * This method will handle saving the refresh_token, if a new one is issued.
     */
    override fun getSsoCredentials(
        parameters: Map<String, String>,
        callback: Callback<SSOCredentials, CredentialsManagerException>
    ) {
        serialExecutor.execute {
            val refreshToken = storage.retrieveString(KEY_REFRESH_TOKEN)
            if (refreshToken.isNullOrEmpty()) {
                callback.onFailure(CredentialsManagerException.NO_REFRESH_TOKEN)
                return@execute
            }

            val request = authenticationClient.ssoExchange(refreshToken)
            try {
                if (parameters.isNotEmpty()) {
                    request.addParameters(parameters)
                }
                val sessionTransferCredentials = request.execute()
                saveSsoCredentials(sessionTransferCredentials)
                callback.onSuccess(sessionTransferCredentials)
            } catch (error: AuthenticationException) {
                val exception = when {
                    error.isNetworkError -> CredentialsManagerException.Code.NO_NETWORK
                    else -> CredentialsManagerException.Code.SSO_EXCHANGE_FAILED
                }
                callback.onFailure(
                    CredentialsManagerException(
                        exception,
                        error
                    )
                )
            } catch (exception: RuntimeException) {
                Log.e(
                    TAG,
                    "Caught unexpected exceptions while fetching sso token ${exception.stackTraceToString()}"
                )
                callback.onFailure(
                    CredentialsManagerException(
                        CredentialsManagerException.Code.UNKNOWN_ERROR,
                        exception
                    )
                )
            }
        }
    }

    /**
     * Creates a new request to exchange a refresh token for a session transfer token that can be used to perform web single sign-on.
     *
     * When opening your website on any browser or web view, add the session transfer token to the URL as a query
     * parameter. Then your website can redirect the user to Auth0's `/authorize` endpoint, passing along the query
     * parameter with the session transfer token. For example,
     *  `https://example.com/login?session_transfer_token=THE_TOKEN`.
     *
     * ## Availability
     *
     * This feature is currently available in
     * [Early Access](https://auth0.com/docs/troubleshoot/product-lifecycle/product-release-stages#early-access).
     * Please reach out to Auth0 support to get it enabled for your tenant.
     *
     * It will fail with [CredentialsManagerException] if the existing refresh_token is null or no longer valid.
     * This method will handle saving the refresh_token, if a new one is issued.
     */
    @JvmSynthetic
    @Throws(CredentialsManagerException::class)
    override suspend fun awaitSsoCredentials(): SSOCredentials {
        return awaitSsoCredentials(emptyMap())
    }

    /**
     * Creates a new request to exchange a refresh token for a session transfer token that can be used to perform web single sign-on.
     *
     * When opening your website on any browser or web view, add the session transfer token to the URL as a query
     * parameter. Then your website can redirect the user to Auth0's `/authorize` endpoint, passing along the query
     * parameter with the session transfer token. For example,
     *  `https://example.com/login?session_transfer_token=THE_TOKEN`.
     *
     * ## Availability
     *
     * This feature is currently available in
     * [Early Access](https://auth0.com/docs/troubleshoot/product-lifecycle/product-release-stages#early-access).
     * Please reach out to Auth0 support to get it enabled for your tenant.
     *
     * It will fail with [CredentialsManagerException] if the existing refresh_token is null or no longer valid.
     * This method will handle saving the refresh_token, if a new one is issued.
     */
    @JvmSynthetic
    @Throws(CredentialsManagerException::class)
    override suspend fun awaitSsoCredentials(parameters: Map<String, String>): SSOCredentials {
        return suspendCancellableCoroutine { continuation ->
            getSsoCredentials(
                parameters,
                object : Callback<SSOCredentials, CredentialsManagerException> {
                    override fun onSuccess(result: SSOCredentials) {
                        continuation.resume(result)
                    }

                    override fun onFailure(error: CredentialsManagerException) {
                        continuation.resumeWithException(error)
                    }
                })
        }
    }

    /**
     * Retrieves the credentials from the storage and refresh them if they have already expired.
     * It will throw [CredentialsManagerException] if the saved access_token or id_token is null,
     * or if the tokens have already expired and the refresh_token is null.
     * This is a Coroutine that is exposed only for Kotlin.
     */
    @JvmSynthetic
    @Throws(CredentialsManagerException::class)
    override suspend fun awaitCredentials(): Credentials {
        return awaitCredentials(null, 0)
    }

    /**
     * Retrieves the credentials from the storage and refresh them if they have already expired.
     * It will throw [CredentialsManagerException] if the saved access_token or id_token is null,
     * or if the tokens have already expired and the refresh_token is null.
     * This is a Coroutine that is exposed only for Kotlin.
     *
     * @param scope    the scope to request for the access token. If null is passed, the previous scope will be kept.
     * @param minTtl   the minimum time in seconds that the access token should last before expiration.
     */
    @JvmSynthetic
    @Throws(CredentialsManagerException::class)
    override suspend fun awaitCredentials(scope: String?, minTtl: Int): Credentials {
        return awaitCredentials(scope, minTtl, emptyMap())
    }

    /**
     * Retrieves the credentials from the storage and refresh them if they have already expired.
     * It will throw [CredentialsManagerException] if the saved access_token or id_token is null,
     * or if the tokens have already expired and the refresh_token is null.
     * This is a Coroutine that is exposed only for Kotlin.
     *
     * @param scope    the scope to request for the access token. If null is passed, the previous scope will be kept.
     * @param minTtl   the minimum time in seconds that the access token should last before expiration.
     * @param parameters additional parameters to send in the request to refresh expired credentials
     */
    @JvmSynthetic
    @Throws(CredentialsManagerException::class)
    override suspend fun awaitCredentials(
        scope: String?,
        minTtl: Int,
        parameters: Map<String, String>
    ): Credentials {
        return awaitCredentials(scope, minTtl, parameters, false)
    }

    /**
     * Retrieves the credentials from the storage and refresh them if they have already expired.
     * It will throw [CredentialsManagerException] if the saved access_token or id_token is null,
     * or if the tokens have already expired and the refresh_token is null.
     * This is a Coroutine that is exposed only for Kotlin.
     *
     * @param scope    the scope to request for the access token. If null is passed, the previous scope will be kept.
     * @param minTtl   the minimum time in seconds that the access token should last before expiration.
     * @param parameters additional parameters to send in the request to refresh expired credentials.
     * @param forceRefresh this will avoid returning the existing credentials and retrieves a new one even if valid credentials exist.
     */
    @JvmSynthetic
    @Throws(CredentialsManagerException::class)
    override suspend fun awaitCredentials(
        scope: String?,
        minTtl: Int,
        parameters: Map<String, String>,
        forceRefresh: Boolean
    ): Credentials {
        return awaitCredentials(scope, minTtl, parameters, mapOf(), forceRefresh)
    }

    /**
     * Retrieves the credentials from the storage and refresh them if they have already expired.
     * It will throw [CredentialsManagerException] if the saved access_token or id_token is null,
     * or if the tokens have already expired and the refresh_token is null.
     * This is a Coroutine that is exposed only for Kotlin.
     *
     * @param scope    the scope to request for the access token. If null is passed, the previous scope will be kept.
     * @param minTtl   the minimum time in seconds that the access token should last before expiration.
     * @param parameters additional parameters to send in the request to refresh expired credentials.
     * @param headers additional headers to send in the request to refresh expired credentials.
     * @param forceRefresh this will avoid returning the existing credentials and retrieves a new one even if valid credentials exist.
     */
    @JvmSynthetic
    @Throws(CredentialsManagerException::class)
    override suspend fun awaitCredentials(
        scope: String?,
        minTtl: Int,
        parameters: Map<String, String>,
        headers: Map<String, String>,
        forceRefresh: Boolean
    ): Credentials {
        return suspendCancellableCoroutine { continuation ->
            getCredentials(
                scope,
                minTtl,
                parameters,
                headers,
                forceRefresh,
                object : Callback<Credentials, CredentialsManagerException> {
                    override fun onSuccess(result: Credentials) {
                        continuation.resume(result)
                    }

                    override fun onFailure(error: CredentialsManagerException) {
                        continuation.resumeWithException(error)
                    }
                })
        }
    }

    /**
     * Retrieves API credentials from storage and automatically renews them using the refresh token if the access
     * token is expired. Otherwise, the retrieved API credentials will be returned as they are still valid.
     *
     * If there are no stored API credentials, the refresh token will be exchanged for a new set of API credentials.
     * New or renewed API credentials will be automatically persisted in storage.
     *
     * @param audience Identifier of the API that your application is requesting access to.
     * @param scope    the scope to request for the access token. If null is passed, the previous scope will be kept.
     * @param minTtl   the minimum time in seconds that the access token should last before expiration.
     * @param parameters additional parameters to send in the request to refresh expired credentials.
     * @param headers additional headers to send in the request to refresh expired credentials.
     */
    @JvmSynthetic
    @Throws(CredentialsManagerException::class)
    override suspend fun awaitApiCredentials(
        audience: String,
        scope: String?,
        minTtl: Int,
        parameters: Map<String, String>,
        headers: Map<String, String>
    ): APICredentials {
        return suspendCancellableCoroutine { continuation ->
            getApiCredentials(
                audience, scope, minTtl, parameters, headers,
                object : Callback<APICredentials, CredentialsManagerException> {
                    override fun onSuccess(result: APICredentials) {
                        continuation.resume(result)
                    }

                    override fun onFailure(error: CredentialsManagerException) {
                        continuation.resumeWithException(error)
                    }
                }
            )
        }
    }

    /**
     * Retrieves the credentials from the storage and refresh them if they have already expired.
     * It will fail with [CredentialsManagerException] if the saved access_token or id_token is null,
     * or if the tokens have already expired and the refresh_token is null.
     *
     * @param callback the callback that will receive a valid [Credentials] or the [CredentialsManagerException].
     */
    override fun getCredentials(callback: Callback<Credentials, CredentialsManagerException>) {
        getCredentials(null, 0, callback)
    }

    /**
     * Retrieves the credentials from the storage and refresh them if they have already expired.
     * It will fail with [CredentialsManagerException] if the saved access_token or id_token is null,
     * or if the tokens have already expired and the refresh_token is null.
     *
     * @param scope    the scope to request for the access token. If null is passed, the previous scope will be kept.
     * @param minTtl   the minimum time in seconds that the access token should last before expiration.
     * @param callback the callback that will receive a valid [Credentials] or the [CredentialsManagerException].
     */
    override fun getCredentials(
        scope: String?,
        minTtl: Int,
        callback: Callback<Credentials, CredentialsManagerException>
    ) {
        getCredentials(scope, minTtl, emptyMap(), callback)
    }

    /**
     * Retrieves the credentials from the storage and refresh them if they have already expired.
     * It will fail with [CredentialsManagerException] if the saved access_token or id_token is null,
     * or if the tokens have already expired and the refresh_token is null.
     *
     * @param scope    the scope to request for the access token. If null is passed, the previous scope will be kept.
     * @param minTtl   the minimum time in seconds that the access token should last before expiration.
     * @param parameters additional parameters to send in the request to refresh expired credentials
     * @param callback the callback that will receive a valid [Credentials] or the [CredentialsManagerException].
     */
    override fun getCredentials(
        scope: String?,
        minTtl: Int,
        parameters: Map<String, String>,
        callback: Callback<Credentials, CredentialsManagerException>
    ) {
        getCredentials(scope, minTtl, parameters, false, callback)
    }

    /**
     * Retrieves the credentials from the storage and refresh them if they have already expired.
     * It will fail with [CredentialsManagerException] if the saved access_token or id_token is null,
     * or if the tokens have already expired and the refresh_token is null.
     *
     * @param scope    the scope to request for the access token. If null is passed, the previous scope will be kept.
     * @param minTtl   the minimum time in seconds that the access token should last before expiration.
     * @param parameters additional parameters to send in the request to refresh expired credentials.
     * @param forceRefresh this will avoid returning the existing credentials and retrieves a new one even if valid credentials exist.
     * @param callback the callback that will receive a valid [Credentials] or the [CredentialsManagerException].
     */
    override fun getCredentials(
        scope: String?,
        minTtl: Int,
        parameters: Map<String, String>,
        forceRefresh: Boolean,
        callback: Callback<Credentials, CredentialsManagerException>
    ) {
        getCredentials(scope, minTtl, parameters, mapOf(), forceRefresh, callback)
    }

    /**
     * Retrieves the credentials from the storage and refresh them if they have already expired.
     * It will fail with [CredentialsManagerException] if the saved access_token or id_token is null,
     * or if the tokens have already expired and the refresh_token is null.
     *
     * @param scope    the scope to request for the access token. If null is passed, the previous scope will be kept.
     * @param minTtl   the minimum time in seconds that the access token should last before expiration.
     * @param parameters additional parameters to send in the request to refresh expired credentials.
     * @param headers additional headers to send in the request to refresh expired credentials.
     * @param forceRefresh this will avoid returning the existing credentials and retrieves a new one even if valid credentials exist.
     * @param callback the callback that will receive a valid [Credentials] or the [CredentialsManagerException].
     */
    override fun getCredentials(
        scope: String?,
        minTtl: Int,
        parameters: Map<String, String>,
        headers: Map<String, String>,
        forceRefresh: Boolean,
        callback: Callback<Credentials, CredentialsManagerException>
    ) {
        serialExecutor.execute {
            val accessToken = storage.retrieveString(KEY_ACCESS_TOKEN)
            val refreshToken = storage.retrieveString(KEY_REFRESH_TOKEN)
            val idToken = storage.retrieveString(KEY_ID_TOKEN)
            val tokenType = storage.retrieveString(KEY_TOKEN_TYPE)
            val expiresAt = storage.retrieveLong(KEY_EXPIRES_AT)
            val storedScope = storage.retrieveString(KEY_SCOPE)
            val hasEmptyCredentials =
                TextUtils.isEmpty(accessToken) && TextUtils.isEmpty(idToken) || expiresAt == null
            if (hasEmptyCredentials) {
                callback.onFailure(CredentialsManagerException.NO_CREDENTIALS)
                return@execute
            }
            val willAccessTokenExpire = willExpire(expiresAt!!, minTtl.toLong())
            val scopeChanged = hasScopeChanged(storedScope, scope)
            if (!forceRefresh && !willAccessTokenExpire && !scopeChanged) {
                callback.onSuccess(
                    recreateCredentials(
                        idToken.orEmpty(),
                        accessToken.orEmpty(),
                        tokenType.orEmpty(),
                        refreshToken,
                        Date(expiresAt),
                        storedScope
                    )
                )
                return@execute
            }
            if (refreshToken == null) {
                callback.onFailure(CredentialsManagerException.NO_REFRESH_TOKEN)
                return@execute
            }
            val request = authenticationClient.renewAuth(refreshToken)
            request.addParameters(parameters)
            if (scope != null) {
                request.addParameter("scope", scope)
            }

            for (header in headers) {
                request.addHeader(header.key, header.value)
            }

            try {
                val fresh = request.execute()
                val expiresAt = fresh.expiresAt.time
                val willAccessTokenExpire = willExpire(expiresAt, minTtl.toLong())
                if (willAccessTokenExpire) {
                    val tokenLifetime = (expiresAt - currentTimeInMillis - minTtl * 1000) / -1000
                    val wrongTtlException = CredentialsManagerException(
                        CredentialsManagerException.Code.LARGE_MIN_TTL, String.format(
                            Locale.getDefault(),
                            "The lifetime of the renewed Access Token (%d) is less than the minTTL requested (%d). Increase the 'Token Expiration' setting of your Auth0 API in the dashboard, or request a lower minTTL.",
                            tokenLifetime,
                            minTtl
                        )
                    )
                    callback.onFailure(wrongTtlException)
                    return@execute
                }

                // non-empty refresh token for refresh token rotation scenarios
                val updatedRefreshToken =
                    if (TextUtils.isEmpty(fresh.refreshToken)) refreshToken else fresh.refreshToken
                val credentials = Credentials(
                    fresh.idToken,
                    fresh.accessToken,
                    fresh.type,
                    updatedRefreshToken,
                    fresh.expiresAt,
                    fresh.scope
                )
                saveCredentials(credentials)
                callback.onSuccess(credentials)
            } catch (error: AuthenticationException) {
                val exception = when {
                    error.isRefreshTokenDeleted || error.isInvalidRefreshToken -> CredentialsManagerException.Code.RENEW_FAILED

                    error.isNetworkError -> CredentialsManagerException.Code.NO_NETWORK
                    else -> CredentialsManagerException.Code.API_ERROR
                }
                callback.onFailure(
                    CredentialsManagerException(
                        exception, error
                    )
                )
            } catch (exception: RuntimeException) {
                /**
                 *  Catching any unexpected runtime errors in the token renewal flow
                 */
                Log.e(
                    TAG,
                    "Caught unexpected exceptions for token renewal ${exception.stackTraceToString()}"
                )
                callback.onFailure(
                    CredentialsManagerException(
                        CredentialsManagerException.Code.UNKNOWN_ERROR,
                        exception
                    )
                )
            }
        }
    }


    /**
     *  Retrieves API credentials from storage and automatically renews them using the refresh token if the access
     *  token is expired. Otherwise, the retrieved API credentials will be returned via the success callback as they are still valid.
     *
     * If there are no stored API credentials, the refresh token will be exchanged for a new set of API credentials.
     * New or renewed API credentials will be automatically persisted in storage.
     *
     * @param audience Identifier of the API that your application is requesting access to.
     * @param scope the scope to request for the access token. If null is passed, the previous scope will be kept.
     * @param minTtl the minimum time in seconds that the access token should last before expiration.
     * @param parameters additional parameters to send in the request to refresh expired credentials.
     * @param headers headers to use when exchanging a refresh token for API credentials.
     * @param callback the callback that will receive a valid [Credentials] or the [CredentialsManagerException].
     */
    override fun getApiCredentials(
        audience: String,
        scope: String?,
        minTtl: Int,
        parameters: Map<String, String>,
        headers: Map<String, String>,
        callback: Callback<APICredentials, CredentialsManagerException>
    ) {
        serialExecutor.execute {
            //Check if existing api credentials are present and valid
            val apiCredentialsJson = storage.retrieveString(audience)
            apiCredentialsJson?.let {
                val apiCredentials = gson.fromJson(it, APICredentials::class.java)
                val willTokenExpire = willExpire(apiCredentials.expiresAt.time, minTtl.toLong())
                val scopeChanged = hasScopeChanged(apiCredentials.scope, scope)
                val hasExpired = hasExpired(apiCredentials.expiresAt.time)
                if (!hasExpired && !willTokenExpire && !scopeChanged) {
                    callback.onSuccess(apiCredentials)
                    return@execute
                }
            }
            //Check if refresh token exists or not
            val refreshToken = storage.retrieveString(KEY_REFRESH_TOKEN)
            if (refreshToken == null) {
                callback.onFailure(CredentialsManagerException.NO_REFRESH_TOKEN)
                return@execute
            }

            val request = authenticationClient.renewAuth(refreshToken, audience, scope)
            request.addParameters(parameters)

            for (header in headers) {
                request.addHeader(header.key, header.value)
            }

            try {
                val newCredentials = request.execute()
                val expiresAt = newCredentials.expiresAt.time
                val willAccessTokenExpire = willExpire(expiresAt, minTtl.toLong())
                if (willAccessTokenExpire) {
                    val tokenLifetime = (expiresAt - currentTimeInMillis - minTtl * 1000) / -1000
                    val wrongTtlException = CredentialsManagerException(
                        CredentialsManagerException.Code.LARGE_MIN_TTL, String.format(
                            Locale.getDefault(),
                            "The lifetime of the renewed Access Token (%d) is less than the minTTL requested (%d). Increase the 'Token Expiration' setting of your Auth0 API in the dashboard, or request a lower minTTL.",
                            tokenLifetime,
                            minTtl
                        )
                    )
                    callback.onFailure(wrongTtlException)
                    return@execute
                }

                // non-empty refresh token for refresh token rotation scenarios
                val updatedRefreshToken =
                    if (TextUtils.isEmpty(newCredentials.refreshToken)) refreshToken else newCredentials.refreshToken
                val newApiCredentials = newCredentials.toAPICredentials()
                storage.store(KEY_REFRESH_TOKEN, updatedRefreshToken)
                storage.store(KEY_ID_TOKEN, newCredentials.idToken)
                saveApiCredentials(newApiCredentials, audience)
                callback.onSuccess(newApiCredentials)
            } catch (error: AuthenticationException) {
                val exception = when {
                    error.isRefreshTokenDeleted || error.isInvalidRefreshToken -> CredentialsManagerException.Code.RENEW_FAILED

                    error.isNetworkError -> CredentialsManagerException.Code.NO_NETWORK
                    else -> CredentialsManagerException.Code.API_ERROR
                }
                callback.onFailure(
                    CredentialsManagerException(
                        exception, error
                    )
                )
            }
        }

    }

    /**
     * Checks if a non-expired pair of credentials can be obtained from this manager.
     *
     * @return whether there are valid credentials stored on this manager.
     */
    override fun hasValidCredentials(): Boolean {
        return hasValidCredentials(0)
    }

    /**
     * Checks if a non-expired pair of credentials can be obtained from this manager.
     *
     * @param minTtl the minimum time in seconds that the access token should last before expiration.
     * @return whether there are valid credentials stored on this manager.
     */
    override fun hasValidCredentials(minTtl: Long): Boolean {
        val accessToken = storage.retrieveString(KEY_ACCESS_TOKEN)
        val refreshToken = storage.retrieveString(KEY_REFRESH_TOKEN)
        val idToken = storage.retrieveString(KEY_ID_TOKEN)
        val expiresAt = storage.retrieveLong(KEY_EXPIRES_AT)
        val emptyCredentials =
            TextUtils.isEmpty(accessToken) && TextUtils.isEmpty(idToken) || expiresAt == null
        return !(emptyCredentials || willExpire(
            expiresAt!!, minTtl
        ) && refreshToken == null)
    }

    /**
     * Removes the credentials from the storage if present.
     */
    override fun clearCredentials() {
        storage.remove(KEY_ACCESS_TOKEN)
        storage.remove(KEY_REFRESH_TOKEN)
        storage.remove(KEY_ID_TOKEN)
        storage.remove(KEY_TOKEN_TYPE)
        storage.remove(KEY_EXPIRES_AT)
        storage.remove(KEY_SCOPE)
        storage.remove(LEGACY_KEY_CACHE_EXPIRES_AT)
    }

    /**
     * Removes the credentials for the given audience from the storage if present.
     */
    override fun clearApiCredentials(audience: String) {
        storage.remove(audience)
        Log.d(TAG, "API Credentials for $audience were just removed from the storage")
    }

    /**
     * Helper method to store the given [SSOCredentials] refresh token in the storage.
     * Method will silently return if the passed credentials have no refresh token.
     *
     * @param ssoCredentials the credentials to save in the storage.
     */
    @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    internal fun saveSsoCredentials(ssoCredentials: SSOCredentials) {
        storage.store(KEY_ID_TOKEN, ssoCredentials.idToken)
        val existingRefreshToken = storage.retrieveString(KEY_REFRESH_TOKEN)
        // Checking if the existing one needs to be replaced with the new one
        if (ssoCredentials.refreshToken.isNullOrEmpty())
            return // No refresh token to save
        if (ssoCredentials.refreshToken == existingRefreshToken)
            return // Same refresh token, no need to save
        storage.store(KEY_REFRESH_TOKEN, ssoCredentials.refreshToken)
    }

    @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    internal fun recreateCredentials(
        idToken: String,
        accessToken: String,
        tokenType: String,
        refreshToken: String?,
        expiresAt: Date,
        scope: String?
    ): Credentials {
        return Credentials(idToken, accessToken, tokenType, refreshToken, expiresAt, scope)
    }

    private companion object {
        private const val KEY_ACCESS_TOKEN = "com.auth0.access_token"
        private const val KEY_REFRESH_TOKEN = "com.auth0.refresh_token"
        private const val KEY_ID_TOKEN = "com.auth0.id_token"
        private const val KEY_TOKEN_TYPE = "com.auth0.token_type"
        private const val KEY_EXPIRES_AT = "com.auth0.expires_at"
        private const val KEY_SCOPE = "com.auth0.scope"

        // This is no longer used as we get the credentials expiry from the access token only,
        // but we still store it so users can rollback to versions where it is required.
        private const val LEGACY_KEY_CACHE_EXPIRES_AT = "com.auth0.cache_expires_at"
        private val TAG = CredentialsManager::class.java.simpleName
    }
}