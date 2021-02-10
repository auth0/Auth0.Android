package com.auth0.android.authentication.storage

import android.text.TextUtils
import androidx.annotation.VisibleForTesting
import com.auth0.android.authentication.AuthenticationAPIClient
import com.auth0.android.authentication.AuthenticationException
import com.auth0.android.callback.AuthenticationCallback
import com.auth0.android.callback.Callback
import com.auth0.android.result.Credentials
import java.util.*

/**
 * Class that handles credentials and allows to save and retrieve them.
 */
public class CredentialsManager @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE) internal constructor(
    authenticationClient: AuthenticationAPIClient,
    storage: Storage,
    jwtDecoder: JWTDecoder
) : BaseCredentialsManager(authenticationClient, storage, jwtDecoder) {
    /**
     * Creates a new instance of the manager that will store the credentials in the given Storage.
     *
     * @param authenticationClient the Auth0 Authentication client to refresh credentials with.
     * @param storage              the storage to use for the credentials.
     */
    public constructor(authenticationClient: AuthenticationAPIClient, storage: Storage) : this(
        authenticationClient,
        storage,
        JWTDecoder()
    )

    /**
     * Stores the given credentials in the storage. Must have an access_token or id_token and a expires_in value.
     *
     * @param credentials the credentials to save in the storage.
     */
    override fun saveCredentials(credentials: Credentials) {
        if (TextUtils.isEmpty(credentials.accessToken) && TextUtils.isEmpty(credentials.idToken)) {
            throw CredentialsManagerException("Credentials must have a valid date of expiration and a valid access_token or id_token value.")
        }
        val cacheExpiresAt = calculateCacheExpiresAt(credentials)
        storage.store(KEY_ACCESS_TOKEN, credentials.accessToken)
        storage.store(KEY_REFRESH_TOKEN, credentials.refreshToken)
        storage.store(KEY_ID_TOKEN, credentials.idToken)
        storage.store(KEY_TOKEN_TYPE, credentials.type)
        storage.store(KEY_EXPIRES_AT, credentials.expiresAt.time)
        storage.store(KEY_SCOPE, credentials.scope)
        storage.store(KEY_CACHE_EXPIRES_AT, cacheExpiresAt)
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
        val accessToken = storage.retrieveString(KEY_ACCESS_TOKEN)
        val refreshToken = storage.retrieveString(KEY_REFRESH_TOKEN)
        val idToken = storage.retrieveString(KEY_ID_TOKEN)
        val tokenType = storage.retrieveString(KEY_TOKEN_TYPE)
        val expiresAt = storage.retrieveLong(KEY_EXPIRES_AT)
        val storedScope = storage.retrieveString(KEY_SCOPE)
        var cacheExpiresAt = storage.retrieveLong(KEY_CACHE_EXPIRES_AT)
        if (cacheExpiresAt == null) {
            cacheExpiresAt = expiresAt
        }
        val hasEmptyCredentials =
            TextUtils.isEmpty(accessToken) && TextUtils.isEmpty(idToken) || expiresAt == null
        if (hasEmptyCredentials) {
            callback.onFailure(CredentialsManagerException("No Credentials were previously set."))
            return
        }
        val hasEitherExpired = hasExpired(cacheExpiresAt!!)
        val willAccessTokenExpire = willExpire(expiresAt!!, minTtl.toLong())
        val scopeChanged = hasScopeChanged(storedScope!!, scope)
        if (!hasEitherExpired && !willAccessTokenExpire && !scopeChanged) {
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
            return
        }
        if (refreshToken == null) {
            callback.onFailure(CredentialsManagerException("Credentials need to be renewed but no Refresh Token is available to renew them."))
            return
        }
        val request = authenticationClient.renewAuth(refreshToken)
        if (scope != null) {
            request.addParameter("scope", scope)
        }
        request.start(object : AuthenticationCallback<Credentials> {
            override fun onSuccess(fresh: Credentials) {
                val expiresAt = fresh.expiresAt.time
                val willAccessTokenExpire = willExpire(expiresAt, minTtl.toLong())
                if (willAccessTokenExpire) {
                    val tokenLifetime = (expiresAt - currentTimeInMillis - minTtl * 1000) / -1000
                    val wrongTtlException = CredentialsManagerException(
                        String.format(
                            Locale.getDefault(),
                            "The lifetime of the renewed Access Token (%d) is less than the minTTL requested (%d). Increase the 'Token Expiration' setting of your Auth0 API in the dashboard, or request a lower minTTL.",
                            tokenLifetime,
                            minTtl
                        )
                    )
                    callback.onFailure(wrongTtlException)
                    return
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
            }

            override fun onFailure(error: AuthenticationException) {
                callback.onFailure(
                    CredentialsManagerException(
                        "An error occurred while trying to use the Refresh Token to renew the Credentials.",
                        error
                    )
                )
            }
        })
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
        var cacheExpiresAt = storage.retrieveLong(KEY_CACHE_EXPIRES_AT)
        if (cacheExpiresAt == null) {
            cacheExpiresAt = expiresAt
        }
        val emptyCredentials =
            TextUtils.isEmpty(accessToken) && TextUtils.isEmpty(idToken) || cacheExpiresAt == null || expiresAt == null
        return !(emptyCredentials || (hasExpired(cacheExpiresAt!!) || willExpire(
            expiresAt!!,
            minTtl
        )) && refreshToken == null)
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
        storage.remove(KEY_CACHE_EXPIRES_AT)
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
        private const val KEY_CACHE_EXPIRES_AT = "com.auth0.cache_expires_at"
    }
}