package com.auth0.android.authentication.storage

import androidx.annotation.VisibleForTesting
import com.auth0.android.authentication.AuthenticationAPIClient
import com.auth0.android.callback.Callback
import com.auth0.android.result.Credentials
import com.auth0.android.util.Clock
import java.util.*
import kotlin.math.min

/**
 * Base class meant to abstract common logic across Credentials Manager implementations.
 * The scope of this class is package-private, as it's not meant to be exposed
 */
public abstract class BaseCredentialsManager internal constructor(
    protected val authenticationClient: AuthenticationAPIClient,
    protected val storage: Storage,
    private val jwtDecoder: JWTDecoder
) {
    private var _clock: Clock = ClockImpl()

    /**
     * Updates the clock instance used for expiration verification purposes.
     * The use of this method can help on situations where the clock comes from an external synced source.
     * The default implementation uses the time returned by [System.currentTimeMillis].
     */
    public fun setClock(clock: Clock) {
        this._clock = clock
    }

    @Throws(CredentialsManagerException::class)
    public abstract fun saveCredentials(credentials: Credentials)
    public abstract fun getCredentials(callback: Callback<Credentials, CredentialsManagerException>)
    public abstract fun getCredentials(
        scope: String?,
        minTtl: Int,
        callback: Callback<Credentials, CredentialsManagerException>
    )

    public abstract fun getCredentials(
        scope: String?,
        minTtl: Int,
        parameters: Map<String, String>,
        callback: Callback<Credentials, CredentialsManagerException>
    )

    public abstract fun clearCredentials()
    public abstract fun hasValidCredentials(): Boolean
    public abstract fun hasValidCredentials(minTtl: Long): Boolean

    @get:VisibleForTesting(otherwise = VisibleForTesting.PACKAGE_PRIVATE)
    internal val currentTimeInMillis: Long
        get() = _clock.getCurrentTimeMillis()

    /**
     * Checks if the stored scope is the same as the requested one.
     *
     * @param storedScope   the stored scope, separated by space characters.
     * @param requiredScope the required scope, separated by space characters.
     * @return whether the scope are different or not
     */
    protected fun hasScopeChanged(storedScope: String?, requiredScope: String?): Boolean {
        if (requiredScope == null) {
            return false
        }
        val stored = storedScope.orEmpty().split(" ").toTypedArray()
        Arrays.sort(stored)
        val required = requiredScope.split(" ").toTypedArray()
        Arrays.sort(required)
        return !stored.contentEquals(required)
    }

    /**
     * Checks if given the required minimum time to live, the expiration time can satisfy that value or not.
     *
     * @param expiresAt the expiration time, in milliseconds.
     * @param minTtl    the time to live required, in seconds.
     * @return whether the value will become expired within the given min TTL or not.
     */
    protected fun willExpire(expiresAt: Long, minTtl: Long): Boolean {
        if (expiresAt <= 0) {
            // Avoids logging out users when this value was not saved (migration scenario)
            return false
        }
        val nextClock = currentTimeInMillis + minTtl * 1000
        return expiresAt <= nextClock
    }

    /**
     * Checks whether the given expiration time has been reached or not.
     *
     * @param expiresAt the expiration time, in milliseconds.
     * @return whether the given expiration time has been reached or not.
     */
    protected fun hasExpired(expiresAt: Long): Boolean {
        return expiresAt <= currentTimeInMillis
    }

    /**
     * Takes a credentials object and returns the lowest expiration time, considering
     * both the access token and the ID token expiration time.
     *
     * @param credentials the credentials object to check.
     * @return the lowest expiration time between the access token and the ID token.
     */
    protected fun calculateCacheExpiresAt(credentials: Credentials): Long {
        var expiresAt = credentials.expiresAt.time
        if (credentials.idToken.isNotEmpty()) {
            val idToken = jwtDecoder.decode(credentials.idToken)
            val idTokenExpiresAtDate = idToken.expiresAt
            if (idTokenExpiresAtDate != null) {
                expiresAt = min(idTokenExpiresAtDate.time, expiresAt)
            }
        }
        return expiresAt
    }

}