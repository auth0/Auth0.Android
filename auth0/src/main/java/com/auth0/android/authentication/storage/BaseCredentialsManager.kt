package com.auth0.android.authentication.storage

import android.util.Log
import androidx.annotation.VisibleForTesting
import com.auth0.android.authentication.AuthenticationAPIClient
import com.auth0.android.callback.Callback
import com.auth0.android.dpop.DPoPException
import com.auth0.android.dpop.DPoPUtil
import com.auth0.android.result.APICredentials
import com.auth0.android.result.Credentials
import com.auth0.android.result.SSOCredentials
import com.auth0.android.result.UserProfile
import com.auth0.android.util.Clock
import java.util.*

/**
 * Base class meant to abstract common logic across Credentials Manager implementations.
 * The scope of this class is package-private, as it's not meant to be exposed
 */
public abstract class BaseCredentialsManager internal constructor(
    protected val authenticationClient: AuthenticationAPIClient,
    protected val storage: Storage,
    private val jwtDecoder: JWTDecoder
) {

    internal companion object {
        internal const val KEY_DPOP_THUMBPRINT = "com.auth0.dpop_key_thumbprint"

        @VisibleForTesting(otherwise = VisibleForTesting.PACKAGE_PRIVATE)
        internal const val KEY_TOKEN_TYPE = "com.auth0.token_type"

        /**
         * Default minimum time to live (in seconds) for the access token.
         * When retrieving credentials, if the access token has less than this amount of time
         * remaining before expiration, it will be automatically renewed.
         * This ensures the access token is valid for at least a short window after retrieval,
         * preventing downstream API call failures from nearly-expired tokens.
         */
        internal const val DEFAULT_MIN_TTL: Int = 60
    }

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
    public abstract fun saveApiCredentials(
        apiCredentials: APICredentials,
        audience: String,
        scope: String? = null
    )

    public abstract fun getCredentials(callback: Callback<Credentials, CredentialsManagerException>)
    public abstract fun getSsoCredentials(
        parameters: Map<String, String>,
        callback: Callback<SSOCredentials, CredentialsManagerException>
    )


    public abstract fun getSsoCredentials(
        callback: Callback<SSOCredentials, CredentialsManagerException>
    )

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

    public abstract fun getCredentials(
        scope: String?,
        minTtl: Int,
        parameters: Map<String, String>,
        forceRefresh: Boolean,
        callback: Callback<Credentials, CredentialsManagerException>
    )

    public abstract fun getCredentials(
        scope: String?,
        minTtl: Int,
        parameters: Map<String, String>,
        headers: Map<String, String>,
        forceRefresh: Boolean,
        callback: Callback<Credentials, CredentialsManagerException>
    )

    public abstract fun getApiCredentials(
        audience: String,
        scope: String? = null,
        minTtl: Int = DEFAULT_MIN_TTL,
        parameters: Map<String, String> = emptyMap(),
        headers: Map<String, String> = emptyMap(),
        callback: Callback<APICredentials, CredentialsManagerException>
    )

    @JvmSynthetic
    @Throws(CredentialsManagerException::class)
    public abstract suspend fun awaitSsoCredentials(parameters: Map<String, String>)
            : SSOCredentials

    @JvmSynthetic
    @Throws(CredentialsManagerException::class)
    public abstract suspend fun awaitSsoCredentials()
            : SSOCredentials

    @JvmSynthetic
    @Throws(CredentialsManagerException::class)
    public abstract suspend fun awaitCredentials(): Credentials

    @JvmSynthetic
    @Throws(CredentialsManagerException::class)
    public abstract suspend fun awaitCredentials(scope: String?, minTtl: Int): Credentials

    @JvmSynthetic
    @Throws(CredentialsManagerException::class)
    public abstract suspend fun awaitCredentials(
        scope: String?,
        minTtl: Int,
        parameters: Map<String, String>
    ): Credentials

    @JvmSynthetic
    @Throws(CredentialsManagerException::class)
    public abstract suspend fun awaitCredentials(
        scope: String?,
        minTtl: Int,
        parameters: Map<String, String>,
        forceRefresh: Boolean
    ): Credentials

    @JvmSynthetic
    @Throws(CredentialsManagerException::class)
    public abstract suspend fun awaitCredentials(
        scope: String?,
        minTtl: Int,
        parameters: Map<String, String>,
        headers: Map<String, String>,
        forceRefresh: Boolean
    ): Credentials

    @JvmSynthetic
    @Throws(CredentialsManagerException::class)
    public abstract suspend fun awaitApiCredentials(
        audience: String,
        scope: String? = null,
        minTtl: Int = DEFAULT_MIN_TTL,
        parameters: Map<String, String> = emptyMap(),
        headers: Map<String, String> = emptyMap()
    ): APICredentials

    public abstract val userProfile: UserProfile?

    public abstract fun clearCredentials()
    public abstract fun clearApiCredentials(audience: String, scope: String? = null)
    public abstract fun clearAll()
    public abstract fun hasValidCredentials(): Boolean
    public abstract fun hasValidCredentials(minTtl: Long): Boolean

    @get:VisibleForTesting(otherwise = VisibleForTesting.PACKAGE_PRIVATE)
    internal val currentTimeInMillis: Long
        get() = _clock.getCurrentTimeMillis()

    /**
     * Stores the DPoP key thumbprint if DPoP was used for this credential set.
     * Uses a dual strategy to store the thumbprint:
     * - credentials.type == "DPoP" when server confirms DPoP but client lacks useDPoP()
     * - isDPoPEnabled catches the case where client used DPoP, server returned token_type: "Bearer"
     */
    protected fun saveDPoPThumbprint(credentials: Credentials) {
        val dpopUsed = credentials.type.equals("DPoP", ignoreCase = true)
                || authenticationClient.isDPoPEnabled

        if (!dpopUsed) {
            storage.remove(KEY_DPOP_THUMBPRINT)
            return
        }

        val thumbprint = try {
            if (DPoPUtil.hasKeyPair()) DPoPUtil.getPublicKeyJWK() else null
        } catch (e: DPoPException) {
            Log.w(this::class.java.simpleName, "Failed to fetch DPoP key thumbprint", e)
            null
        }

        if (thumbprint != null) {
            storage.store(KEY_DPOP_THUMBPRINT, thumbprint)
        } else {
            storage.remove(KEY_DPOP_THUMBPRINT)
        }
    }

    /**
     * Validates DPoP key/token alignment before attempting a refresh.
     *
     * Uses two signals to detect DPoP-bound credentials:
     * - tokenType == "DPoP"
     * - KEY_DPOP_THUMBPRINT exists
     *
     * @param tokenType the token_type value from storage (or decrypted credentials for migration)
     * @return null if validation passes, or a CredentialsManagerException if it fails
     */
    protected fun validateDPoPState(tokenType: String?): CredentialsManagerException? {
        val storedThumbprint = storage.retrieveString(KEY_DPOP_THUMBPRINT)
        val isDPoPBound = (tokenType?.equals("DPoP", ignoreCase = true) == true)
            || (storedThumbprint != null)
        if (!isDPoPBound) return null

        // Check 1: Does the DPoP key still exist in KeyStore?
        val hasKey = try {
            DPoPUtil.hasKeyPair()
        } catch (e: DPoPException) {
            Log.e(this::class.java.simpleName, "Failed to check DPoP key existence", e)
            false
        }
        if (!hasKey) {
            Log.w(this::class.java.simpleName, "DPoP key missing from KeyStore. Clearing stale credentials.")
            clearCredentials()
            return CredentialsManagerException(CredentialsManagerException.Code.DPOP_KEY_MISSING)
        }

        // Check 2: Is the AuthenticationAPIClient configured with DPoP?
        if (!authenticationClient.isDPoPEnabled) {
            return CredentialsManagerException(CredentialsManagerException.Code.DPOP_NOT_CONFIGURED)
        }

        // Check 3: Does the current key match the one used when credentials were saved?
        val currentThumbprint = try {
            DPoPUtil.getPublicKeyJWK()
        } catch (e: DPoPException) {
            Log.e(this::class.java.simpleName, "Failed to read DPoP key thumbprint", e)
            null
        }

        if (storedThumbprint != null) {
            if (currentThumbprint != storedThumbprint) {
                Log.w(this::class.java.simpleName, "DPoP key thumbprint mismatch. The key pair has changed since credentials were saved. Clearing stale credentials.")
                clearCredentials()
                return CredentialsManagerException(CredentialsManagerException.Code.DPOP_KEY_MISMATCH)
            }
        } else if (currentThumbprint != null) {
            // Migration: existing DPoP user upgraded — no thumbprint stored yet.
            // Backfill so future checks can detect key rotation.
            storage.store(KEY_DPOP_THUMBPRINT, currentThumbprint)
        }

        return null
    }

    /**
     * Checks if the stored scope is the same as the requested one.
     *
     * @param storedScope   the stored scope, separated by space characters.
     * @param requiredScope the required scope, separated by space characters.
     * @param ignoreOpenid whether to ignore the openid scope from the storedScope or not while comparing.
     * @return whether the scope are different or not
     */
    protected fun hasScopeChanged(
        storedScope: String?,
        requiredScope: String?,
        ignoreOpenid: Boolean = false
    ): Boolean {
        if (requiredScope == null) {
            return false
        }
        val storedScopes =
            storedScope.orEmpty().split(" ").filter { it.isNotEmpty() }.toMutableSet()
        if (ignoreOpenid) {
            storedScopes.remove("openid")
        }
        val requiredScopes = requiredScope.split(" ").filter { it.isNotEmpty() }.toSet()
        return storedScopes != requiredScopes
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
     * Returns the key for storing the APICredentials in storage. Uses a combination of audience and scope.
     *
     * @param audience the audience of the credentials.
     * @param scope    optional scope for the credentials.
     */
    protected fun getAPICredentialsKey(audience: String, scope: String?): String {
        // Use audience if scope is null else use a combination of audience and scope
        if (scope == null) return audience
        val sortedScope = scope.split(" ").sorted().joinToString("::")
        return "$audience::${sortedScope}"

    }
}
