package com.auth0.android.authentication.storage

import android.app.Activity
import android.content.Context
import android.opengl.Visibility
import android.provider.Settings.Secure
import android.text.TextUtils
import android.util.Base64
import android.util.Log
import androidx.annotation.VisibleForTesting
import androidx.fragment.app.FragmentActivity
import com.auth0.android.Auth0Exception
import com.auth0.android.authentication.AuthenticationAPIClient
import com.auth0.android.callback.Callback
import com.auth0.android.request.internal.GsonProvider
import com.auth0.android.result.Credentials
import com.auth0.android.result.OptionalCredentials
import com.google.gson.Gson
import kotlinx.coroutines.suspendCancellableCoroutine
import java.util.*
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * A safer alternative to the [CredentialsManager] class. A combination of RSA and AES keys is used to keep the values secure.
 * On devices with a Secure LockScreen configured (PIN, Pattern, Password or Fingerprint) an extra authentication step can be required.
 */
public class SecureCredentialsManager @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE) internal constructor(
    apiClient: AuthenticationAPIClient,
    storage: Storage,
    private val crypto: CryptoUtil,
    jwtDecoder: JWTDecoder,
    private val serialExecutor: Executor,
    private val localAuthenticationManagerFactory: LocalAuthenticationManagerFactory
) : SecuredCredentialsManager(apiClient, storage, jwtDecoder) {
    private val gson: Gson = GsonProvider.gson


    /**
     * Creates a new SecureCredentialsManager to handle Credentials
     *
     * @param context   a valid context
     * @param apiClient the Auth0 Authentication API Client to handle token refreshment when needed.
     * @param storage   the storage implementation to use
     */
    public constructor(
        context: Context,
        apiClient: AuthenticationAPIClient,
        storage: Storage
    ) : this(
        apiClient,
        storage,
        CryptoUtil(context, storage, KEY_ALIAS),
        JWTDecoder(),
        Executors.newSingleThreadExecutor(),
        DefaultLocalAuthenticationManagerFactory()
    )


    /**
     * Saves the given credentials in the Storage.
     *
     * @param credentials the credentials to save.
     * @throws CredentialsManagerException if the credentials couldn't be encrypted. Some devices are not compatible at all with the cryptographic
     * implementation and will have [CredentialsManagerException.isDeviceIncompatible] return true.
     */
    @Throws(CredentialsManagerException::class)
    @Synchronized
    override fun saveCredentials(credentials: Credentials) {
        if (TextUtils.isEmpty(credentials.accessToken) && TextUtils.isEmpty(credentials.idToken)) {
            throw CredentialsManagerException.INVALID_CREDENTIALS
        }
        val json = gson.toJson(credentials)
        val canRefresh = !TextUtils.isEmpty(credentials.refreshToken)
        Log.d(TAG, "Trying to encrypt the given data using the private key.")
        try {
            val encrypted = crypto.encrypt(json.toByteArray())
            val encryptedEncoded = Base64.encodeToString(encrypted, Base64.DEFAULT)
            storage.store(KEY_CREDENTIALS, encryptedEncoded)
            storage.store(
                KEY_EXPIRES_AT, credentials.expiresAt.time
            )
            storage.store(LEGACY_KEY_CACHE_EXPIRES_AT, credentials.expiresAt.time)
            storage.store(KEY_CAN_REFRESH, canRefresh)
        } catch (e: IncompatibleDeviceException) {
            throw CredentialsManagerException(
                CredentialsManagerException.Code.INCOMPATIBLE_DEVICE,
                e
            )
        } catch (e: CryptoException) {
            /*
             * If the keys were invalidated in the call above a good new pair is going to be available
             * to use on the next call. We clear any existing credentials so #hasValidCredentials returns
             * a true value. Retrying this operation will succeed.
             */
            clearCredentials()
            throw CredentialsManagerException(CredentialsManagerException.Code.CRYPTO_EXCEPTION, e)
        }
    }

    /**
     * Tries to obtain the credentials from the Storage. The method will return [Credentials].
     * If something unexpected happens, then [CredentialsManagerException] exception will be thrown. Some devices are not compatible
     * at all with the cryptographic implementation and will have [CredentialsManagerException.isDeviceIncompatible] return true.
     * This is a Coroutine that is exposed only for Kotlin.
     *
     * If the user's lock screen authentication configuration matches the authentication level specified in the [authenticationOptions],
     * the user will be prompted to authenticate before accessing the credentials.
     *
     * @param fragmentActivity the activity that will be used to host the [androidx.biometric.BiometricPrompt]
     * @param authenticationOptions, an instance of [LocalAuthenticationOptions] used to configure authentication performed using [androidx.biometric.BiometricPrompt]
     */
    @JvmSynthetic
    @Throws(CredentialsManagerException::class)
    public suspend fun awaitCredentials(
        fragmentActivity: FragmentActivity,
        authenticationOptions: LocalAuthenticationOptions
    ): Credentials {
        return awaitCredentials(fragmentActivity, authenticationOptions, null, 0)
    }

    /**
     * Tries to obtain the credentials from the Storage. The method will return [Credentials].
     * If something unexpected happens, then [CredentialsManagerException] exception will be thrown. Some devices are not compatible
     * at all with the cryptographic implementation and will have [CredentialsManagerException.isDeviceIncompatible] return true.
     * This is a Coroutine that is exposed only for Kotlin.
     *
     * If the user's lock screen authentication configuration matches the authentication level specified in the [authenticationOptions],
     * the user will be prompted to authenticate before accessing the credentials.
     *
     * @param fragmentActivity the activity that will be used to host the [androidx.biometric.BiometricPrompt]
     * @param authenticationOptions, an instance of [LocalAuthenticationOptions] used to configure authentication performed using [androidx.biometric.BiometricPrompt]
     * @param scope    the scope to request for the access token. If null is passed, the previous scope will be kept.
     * @param minTtl   the minimum time in seconds that the access token should last before expiration.
     */
    @JvmSynthetic
    @Throws(CredentialsManagerException::class)
    public suspend fun awaitCredentials(
        fragmentActivity: FragmentActivity,
        authenticationOptions: LocalAuthenticationOptions,
        scope: String?,
        minTtl: Int
    ): Credentials {
        return awaitCredentials(fragmentActivity, authenticationOptions, scope, minTtl, emptyMap())
    }

    /**
     * Tries to obtain the credentials from the Storage. The method will return [Credentials].
     * If something unexpected happens, then [CredentialsManagerException] exception will be thrown. Some devices are not compatible
     * at all with the cryptographic implementation and will have [CredentialsManagerException.isDeviceIncompatible] return true.
     * This is a Coroutine that is exposed only for Kotlin.
     *
     * If the user's lock screen authentication configuration matches the authentication level specified in the [authenticationOptions],
     * the user will be prompted to authenticate before accessing the credentials.
     *
     * @param fragmentActivity the activity that will be used to host the [androidx.biometric.BiometricPrompt]
     * @param authenticationOptions, an instance of [LocalAuthenticationOptions] used to configure authentication performed using [androidx.biometric.BiometricPrompt]
     * @param scope    the scope to request for the access token. If null is passed, the previous scope will be kept.
     * @param minTtl   the minimum time in seconds that the access token should last before expiration.
     * @param parameters additional parameters to send in the request to refresh expired credentials
     */
    @JvmSynthetic
    @Throws(CredentialsManagerException::class)
    public suspend fun awaitCredentials(
        fragmentActivity: FragmentActivity,
        authenticationOptions: LocalAuthenticationOptions,
        scope: String?,
        minTtl: Int,
        parameters: Map<String, String>
    ): Credentials {
        return awaitCredentials(
            fragmentActivity,
            authenticationOptions,
            scope,
            minTtl,
            parameters,
            false
        )
    }

    /**
     * Tries to obtain the credentials from the Storage. The method will return [Credentials].
     * If something unexpected happens, then [CredentialsManagerException] exception will be thrown. Some devices are not compatible
     * at all with the cryptographic implementation and will have [CredentialsManagerException.isDeviceIncompatible] return true.
     * This is a Coroutine that is exposed only for Kotlin.
     *
     * If the user's lock screen authentication configuration matches the authentication level specified in the [authenticationOptions],
     * the user will be prompted to authenticate before accessing the credentials.
     *
     * @param fragmentActivity the activity that will be used to host the [androidx.biometric.BiometricPrompt]
     * @param authenticationOptions, an instance of [LocalAuthenticationOptions] used to configure authentication performed using [androidx.biometric.BiometricPrompt]
     * @param scope    the scope to request for the access token. If null is passed, the previous scope will be kept.
     * @param minTtl   the minimum time in seconds that the access token should last before expiration.
     * @param parameters additional parameters to send in the request to refresh expired credentials.
     * @param forceRefresh this will avoid returning the existing credentials and retrieves a new one even if valid credentials exist.
     */
    @JvmSynthetic
    @Throws(CredentialsManagerException::class)
    public suspend fun awaitCredentials(
        fragmentActivity: FragmentActivity,
        authenticationOptions: LocalAuthenticationOptions,
        scope: String?,
        minTtl: Int,
        parameters: Map<String, String>,
        forceRefresh: Boolean,
    ): Credentials {
        return awaitCredentials(
            fragmentActivity,
            authenticationOptions,
            scope,
            minTtl,
            parameters,
            mapOf(),
            forceRefresh
        )
    }

    /**
     * Tries to obtain the credentials from the Storage. The method will return [Credentials].
     * If something unexpected happens, then [CredentialsManagerException] exception will be thrown. Some devices are not compatible
     * at all with the cryptographic implementation and will have [CredentialsManagerException.isDeviceIncompatible] return true.
     * This is a Coroutine that is exposed only for Kotlin.
     *
     * If the user's lock screen authentication configuration matches the authentication level specified in the [authenticationOptions],
     * the user will be prompted to authenticate before accessing the credentials.
     *
     * @param fragmentActivity the activity that will be used to host the [androidx.biometric.BiometricPrompt]
     * @param authenticationOptions, an instance of [LocalAuthenticationOptions] used to configure authentication performed using [androidx.biometric.BiometricPrompt]
     * @param scope    the scope to request for the access token. If null is passed, the previous scope will be kept.
     * @param minTtl   the minimum time in seconds that the access token should last before expiration.
     * @param parameters additional parameters to send in the request to refresh expired credentials.
     * @param headers additional headers to send in the request to refresh expired credentials.
     * @param forceRefresh this will avoid returning the existing credentials and retrieves a new one even if valid credentials exist.
     */
    @JvmSynthetic
    @Throws(CredentialsManagerException::class)
    public suspend fun awaitCredentials(
        fragmentActivity: FragmentActivity,
        authenticationOptions: LocalAuthenticationOptions,
        scope: String?,
        minTtl: Int,
        parameters: Map<String, String>,
        headers: Map<String, String>,
        forceRefresh: Boolean,
    ): Credentials {
        return suspendCancellableCoroutine { continuation ->
            getCredentials(
                fragmentActivity,
                authenticationOptions,
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
     * Tries to obtain the credentials from the Storage. The callback's [Callback.onSuccess] method will be called with the result.
     * If something unexpected happens, the [Callback.onFailure] method will be called with the error. Some devices are not compatible
     * at all with the cryptographic implementation and will have [CredentialsManagerException.isDeviceIncompatible] return true.
     *
     * If the user's lock screen authentication configuration matches the authentication level specified in the [authenticationOptions],
     * the user will be prompted to authenticate before accessing the credentials.
     *
     * @param fragmentActivity the activity that will be used to host the [androidx.biometric.BiometricPrompt]
     * @param authenticationOptions an instance of [LocalAuthenticationOptions] used to configure authentication performed using [androidx.biometric.BiometricPrompt]
     * @param callback the callback to receive the result in.
     */
    override fun getCredentials(
        fragmentActivity: FragmentActivity,
        authenticationOptions: LocalAuthenticationOptions,
        callback: Callback<Credentials, CredentialsManagerException>
    ) {
        getCredentials(fragmentActivity, authenticationOptions, null, 0, callback)
    }

    /**
     * Tries to obtain the credentials from the Storage. The callback's [Callback.onSuccess] method will be called with the result.
     * If something unexpected happens, the [Callback.onFailure] method will be called with the error. Some devices are not compatible
     * at all with the cryptographic implementation and will have [CredentialsManagerException.isDeviceIncompatible] return true.
     *
     * If the user's lock screen authentication configuration matches the authentication level specified in the [authenticationOptions],
     * the user will be prompted to authenticate before accessing the credentials.
     *
     * @param fragmentActivity the activity that will be used to host the [androidx.biometric.BiometricPrompt]
     * @param authenticationOptions an instance of [LocalAuthenticationOptions] used to configure authentication performed using [androidx.biometric.BiometricPrompt]
     * @param scope    the scope to request for the access token. If null is passed, the previous scope will be kept.
     * @param minTtl   the minimum time in seconds that the access token should last before expiration.
     * @param callback the callback to receive the result in.
     */
    override fun getCredentials(
        fragmentActivity: FragmentActivity,
        authenticationOptions: LocalAuthenticationOptions,
        scope: String?,
        minTtl: Int,
        callback: Callback<Credentials, CredentialsManagerException>
    ) {
        getCredentials(fragmentActivity, authenticationOptions, scope, minTtl, emptyMap(), callback)
    }

    /**
     * Tries to obtain the credentials from the Storage. The callback's [Callback.onSuccess] method will be called with the result.
     * If something unexpected happens, the [Callback.onFailure] method will be called with the error. Some devices are not compatible
     * at all with the cryptographic implementation and will have [CredentialsManagerException.isDeviceIncompatible] return true.
     *
     * If the user's lock screen authentication configuration matches the authentication level specified in the [authenticationOptions],
     * the user will be prompted to authenticate before accessing the credentials.
     *
     * @param fragmentActivity the activity that will be used to host the [androidx.biometric.BiometricPrompt]
     * @param authenticationOptions, an instance of [LocalAuthenticationOptions] used to configure authentication performed using [androidx.biometric.BiometricPrompt]
     * @param scope    the scope to request for the access token. If null is passed, the previous scope will be kept.
     * @param minTtl   the minimum time in seconds that the access token should last before expiration.
     * @param parameters additional parameters to send in the request to refresh expired credentials
     * @param callback the callback to receive the result in.
     */
    public fun getCredentials(
        fragmentActivity: FragmentActivity,
        authenticationOptions: LocalAuthenticationOptions,
        scope: String?,
        minTtl: Int,
        parameters: Map<String, String>,
        callback: Callback<Credentials, CredentialsManagerException>
    ) {
        getCredentials(
            fragmentActivity,
            authenticationOptions,
            scope,
            minTtl,
            parameters,
            false,
            callback
        )
    }

    /**
     * Tries to obtain the credentials from the Storage. The callback's [Callback.onSuccess] method will be called with the result.
     * If something unexpected happens, the [Callback.onFailure] method will be called with the error. Some devices are not compatible
     * at all with the cryptographic implementation and will have [CredentialsManagerException.isDeviceIncompatible] return true.
     *
     *
     * If the user's lock screen authentication configuration matches the authentication level specified in the [authenticationOptions],
     * the user will be prompted to authenticate before accessing the credentials.
     *
     * @param fragmentActivity the activity that will be used to host the [androidx.biometric.BiometricPrompt]
     * @param authenticationOptions, an instance of [LocalAuthenticationOptions] used to configure authentication performed using [androidx.biometric.BiometricPrompt]
     * @param scope    the scope to request for the access token. If null is passed, the previous scope will be kept.
     * @param minTtl   the minimum time in seconds that the access token should last before expiration.
     * @param parameters additional parameters to send in the request to refresh expired credentials
     * @param forceRefresh this will avoid returning the existing credentials and retrieves a new one even if valid credentials exist.
     * @param callback the callback to receive the result in.
     */
    public fun getCredentials(
        fragmentActivity: FragmentActivity,
        authenticationOptions: LocalAuthenticationOptions,
        scope: String?,
        minTtl: Int,
        parameters: Map<String, String>,
        forceRefresh: Boolean,
        callback: Callback<Credentials, CredentialsManagerException>
    ) {
        getCredentials(
            fragmentActivity,
            authenticationOptions,
            scope,
            minTtl,
            parameters,
            mapOf(),
            forceRefresh,
            callback
        )
    }

    /**
     * Tries to obtain the credentials from the Storage. The callback's [Callback.onSuccess] method will be called with the result.
     * If something unexpected happens, the [Callback.onFailure] method will be called with the error. Some devices are not compatible
     * at all with the cryptographic implementation and will have [CredentialsManagerException.isDeviceIncompatible] return true.
     *
     *
     * If the user's lock screen authentication configuration matches the authentication level specified in the [authenticationOptions],
     * the user will be prompted to authenticate before accessing the credentials.
     *
     * @param fragmentActivity the activity that will be used to host the [androidx.biometric.BiometricPrompt]
     * @param authenticationOptions, an instance of [LocalAuthenticationOptions] used to configure authentication performed using [androidx.biometric.BiometricPrompt]
     * @param scope    the scope to request for the access token. If null is passed, the previous scope will be kept.
     * @param minTtl   the minimum time in seconds that the access token should last before expiration.
     * @param parameters additional parameters to send in the request to refresh expired credentials.
     * @param forceRefresh this will avoid returning the existing credentials and retrieves a new one even if valid credentials exist.
     * @param callback the callback to receive the result in.
     */
    public fun getCredentials(
        fragmentActivity: FragmentActivity,
        authenticationOptions: LocalAuthenticationOptions,
        scope: String? = null,
        minTtl: Int = 0,
        parameters: Map<String, String> = emptyMap(),
        headers: Map<String, String> = emptyMap(),
        forceRefresh: Boolean = false,
        callback: Callback<Credentials, CredentialsManagerException>
    ) {

        val localAuthenticationManager = localAuthenticationManagerFactory.create(
            activity = fragmentActivity,
            authenticationOptions = authenticationOptions,
            resultCallback = localAuthenticationResultCallback(
                scope,
                minTtl,
                parameters,
                headers,
                forceRefresh,
                callback
            )
        )
        localAuthenticationManager.authenticate()
    }

    private val localAuthenticationResultCallback =
        { scope: String?, minTtl: Int, parameters: Map<String, String>, headers: Map<String, String>, forceRefresh: Boolean, callback: Callback<Credentials, CredentialsManagerException> ->
            object : Callback<Boolean, CredentialsManagerException> {
                override fun onSuccess(result: Boolean) {
                    getCredentials(
                        scope, minTtl, parameters, headers, forceRefresh,
                        callback
                    )
                }

                override fun onFailure(error: CredentialsManagerException) {
                    callback.onFailure(error)
                }
            }
        }

    /**
     * Delete the stored credentials
     */
    override fun clearCredentials() {
        storage.remove(KEY_CREDENTIALS)
        storage.remove(KEY_EXPIRES_AT)
        storage.remove(LEGACY_KEY_CACHE_EXPIRES_AT)
        storage.remove(KEY_CAN_REFRESH)
        Log.d(TAG, "Credentials were just removed from the storage")
    }

    /**
     * Returns whether this manager contains a valid non-expired pair of credentials.
     *
     * @return whether this manager contains a valid non-expired pair of credentials or not.
     */
    override fun hasValidCredentials(): Boolean {
        return hasValidCredentials(0)
    }

    /**
     * Returns whether this manager contains a valid non-expired pair of credentials.
     *
     * @param minTtl the minimum time in seconds that the access token should last before expiration.
     * @return whether this manager contains a valid non-expired pair of credentials or not.
     */
    override fun hasValidCredentials(minTtl: Long): Boolean {
        val encryptedEncoded = storage.retrieveString(KEY_CREDENTIALS)
        var expiresAt = storage.retrieveLong(KEY_EXPIRES_AT)
        if (expiresAt == null) {
            // Avoids logging out users when this value was not saved (migration scenario)
            expiresAt = 0L
        }
        val canRefresh = storage.retrieveBoolean(KEY_CAN_REFRESH)
        val emptyCredentials = TextUtils.isEmpty(encryptedEncoded)
        return !(emptyCredentials || willExpire(
            expiresAt,
            minTtl
        ) &&
                (canRefresh == null || !canRefresh))
    }

    @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    internal fun getCredentials(
        scope: String?,
        minTtl: Int,
        parameters: Map<String, String>,
        headers: Map<String, String>,
        forceRefresh: Boolean,
        callback: Callback<Credentials, CredentialsManagerException>
    ) {

        if (!hasValidCredentials(minTtl.toLong())) {
            callback.onFailure(CredentialsManagerException.NO_CREDENTIALS)
            return
        }
        serialExecutor.execute {
            val encryptedEncoded = storage.retrieveString(KEY_CREDENTIALS)
            if (encryptedEncoded.isNullOrBlank()) {
                callback.onFailure(CredentialsManagerException.NO_CREDENTIALS)
                return@execute
            }
            val encrypted = Base64.decode(encryptedEncoded, Base64.DEFAULT)
            val json: String
            try {
                json = String(crypto.decrypt(encrypted))
            } catch (e: IncompatibleDeviceException) {
                callback.onFailure(
                    CredentialsManagerException(
                        CredentialsManagerException.Code.INCOMPATIBLE_DEVICE,
                        e
                    )
                )
                return@execute
            } catch (e: CryptoException) {
                //If keys were invalidated, existing credentials will not be recoverable.
                clearCredentials()
                callback.onFailure(
                    CredentialsManagerException(
                        CredentialsManagerException.Code.CRYPTO_EXCEPTION,
                        e
                    )
                )
                return@execute
            }
            val bridgeCredentials = gson.fromJson(json, OptionalCredentials::class.java)
            /* OPTIONAL CREDENTIALS
             * This bridge is required to prevent users from being logged out when
             * migrating from Credentials with optional Access Token and ID token
             */
            val credentials = Credentials(
                bridgeCredentials.idToken.orEmpty(),
                bridgeCredentials.accessToken.orEmpty(),
                bridgeCredentials.type.orEmpty(),
                bridgeCredentials.refreshToken,
                bridgeCredentials.expiresAt ?: Date(),
                bridgeCredentials.scope
            )
            val expiresAt = credentials.expiresAt.time
            val hasEmptyCredentials =
                TextUtils.isEmpty(credentials.accessToken) && TextUtils.isEmpty(credentials.idToken)
            if (hasEmptyCredentials) {
                callback.onFailure(CredentialsManagerException.NO_CREDENTIALS)
                return@execute
            }
            val willAccessTokenExpire = willExpire(expiresAt, minTtl.toLong())
            val scopeChanged = hasScopeChanged(credentials.scope, scope)
            if (!forceRefresh && !willAccessTokenExpire && !scopeChanged) {
                callback.onSuccess(credentials)
                return@execute
            }
            if (credentials.refreshToken == null) {
                callback.onFailure(CredentialsManagerException.NO_REFRESH_TOKEN)
                return@execute
            }
            Log.d(TAG, "Credentials have expired. Renewing them now...")
            val request = authenticationClient.renewAuth(
                credentials.refreshToken
            )

            request.addParameters(parameters)
            if (scope != null) {
                request.addParameter("scope", scope)
            }

            for (header in headers) {
                request.addHeader(header.key, header.value)
            }

            val freshCredentials: Credentials
            try {
                val fresh = request.execute()
                val expiresAt = fresh.expiresAt.time
                val willAccessTokenExpire = willExpire(expiresAt, minTtl.toLong())
                if (willAccessTokenExpire) {
                    val tokenLifetime = (expiresAt - currentTimeInMillis - minTtl * 1000) / -1000
                    val wrongTtlException = CredentialsManagerException(
                        CredentialsManagerException.Code.LARGE_MIN_TTL,
                        String.format(
                            Locale.getDefault(),
                            "The lifetime of the renewed Access Token (%d) is less than the minTTL requested (%d). Increase the 'Token Expiration' setting of your Auth0 API in the dashboard, or request a lower minTTL.",
                            tokenLifetime,
                            minTtl
                        )
                    )
                    callback.onFailure(wrongTtlException)
                    return@execute
                }

                //non-empty refresh token for refresh token rotation scenarios
                val updatedRefreshToken =
                    if (TextUtils.isEmpty(fresh.refreshToken)) credentials.refreshToken else fresh.refreshToken
                freshCredentials = Credentials(
                    fresh.idToken,
                    fresh.accessToken,
                    fresh.type,
                    updatedRefreshToken,
                    fresh.expiresAt,
                    fresh.scope
                )
            } catch (error: Auth0Exception) {
                callback.onFailure(
                    CredentialsManagerException(
                        CredentialsManagerException.Code.RENEW_FAILED,
                        error
                    )
                )
                return@execute
            }

            try {
                saveCredentials(freshCredentials)
                callback.onSuccess(freshCredentials)
            } catch (error: CredentialsManagerException) {
                val exception = CredentialsManagerException(
                    CredentialsManagerException.Code.STORE_FAILED, error
                )
                if (error.cause is IncompatibleDeviceException || error.cause is CryptoException) {
                    exception.refreshedCredentials = freshCredentials
                }
                callback.onFailure(exception)
            }
        }
    }

    internal companion object {
        private val TAG = SecureCredentialsManager::class.java.simpleName
        private const val KEY_CREDENTIALS = "com.auth0.credentials"
        private const val KEY_EXPIRES_AT = "com.auth0.credentials_access_token_expires_at"

        // This is no longer used as we get the credentials expiry from the access token only,
        // but we still store it so users can rollback to versions where it is required.
        private const val LEGACY_KEY_CACHE_EXPIRES_AT = "com.auth0.credentials_expires_at"
        private const val KEY_CAN_REFRESH = "com.auth0.credentials_can_refresh"
        private const val KEY_ALIAS = "com.auth0.key"
    }
}