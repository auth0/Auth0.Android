package com.auth0.android.authentication.storage

import android.content.Context
import android.text.TextUtils
import android.util.Base64
import android.util.Log
import androidx.annotation.VisibleForTesting
import androidx.fragment.app.FragmentActivity
import com.auth0.android.Auth0
import com.auth0.android.authentication.AuthenticationAPIClient
import com.auth0.android.authentication.AuthenticationException
import com.auth0.android.callback.Callback
import com.auth0.android.request.internal.GsonProvider
import com.auth0.android.result.APICredentials
import com.auth0.android.result.Credentials
import com.auth0.android.result.OptionalCredentials
import com.auth0.android.result.SSOCredentials
import com.auth0.android.result.UserProfile
import com.auth0.android.result.toAPICredentials
import com.google.gson.Gson
import kotlinx.coroutines.suspendCancellableCoroutine
import java.lang.ref.WeakReference
import java.util.Date
import java.util.Locale
import java.util.concurrent.Executor
import java.util.concurrent.atomic.AtomicLong
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
    private val fragmentActivity: WeakReference<FragmentActivity>? = null,
    private val localAuthenticationOptions: LocalAuthenticationOptions? = null,
    private val localAuthenticationManagerFactory: LocalAuthenticationManagerFactory? = null,
) : BaseCredentialsManager(apiClient, storage, jwtDecoder) {
    private val gson: Gson = GsonProvider.gson

    // Biometric session management
    private val lastBiometricAuthTime = AtomicLong(NO_SESSION)

    /**
     * Creates a new SecureCredentialsManager to handle Credentials
     *
     * @param context   a valid context
     * @param auth0     the Auth0 account information to use
     * @param storage   the storage implementation to use
     */
    public constructor(
        context: Context,
        auth0: Auth0,
        storage: Storage,
    ) : this(
        AuthenticationAPIClient(auth0),
        context,
        auth0,
        storage
    )

    /**
     * Creates a new SecureCredentialsManager to handle Credentials with a custom AuthenticationAPIClient instance.
     * Use this constructor when you need to configure the API client with advanced features like DPoP.
     *
     * Example usage:
     * ```
     * val auth0 = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN")
     * val apiClient = AuthenticationAPIClient(auth0).useDPoP(context)
     * val manager = SecureCredentialsManager(apiClient, context, auth0, storage)
     * ```
     *
     * @param apiClient a configured AuthenticationAPIClient instance
     * @param context   a valid context
     * @param auth0     the Auth0 account information to use
     * @param storage   the storage implementation to use
     */
    public constructor(
        apiClient: AuthenticationAPIClient,
        context: Context,
        auth0: Auth0,
        storage: Storage
    ) : this(
        apiClient,
        storage,
        CryptoUtil(context, storage, KEY_ALIAS),
        JWTDecoder(),
        auth0.executor
    )


    /**
     * Creates a new SecureCredentialsManager to handle Credentials with biometrics Authentication
     *
     * @param context   a valid context
     * @param auth0     the Auth0 account information to use
     * @param storage   the storage implementation to use
     * @param fragmentActivity the FragmentActivity to use for the biometric authentication
     * @param localAuthenticationOptions the options of type [LocalAuthenticationOptions] to use for the biometric authentication
     */
    public constructor(
        context: Context,
        auth0: Auth0,
        storage: Storage,
        fragmentActivity: FragmentActivity,
        localAuthenticationOptions: LocalAuthenticationOptions
    ) : this(
        AuthenticationAPIClient(auth0),
        context,
        auth0,
        storage,
        fragmentActivity,
        localAuthenticationOptions
    )


    /**
     * Creates a new SecureCredentialsManager to handle Credentials with biometrics Authentication
     * and a custom AuthenticationAPIClient instance.
     * Use this constructor when you need to configure the API client with advanced features like DPoP
     * along with biometric authentication.
     *
     * Example usage:
     * ```
     * val auth0 = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN")
     * val apiClient = AuthenticationAPIClient(auth0).useDPoP(context)
     * val manager = SecureCredentialsManager(
     *     apiClient,
     *     context,
     *     auth0,
     *     storage,
     *     fragmentActivity,
     *     localAuthenticationOptions
     * )
     * ```
     *
     * @param apiClient a configured AuthenticationAPIClient instance
     * @param context   a valid context
     * @param auth0     the Auth0 account information to use
     * @param storage   the storage implementation to use
     * @param fragmentActivity the FragmentActivity to use for the biometric authentication
     * @param localAuthenticationOptions the options of type [LocalAuthenticationOptions] to use for the biometric authentication
     */
    public constructor(
        apiClient: AuthenticationAPIClient,
        context: Context,
        auth0: Auth0,
        storage: Storage,
        fragmentActivity: FragmentActivity,
        localAuthenticationOptions: LocalAuthenticationOptions
    ) : this(
        apiClient,
        storage,
        CryptoUtil(context, storage, KEY_ALIAS),
        JWTDecoder(),
        auth0.executor,
        WeakReference(fragmentActivity),
        localAuthenticationOptions,
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
                CredentialsManagerException.Code.INCOMPATIBLE_DEVICE, e
            )
        } catch (e: CryptoException) {/*
             * If the keys were invalidated in the call above a good new pair is going to be available
             * to use on the next call. We clear any existing credentials so #hasValidCredentials returns
             * a true value. Retrying this operation will succeed.
             */
            clearCredentials()
            throw CredentialsManagerException(
                CredentialsManagerException.Code.CRYPTO_EXCEPTION, e
            )
        }
    }

    /**
     * Stores the given [APICredentials] in the storage for the given audience.
     * @param apiCredentials the API Credentials to be stored
     * @param audience the audience for which the credentials are stored
     */
    override fun saveApiCredentials(apiCredentials: APICredentials, audience: String) {
        val json = gson.toJson(apiCredentials)
        try {
            val encrypted = crypto.encrypt(json.toByteArray())
            val encryptedEncoded = Base64.encodeToString(encrypted, Base64.DEFAULT)
            storage.store(audience, encryptedEncoded)
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
            clearApiCredentials(audience)
            throw CredentialsManagerException(
                CredentialsManagerException.Code.CRYPTO_EXCEPTION,
                e
            )
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
            val existingCredentials: Credentials = try {
                getExistingCredentials()
            } catch (exception: CredentialsManagerException) {
                Log.e(TAG, "Error while fetching existing credentials", exception)
                callback.onFailure(exception)
                return@execute
            }
            if (existingCredentials.refreshToken.isNullOrEmpty()) {
                callback.onFailure(CredentialsManagerException.NO_REFRESH_TOKEN)
                return@execute
            }

            val request =
                authenticationClient.ssoExchange(existingCredentials.refreshToken)
            try {
                if (parameters.isNotEmpty()) {
                    request.addParameters(parameters)
                }
                val sessionCredentials = request.execute()
                saveSsoCredentials(sessionCredentials)
                callback.onSuccess(sessionCredentials)
            } catch (error: AuthenticationException) {
                val exception = when {
                    error.isNetworkError -> CredentialsManagerException.Code.NO_NETWORK
                    else -> CredentialsManagerException.Code.SSO_EXCHANGE_FAILED
                }
                callback.onFailure(
                    CredentialsManagerException(
                        exception, error
                    )
                )
            } catch (error: CredentialsManagerException) {
                val exception = CredentialsManagerException(
                    CredentialsManagerException.Code.STORE_FAILED, error
                )
                callback.onFailure(exception)
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

    public override val userProfile: UserProfile?
        get() {
            val credentials: Credentials? = getExistingCredentials()
            // Handle null credentials gracefully
            if (credentials == null) {
                return null
            }
            return credentials.user
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
     * Tries to obtain the credentials from the Storage. The method will return [Credentials].
     * If something unexpected happens, then [CredentialsManagerException] exception will be thrown. Some devices are not compatible
     * at all with the cryptographic implementation and will have [CredentialsManagerException.isDeviceIncompatible] return true.
     * This is a Coroutine that is exposed only for Kotlin.
     *
     * If the user's lock screen authentication configuration matches the authentication level specified in the [authenticationOptions],
     * the user will be prompted to authenticate before accessing the credentials.
     *
     */
    @JvmSynthetic
    @Throws(CredentialsManagerException::class)
    override suspend fun awaitCredentials(): Credentials {
        return awaitCredentials(null, 0)
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
     * @param scope    the scope to request for the access token. If null is passed, the previous scope will be kept.
     * @param minTtl   the minimum time in seconds that the access token should last before expiration.
     */
    @JvmSynthetic
    @Throws(CredentialsManagerException::class)
    override suspend fun awaitCredentials(
        scope: String?, minTtl: Int
    ): Credentials {
        return awaitCredentials(scope, minTtl, emptyMap())
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
     * @param scope    the scope to request for the access token. If null is passed, the previous scope will be kept.
     * @param minTtl   the minimum time in seconds that the access token should last before expiration.
     * @param parameters additional parameters to send in the request to refresh expired credentials
     */
    @JvmSynthetic
    @Throws(CredentialsManagerException::class)
    override suspend fun awaitCredentials(
        scope: String?, minTtl: Int, parameters: Map<String, String>
    ): Credentials {
        return awaitCredentials(
            scope, minTtl, parameters, false
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
        forceRefresh: Boolean,
    ): Credentials {
        return awaitCredentials(
            scope, minTtl, parameters, mapOf(), forceRefresh
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
        forceRefresh: Boolean,
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
                audience,
                scope,
                minTtl,
                parameters,
                headers,
                object : Callback<APICredentials, CredentialsManagerException> {
                    override fun onSuccess(result: APICredentials) {
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
     * @param callback the callback to receive the result in.
     */
    override fun getCredentials(
        callback: Callback<Credentials, CredentialsManagerException>
    ) {
        getCredentials(null, 0, callback)
    }

    /**
     * Tries to obtain the credentials from the Storage. The callback's [Callback.onSuccess] method will be called with the result.
     * If something unexpected happens, the [Callback.onFailure] method will be called with the error. Some devices are not compatible
     * at all with the cryptographic implementation and will have [CredentialsManagerException.isDeviceIncompatible] return true.
     *
     * If the user's lock screen authentication configuration matches the authentication level specified in the [authenticationOptions],
     * the user will be prompted to authenticate before accessing the credentials.
     *
     * @param scope    the scope to request for the access token. If null is passed, the previous scope will be kept.
     * @param minTtl   the minimum time in seconds that the access token should last before expiration.
     * @param callback the callback to receive the result in.
     */
    override fun getCredentials(
        scope: String?, minTtl: Int, callback: Callback<Credentials, CredentialsManagerException>
    ) {
        getCredentials(scope, minTtl, emptyMap(), callback)
    }

    /**
     * Tries to obtain the credentials from the Storage. The callback's [Callback.onSuccess] method will be called with the result.
     * If something unexpected happens, the [Callback.onFailure] method will be called with the error. Some devices are not compatible
     * at all with the cryptographic implementation and will have [CredentialsManagerException.isDeviceIncompatible] return true.
     *
     * If the user's lock screen authentication configuration matches the authentication level specified in the [authenticationOptions],
     * the user will be prompted to authenticate before accessing the credentials.
     *
     * @param scope    the scope to request for the access token. If null is passed, the previous scope will be kept.
     * @param minTtl   the minimum time in seconds that the access token should last before expiration.
     * @param parameters additional parameters to send in the request to refresh expired credentials
     * @param callback the callback to receive the result in.
     */
    override fun getCredentials(
        scope: String?,
        minTtl: Int,
        parameters: Map<String, String>,
        callback: Callback<Credentials, CredentialsManagerException>
    ) {
        getCredentials(
            scope, minTtl, parameters, false, callback
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
     * @param scope    the scope to request for the access token. If null is passed, the previous scope will be kept.
     * @param minTtl   the minimum time in seconds that the access token should last before expiration.
     * @param parameters additional parameters to send in the request to refresh expired credentials
     * @param forceRefresh this will avoid returning the existing credentials and retrieves a new one even if valid credentials exist.
     * @param callback the callback to receive the result in.
     */
    override fun getCredentials(
        scope: String?,
        minTtl: Int,
        parameters: Map<String, String>,
        forceRefresh: Boolean,
        callback: Callback<Credentials, CredentialsManagerException>
    ) {
        getCredentials(
            scope, minTtl, parameters, mapOf(), forceRefresh, callback
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
     * @param scope    the scope to request for the access token. If null is passed, the previous scope will be kept.
     * @param minTtl   the minimum time in seconds that the access token should last before expiration.
     * @param parameters additional parameters to send in the request to refresh expired credentials.
     * @param forceRefresh this will avoid returning the existing credentials and retrieves a new one even if valid credentials exist.
     * @param callback the callback to receive the result in.
     */
    override fun getCredentials(
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

        if (fragmentActivity != null && localAuthenticationOptions != null && localAuthenticationManagerFactory != null) {
            // Check if biometric session is valid based on policy
            if (isBiometricSessionValid()) {
                // Session is valid, bypass biometric prompt
                continueGetCredentials(scope, minTtl, parameters, headers, forceRefresh, callback)
                return
            }

            fragmentActivity.get()?.let { fragmentActivity ->
                startBiometricAuthentication(
                    fragmentActivity,
                    biometricAuthenticationCredentialsCallback(
                        scope, minTtl, parameters, headers, forceRefresh, callback
                    )
                )
            } ?: run {
                callback.onFailure(CredentialsManagerException.BIOMETRIC_ERROR_NO_ACTIVITY)
            }
            return
        }

        continueGetCredentials(scope, minTtl, parameters, headers, forceRefresh, callback)
    }


    /**
     * Retrieves API credentials from storage and automatically renews them using the refresh token if the access
     * token is expired. Otherwise, the retrieved API credentials will be returned via the success callback as they are still valid.
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
    override fun getApiCredentials(
        audience: String,
        scope: String?,
        minTtl: Int,
        parameters: Map<String, String>,
        headers: Map<String, String>,
        callback: Callback<APICredentials, CredentialsManagerException>
    ) {

        if (fragmentActivity != null && localAuthenticationOptions != null && localAuthenticationManagerFactory != null) {

            if (isBiometricSessionValid()) {
                continueGetApiCredentials(audience, scope, minTtl, parameters, headers, callback)
                return
            }

            fragmentActivity.get()?.let { fragmentActivity ->
                startBiometricAuthentication(
                    fragmentActivity,
                    biometricAuthenticationApiCredentialsCallback(
                        audience, scope, minTtl, parameters, headers, callback
                    )
                )
            } ?: run {
                callback.onFailure(CredentialsManagerException.BIOMETRIC_ERROR_NO_ACTIVITY)
            }
            return
        }

        continueGetApiCredentials(audience, scope, minTtl, parameters, headers, callback)
    }


    /**
     * Delete the stored credentials
     */
    override fun clearCredentials() {
        storage.remove(KEY_CREDENTIALS)
        storage.remove(KEY_EXPIRES_AT)
        storage.remove(LEGACY_KEY_CACHE_EXPIRES_AT)
        storage.remove(KEY_CAN_REFRESH)
        clearBiometricSession()
        Log.d(TAG, "Credentials were just removed from the storage")
    }

    /**
     * Removes the credentials for the given audience from the storage if present.
     */
    override fun clearApiCredentials(audience: String) {
        storage.remove(audience)
        Log.d(TAG, "API Credentials for $audience were just removed from the storage")
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
            expiresAt, minTtl
        ) && (canRefresh == null || !canRefresh))
    }

    @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    internal fun continueGetCredentials(
        scope: String?,
        minTtl: Int,
        parameters: Map<String, String>,
        headers: Map<String, String>,
        forceRefresh: Boolean,
        callback: Callback<Credentials, CredentialsManagerException>
    ) {
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
                        CredentialsManagerException.Code.INCOMPATIBLE_DEVICE, e
                    )
                )
                return@execute
            } catch (e: CryptoException) {
                //If keys were invalidated, existing credentials will not be recoverable.
                clearCredentials()
                callback.onFailure(
                    CredentialsManagerException(
                        CredentialsManagerException.Code.CRYPTO_EXCEPTION, e
                    )
                )
                return@execute
            }
            val bridgeCredentials = gson.fromJson(json, OptionalCredentials::class.java)/* OPTIONAL CREDENTIALS
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
                return@execute
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


    @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    internal fun continueGetApiCredentials(
        audience: String,
        scope: String?,
        minTtl: Int,
        parameters: Map<String, String>,
        headers: Map<String, String>,
        callback: Callback<APICredentials, CredentialsManagerException>
    ) {
        serialExecutor.execute {
            val encryptedEncodedJson = storage.retrieveString(audience)
            //Check if existing api credentials are present and valid

            encryptedEncodedJson?.let { encryptedEncoded ->
                val encrypted = Base64.decode(encryptedEncoded, Base64.DEFAULT)
                val json: String = try {
                    String(crypto.decrypt(encrypted))
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
                    clearApiCredentials(audience)
                    callback.onFailure(
                        CredentialsManagerException(
                            CredentialsManagerException.Code.CRYPTO_EXCEPTION,
                            e
                        )
                    )
                    return@execute
                }

                val apiCredentials = gson.fromJson(json, APICredentials::class.java)

                val expiresAt = apiCredentials.expiresAt.time
                val willAccessTokenExpire = willExpire(expiresAt, minTtl.toLong())
                val scopeChanged = hasScopeChanged(apiCredentials.scope, scope)
                val hasExpired = hasExpired(apiCredentials.expiresAt.time)
                if (!hasExpired && !willAccessTokenExpire && !scopeChanged) {
                    callback.onSuccess(apiCredentials)
                    return@execute
                }
            }

            //Check if refresh token exists or not
            val existingCredentials: Credentials = try {
                getExistingCredentials()
            } catch (exception: CredentialsManagerException) {
                callback.onFailure(exception)
                return@execute
            }
            val refreshToken = existingCredentials.refreshToken
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
                saveCredentials(
                    existingCredentials.copy(
                        refreshToken = updatedRefreshToken,
                        idToken = newCredentials.idToken
                    )
                )
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

    @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    internal fun clearFragmentActivity() {
        fragmentActivity!!.clear()
    }

    /**
     * Helper method to fetch existing credentials from the storage.
     * This method is not thread safe
     */
    @JvmSynthetic
    @Throws(CredentialsManagerException::class)
    private fun getExistingCredentials(): Credentials {
        val encryptedEncoded = storage.retrieveString(KEY_CREDENTIALS)
        if (encryptedEncoded.isNullOrBlank()) {
            throw CredentialsManagerException.NO_CREDENTIALS
        }
        val encrypted = Base64.decode(encryptedEncoded, Base64.DEFAULT)
        val json: String = try {
            String(crypto.decrypt(encrypted))
        } catch (e: IncompatibleDeviceException) {
            throw CredentialsManagerException(
                CredentialsManagerException.Code.INCOMPATIBLE_DEVICE, e
            )
        } catch (e: CryptoException) {
            clearCredentials()
            throw CredentialsManagerException(
                CredentialsManagerException.Code.CRYPTO_EXCEPTION, e
            )
        }
        val bridgeCredentials = gson.fromJson(json, OptionalCredentials::class.java)
        val existingCredentials = Credentials(
            bridgeCredentials.idToken.orEmpty(),
            bridgeCredentials.accessToken.orEmpty(),
            bridgeCredentials.type.orEmpty(),
            bridgeCredentials.refreshToken,
            bridgeCredentials.expiresAt ?: Date(),
            bridgeCredentials.scope
        )
        return existingCredentials
    }

    /**
     * Helper method to start the biometric authentication for accessing the credentials
     */
    private fun startBiometricAuthentication(
        fragmentActivity: FragmentActivity,
        biometricResultCallback: Callback<Boolean, CredentialsManagerException>
    ) {
        val localAuthenticationManager = localAuthenticationManagerFactory?.create(
            activity = fragmentActivity,
            authenticationOptions = localAuthenticationOptions!!,
            resultCallback = biometricResultCallback,
        )
        localAuthenticationManager?.authenticate()
    }

    /**
     * Biometric authentication callback for authentication credentials
     */
    private val biometricAuthenticationCredentialsCallback =
        { scope: String?, minTtl: Int, parameters: Map<String, String>, headers: Map<String, String>,
          forceRefresh: Boolean, callback: Callback<Credentials, CredentialsManagerException> ->
            object : Callback<Boolean, CredentialsManagerException> {
                override fun onSuccess(result: Boolean) {
                    updateBiometricSession()
                    continueGetCredentials(
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
     * Biometric authentication callback for API credentials
     */
    private val biometricAuthenticationApiCredentialsCallback =
        { audience: String, scope: String?, minTtl: Int, parameters: Map<String, String>, headers: Map<String, String>,
          callback: Callback<APICredentials, CredentialsManagerException> ->
            object : Callback<Boolean, CredentialsManagerException> {
                override fun onSuccess(result: Boolean) {
                    updateBiometricSession()
                    continueGetApiCredentials(
                        audience, scope, minTtl, parameters, headers,
                        callback
                    )
                }

                override fun onFailure(error: CredentialsManagerException) {
                    callback.onFailure(error)
                }
            }
        }

    /**
     * Helper method to stores the given [ssoCredentials] refresh token in the storage.
     * Method will silently return if the passed credentials have no refresh token.
     *
     * @param ssoCredentials the credentials to save in the storage.
     */
    @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    internal fun saveSsoCredentials(ssoCredentials: SSOCredentials) {
        val existingCredentials: Credentials = try {
            getExistingCredentials()
        } catch (exception: CredentialsManagerException) {
            Log.e(TAG, "Error while fetching existing credentials", exception)
            return
        }
        val newCredentials = existingCredentials.copy(
            refreshToken = ssoCredentials.refreshToken
                ?: existingCredentials.refreshToken, idToken = ssoCredentials.idToken
        )
        saveCredentials(newCredentials)
    }

    /**
     * Checks if the current biometric session is valid based on the configured policy.
     */
    @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    internal fun isBiometricSessionValid(): Boolean {
        val lastAuth = lastBiometricAuthTime.get()
        if (lastAuth == NO_SESSION) return false // No session exists

        val policy = localAuthenticationOptions?.policy ?: BiometricPolicy.Always
        return when (policy) {
            is BiometricPolicy.Session,
            is BiometricPolicy.AppLifecycle -> {
                val timeoutMillis = when (policy) {
                    is BiometricPolicy.Session -> policy.timeoutInSeconds
                    is BiometricPolicy.AppLifecycle -> policy.timeoutInSeconds
                    else -> return false
                } * 1000L
                System.currentTimeMillis() - lastAuth < timeoutMillis
            }

            is BiometricPolicy.Always -> false
        }
    }

    /**
     * Updates the biometric session timestamp to the current time.
     */
    private fun updateBiometricSession() {
        lastBiometricAuthTime.set(System.currentTimeMillis())
    }

    /**
     * Clears the in-memory biometric session timestamp. Can be called from any thread.
     */
    public fun clearBiometricSession() {
        lastBiometricAuthTime.set(NO_SESSION)
    }

    internal companion object {
        private val TAG = SecureCredentialsManager::class.java.simpleName

        @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
        internal const val KEY_CREDENTIALS = "com.auth0.credentials"

        @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
        internal const val KEY_EXPIRES_AT = "com.auth0.credentials_access_token_expires_at"

        // This is no longer used as we get the credentials expiry from the access token only,
        // but we still store it so users can rollback to versions where it is required.
        @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
        internal const val LEGACY_KEY_CACHE_EXPIRES_AT = "com.auth0.credentials_expires_at"

        @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
        internal const val KEY_CAN_REFRESH = "com.auth0.credentials_can_refresh"

        @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
        internal const val KEY_ALIAS = "com.auth0.key"

        // Using NO_SESSION to represent "no session" (uninitialized state)
        private const val NO_SESSION = -1L
    }
}