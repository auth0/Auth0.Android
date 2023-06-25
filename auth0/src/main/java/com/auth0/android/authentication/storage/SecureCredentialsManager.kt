package com.auth0.android.authentication.storage

import android.app.Activity
import android.app.KeyguardManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.text.TextUtils
import android.util.Base64
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.IntRange
import androidx.annotation.VisibleForTesting
import androidx.lifecycle.Lifecycle
import com.auth0.android.Auth0Exception
import com.auth0.android.authentication.AuthenticationAPIClient
import com.auth0.android.authentication.AuthenticationException
import com.auth0.android.callback.AuthenticationCallback
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
    private val serialExecutor: Executor
) : BaseCredentialsManager(apiClient, storage, jwtDecoder) {
    private val gson: Gson = GsonProvider.gson

    //Changeable by the user
    private var authenticateBeforeDecrypt: Boolean
    private var authenticationRequestCode = -1
    private var activity: Activity? = null
    private var activityResultContract: ActivityResultLauncher<Intent>? = null

    //State for retrying operations
    private var decryptCallback: Callback<Credentials, CredentialsManagerException>? = null
    private var authIntent: Intent? = null
    private var scope: String? = null
    private var minTtl = 0
    private var forceRefresh = false

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
        Executors.newSingleThreadExecutor()
    )

    /**
     * Require the user to authenticate using the configured LockScreen before accessing the credentials.
     * This method MUST be called in [Activity.onCreate]. This feature is disabled by default and will
     * only work if the user has configured a secure LockScreen (PIN, Pattern, Password or Fingerprint).
     *
     * If the activity passed as first argument is a subclass of ComponentActivity, the authentication result
     * will be handled internally using "Activity Results API" which should be called from the main thread.
     * Otherwise, your activity must override the [Activity.onActivityResult] method
     * and call [SecureCredentialsManager.checkAuthenticationResult] with the received parameters.
     *
     * @param activity    a valid activity context. Will be used in the authentication request to launch a LockScreen intent.
     * @param requestCode the request code to use in the authentication request. Must be a value between 1 and 255.
     * @param title       the text to use as title in the authentication screen. Passing null will result in using the OS's default value.
     * @param description the text to use as description in the authentication screen. On some Android versions it might not be shown. Passing null will result in using the OS's default value.
     * @return whether this device supports requiring authentication or not. This result can be ignored safely.
     */
    public fun requireAuthentication(
        activity: Activity,
        @IntRange(from = 1, to = 255) requestCode: Int,
        title: String?,
        description: String?
    ): Boolean {
        require(!(requestCode < 1 || requestCode > 255)) { "Request code must be a value between 1 and 255." }
        val kManager = activity.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        authIntent = kManager.createConfirmDeviceCredentialIntent(title, description)
        authenticateBeforeDecrypt =
            ((Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && kManager.isDeviceSecure || kManager.isKeyguardSecure)
                    && authIntent != null)
        if (authenticateBeforeDecrypt) {
            authenticationRequestCode = requestCode

            /*
             *  https://developer.android.com/training/basics/intents/result#register
             *  Docs say it's safe to call "registerForActivityResult" BEFORE the activity is created. In practice,
             *  when that's not the case, a RuntimeException is thrown. The lifecycle state check below is meant to
             *  prevent that exception while still falling back to the old "startActivityForResult" flow. That's in
             *  case devs are invoking this method in places other than the Activity's "OnCreate" method.
             */
            if (activity is ComponentActivity && !activity.lifecycle.currentState.isAtLeast(
                    Lifecycle.State.STARTED
                )
            ) {
                activityResultContract =
                    activity.registerForActivityResult(
                        ActivityResultContracts.StartActivityForResult(),
                        activity.activityResultRegistry
                    ) {
                        checkAuthenticationResult(authenticationRequestCode, it.resultCode)
                    }
            } else {
                this.activity = activity
            }
        }
        return authenticateBeforeDecrypt
    }

    /**
     * Checks the result after showing the LockScreen to the user.
     * Must be called from the [Activity.onActivityResult] method with the received parameters.
     * Called internally when your activity is a subclass of ComponentActivity (using Activity Results API).
     * It's safe to call this method even if [SecureCredentialsManager.requireAuthentication] was unsuccessful.
     *
     * @param requestCode the request code received in the onActivityResult call.
     * @param resultCode  the result code received in the onActivityResult call.
     * @return true if the result was handled, false otherwise.
     */
    public fun checkAuthenticationResult(requestCode: Int, resultCode: Int): Boolean {
        if (requestCode != authenticationRequestCode || decryptCallback == null) {
            return false
        }
        if (resultCode == Activity.RESULT_OK) {
            continueGetCredentials(scope, minTtl, emptyMap(), forceRefresh, decryptCallback!!)
        } else {
            decryptCallback!!.onFailure(CredentialsManagerException("The user didn't pass the authentication challenge."))
            decryptCallback = null
        }
        return true
    }

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
            throw CredentialsManagerException("Credentials must have a valid date of expiration and a valid access_token or id_token value.")
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
                String.format(
                    "This device is not compatible with the %s class.",
                    SecureCredentialsManager::class.java.simpleName
                ), e
            )
        } catch (e: CryptoException) {
            /*
             * If the keys were invalidated in the call above a good new pair is going to be available
             * to use on the next call. We clear any existing credentials so #hasValidCredentials returns
             * a true value. Retrying this operation will succeed.
             */
            clearCredentials()
            throw CredentialsManagerException(
                "A change on the Lock Screen security settings have deemed the encryption keys invalid and have been recreated. Please try saving the credentials again.",
                e
            )
        }
    }

    /**
     * Tries to obtain the credentials from the Storage. The method will return [Credentials].
     * If something unexpected happens, then [CredentialsManagerException] exception will be thrown. Some devices are not compatible
     * at all with the cryptographic implementation and will have [CredentialsManagerException.isDeviceIncompatible] return true.
     * This is a Coroutine that is exposed only for Kotlin.
     *
     * If a LockScreen is setup and [SecureCredentialsManager.requireAuthentication] was called, the user will be asked to authenticate before accessing
     * the credentials. Your activity must override the [Activity.onActivityResult] method and call
     * [SecureCredentialsManager.checkAuthenticationResult] with the received values.
     */
    @JvmSynthetic
    @Throws(CredentialsManagerException::class)
    public suspend fun awaitCredentials(): Credentials {
        return awaitCredentials(null, 0)
    }

    /**
     * Tries to obtain the credentials from the Storage. The method will return [Credentials].
     * If something unexpected happens, then [CredentialsManagerException] exception will be thrown. Some devices are not compatible
     * at all with the cryptographic implementation and will have [CredentialsManagerException.isDeviceIncompatible] return true.
     * This is a Coroutine that is exposed only for Kotlin.
     *
     * If a LockScreen is setup and [SecureCredentialsManager.requireAuthentication] was called, the user will be asked to authenticate before accessing
     * the credentials. Your activity must override the [Activity.onActivityResult] method and call
     * [SecureCredentialsManager.checkAuthenticationResult] with the received values.
     *
     * @param scope    the scope to request for the access token. If null is passed, the previous scope will be kept.
     * @param minTtl   the minimum time in seconds that the access token should last before expiration.
     */
    @JvmSynthetic
    @Throws(CredentialsManagerException::class)
    public suspend fun awaitCredentials(scope: String?, minTtl: Int): Credentials {
        return awaitCredentials(scope, minTtl, emptyMap())
    }

    /**
     * Tries to obtain the credentials from the Storage. The method will return [Credentials].
     * If something unexpected happens, then [CredentialsManagerException] exception will be thrown. Some devices are not compatible
     * at all with the cryptographic implementation and will have [CredentialsManagerException.isDeviceIncompatible] return true.
     * This is a Coroutine that is exposed only for Kotlin.
     *
     * If a LockScreen is setup and [SecureCredentialsManager.requireAuthentication] was called, the user will be asked to authenticate before accessing
     * the credentials. Your activity must override the [Activity.onActivityResult] method and call
     * [SecureCredentialsManager.checkAuthenticationResult] with the received values.
     *
     * @param scope    the scope to request for the access token. If null is passed, the previous scope will be kept.
     * @param minTtl   the minimum time in seconds that the access token should last before expiration.
     * @param parameters additional parameters to send in the request to refresh expired credentials
     */
    @JvmSynthetic
    @Throws(CredentialsManagerException::class)
    public suspend fun awaitCredentials(
        scope: String?,
        minTtl: Int,
        parameters: Map<String, String>
    ): Credentials {
        return awaitCredentials(scope, minTtl, parameters, false)
    }

    /**
     * Tries to obtain the credentials from the Storage. The method will return [Credentials].
     * If something unexpected happens, then [CredentialsManagerException] exception will be thrown. Some devices are not compatible
     * at all with the cryptographic implementation and will have [CredentialsManagerException.isDeviceIncompatible] return true.
     * This is a Coroutine that is exposed only for Kotlin.
     *
     * If a LockScreen is setup and [SecureCredentialsManager.requireAuthentication] was called, the user will be asked to authenticate before accessing
     * the credentials. Your activity must override the [Activity.onActivityResult] method and call
     * [SecureCredentialsManager.checkAuthenticationResult] with the received values.
     *
     * @param scope    the scope to request for the access token. If null is passed, the previous scope will be kept.
     * @param minTtl   the minimum time in seconds that the access token should last before expiration.
     * @param parameters additional parameters to send in the request to refresh expired credentials.
     * @param forceRefresh this will avoid returning the existing credentials and retrieves a new one even if valid credentials exist.
     */
    @JvmSynthetic
    @Throws(CredentialsManagerException::class)
    public suspend fun awaitCredentials(
        scope: String?,
        minTtl: Int,
        parameters: Map<String, String>,
        forceRefresh: Boolean,
    ): Credentials {
        return suspendCancellableCoroutine { continuation ->
            getCredentials(
                scope,
                minTtl,
                parameters,
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
     *
     * If a LockScreen is setup and [SecureCredentialsManager.requireAuthentication] was called, the user will be asked to authenticate before accessing
     * the credentials. Your activity must override the [Activity.onActivityResult] method and call
     * [checkAuthenticationResult] with the received values.
     *
     * @param callback the callback to receive the result in.
     */
    override fun getCredentials(callback: Callback<Credentials, CredentialsManagerException>) {
        getCredentials(null, 0, callback)
    }

    /**
     * Tries to obtain the credentials from the Storage. The callback's [Callback.onSuccess] method will be called with the result.
     * If something unexpected happens, the [Callback.onFailure] method will be called with the error. Some devices are not compatible
     * at all with the cryptographic implementation and will have [CredentialsManagerException.isDeviceIncompatible] return true.
     *
     *
     * If a LockScreen is setup and [SecureCredentialsManager.requireAuthentication] was called, the user will be asked to authenticate before accessing
     * the credentials. Your activity must override the [Activity.onActivityResult] method and call
     * [SecureCredentialsManager.checkAuthenticationResult] with the received values.
     *
     * @param scope    the scope to request for the access token. If null is passed, the previous scope will be kept.
     * @param minTtl   the minimum time in seconds that the access token should last before expiration.
     * @param callback the callback to receive the result in.
     */
    override fun getCredentials(
        scope: String?,
        minTtl: Int,
        callback: Callback<Credentials, CredentialsManagerException>
    ) {
        getCredentials(scope, minTtl, emptyMap(), callback)
    }

    /**
     * Tries to obtain the credentials from the Storage. The callback's [Callback.onSuccess] method will be called with the result.
     * If something unexpected happens, the [Callback.onFailure] method will be called with the error. Some devices are not compatible
     * at all with the cryptographic implementation and will have [CredentialsManagerException.isDeviceIncompatible] return true.
     *
     *
     * If a LockScreen is setup and [SecureCredentialsManager.requireAuthentication] was called, the user will be asked to authenticate before accessing
     * the credentials. Your activity must override the [Activity.onActivityResult] method and call
     * [SecureCredentialsManager.checkAuthenticationResult] with the received values.
     *
     * @param scope    the scope to request for the access token. If null is passed, the previous scope will be kept.
     * @param minTtl   the minimum time in seconds that the access token should last before expiration.
     * @param parameters additional parameters to send in the request to refresh expired credentials
     * @param callback the callback to receive the result in.
     */
    public fun getCredentials(
        scope: String?,
        minTtl: Int,
        parameters: Map<String, String>,
        callback: Callback<Credentials, CredentialsManagerException>
    ) {
        getCredentials(scope, minTtl, parameters, false, callback)
    }

    /**
     * Tries to obtain the credentials from the Storage. The callback's [Callback.onSuccess] method will be called with the result.
     * If something unexpected happens, the [Callback.onFailure] method will be called with the error. Some devices are not compatible
     * at all with the cryptographic implementation and will have [CredentialsManagerException.isDeviceIncompatible] return true.
     *
     *
     * If a LockScreen is setup and [SecureCredentialsManager.requireAuthentication] was called, the user will be asked to authenticate before accessing
     * the credentials. Your activity must override the [Activity.onActivityResult] method and call
     * [SecureCredentialsManager.checkAuthenticationResult] with the received values.
     *
     * @param scope    the scope to request for the access token. If null is passed, the previous scope will be kept.
     * @param minTtl   the minimum time in seconds that the access token should last before expiration.
     * @param parameters additional parameters to send in the request to refresh expired credentials.
     * @param forceRefresh this will avoid returning the existing credentials and retrieves a new one even if valid credentials exist.
     * @param callback the callback to receive the result in.
     */
    public fun getCredentials(
        scope: String?,
        minTtl: Int,
        parameters: Map<String, String>,
        forceRefresh: Boolean,
        callback: Callback<Credentials, CredentialsManagerException>
    ) {
        if (!hasValidCredentials(minTtl.toLong())) {
            callback.onFailure(CredentialsManagerException("No Credentials were previously set."))
            return
        }
        if (authenticateBeforeDecrypt) {
            Log.d(
                TAG,
                "Authentication is required to read the Credentials. Showing the LockScreen."
            )
            decryptCallback = callback
            this.scope = scope
            this.minTtl = minTtl
            this.forceRefresh = forceRefresh
            activityResultContract?.launch(authIntent)
                ?: activity?.startActivityForResult(authIntent, authenticationRequestCode)
            return
        }
        continueGetCredentials(scope, minTtl, parameters, forceRefresh, callback)
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

    private fun continueGetCredentials(
        scope: String?,
        minTtl: Int,
        parameters: Map<String, String>,
        forceRefresh: Boolean,
        callback: Callback<Credentials, CredentialsManagerException>
    ) {
        serialExecutor.execute {
            val encryptedEncoded = storage.retrieveString(KEY_CREDENTIALS)
            if (encryptedEncoded.isNullOrBlank()) {
                callback.onFailure(CredentialsManagerException("No Credentials were previously set."))
                decryptCallback = null
                return@execute
            }
            val encrypted = Base64.decode(encryptedEncoded, Base64.DEFAULT)
            val json: String
            try {
                json = String(crypto.decrypt(encrypted))
            } catch (e: IncompatibleDeviceException) {
                callback.onFailure(
                    CredentialsManagerException(
                        String.format(
                            "This device is not compatible with the %s class.",
                            SecureCredentialsManager::class.java.simpleName
                        ), e
                    )
                )
                decryptCallback = null
                return@execute
            } catch (e: CryptoException) {
                //If keys were invalidated, existing credentials will not be recoverable.
                clearCredentials()
                callback.onFailure(
                    CredentialsManagerException(
                        "A change on the Lock Screen security settings have deemed the encryption keys invalid and have been recreated. " +
                                "Any previously stored content is now lost. Please try saving the credentials again.",
                        e
                    )
                )
                decryptCallback = null
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
                callback.onFailure(CredentialsManagerException("No Credentials were previously set."))
                decryptCallback = null
                return@execute
            }
            val willAccessTokenExpire = willExpire(expiresAt, minTtl.toLong())
            val scopeChanged = hasScopeChanged(credentials.scope, scope)
            if (!forceRefresh && !willAccessTokenExpire && !scopeChanged) {
                callback.onSuccess(credentials)
                decryptCallback = null
                return@execute
            }
            if (credentials.refreshToken == null) {
                callback.onFailure(CredentialsManagerException("No Credentials were previously set."))
                decryptCallback = null
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

            val freshCredentials: Credentials
            try {
                val fresh = request.execute()
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
                    decryptCallback = null
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
                        "An error occurred while trying to use the Refresh Token to renew the Credentials.",
                        error
                    )
                )
                decryptCallback = null
                return@execute
            }

            try {
                saveCredentials(freshCredentials)
                callback.onSuccess(freshCredentials)
            } catch (error: CredentialsManagerException) {
                val exception = CredentialsManagerException(
                    "An error occurred while saving the refreshed Credentials.", error)
                if(error.cause is IncompatibleDeviceException || error.cause is CryptoException) {
                    exception.refreshedCredentials = freshCredentials
                }
                callback.onFailure(exception)
            }
            decryptCallback = null
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

    init {
        authenticateBeforeDecrypt = false
    }
}