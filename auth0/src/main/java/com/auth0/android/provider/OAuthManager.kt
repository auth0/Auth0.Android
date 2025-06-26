package com.auth0.android.provider

import android.content.Context
import android.net.Uri
import android.text.TextUtils
import android.util.Base64
import android.util.Log
import androidx.annotation.VisibleForTesting
import com.auth0.android.Auth0
import com.auth0.android.Auth0Exception
import com.auth0.android.authentication.AuthenticationAPIClient
import com.auth0.android.authentication.AuthenticationException
import com.auth0.android.callback.Callback
import com.auth0.android.dpop.DPoPProvider
import com.auth0.android.dpop.KeyStoreManager
import com.auth0.android.request.internal.Jwt
import com.auth0.android.request.internal.OidcUtils
import com.auth0.android.result.Credentials
import java.security.SecureRandom
import java.util.*

internal class OAuthManager(
    private val account: Auth0,
    private val callback: Callback<Credentials, AuthenticationException>,
    parameters: Map<String, String>,
    ctOptions: CustomTabsOptions,
    private val launchAsTwa: Boolean = false,
    private val customAuthorizeUrl: String? = null
) : ResumableManager() {
    private val parameters: MutableMap<String, String>
    private val headers: MutableMap<String, String>
    private val ctOptions: CustomTabsOptions
    private val apiClient: AuthenticationAPIClient
    private var requestCode = 0
    private var pkce: PKCE? = null

    private val dPoPProvider = DPoPProvider()
    private val keyStoreManager = KeyStoreManager()

    init {
        if (keyStoreManager.getEs256KeyPair() == null) {
            keyStoreManager.generateKeyPair()
        }
    }

    private var _currentTimeInMillis: Long? = null

    @set:VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    internal var currentTimeInMillis: Long
        get() = if (_currentTimeInMillis != null) _currentTimeInMillis!! else System.currentTimeMillis()
        set(value) {
            _currentTimeInMillis = value
        }

    private var idTokenVerificationLeeway: Int? = null
    private var idTokenVerificationIssuer: String? = null

    @VisibleForTesting(otherwise = VisibleForTesting.PACKAGE_PRIVATE)
    fun setPKCE(pkce: PKCE?) {
        this.pkce = pkce
    }

    fun setIdTokenVerificationLeeway(leeway: Int?) {
        idTokenVerificationLeeway = leeway
    }

    fun setIdTokenVerificationIssuer(issuer: String?) {
        idTokenVerificationIssuer = if (TextUtils.isEmpty(issuer)) apiClient.baseURL else issuer
    }

    fun startAuthentication(context: Context, redirectUri: String, requestCode: Int) {
        OidcUtils.includeDefaultScope(parameters)
        addPKCEParameters(parameters, redirectUri, headers)
        addClientParameters(parameters, redirectUri)
        addValidationParameters(parameters)
        addDopParameter(parameters)
        val uri = buildAuthorizeUri()
        this.requestCode = requestCode
        AuthenticationActivity.authenticateUsingBrowser(context, uri, launchAsTwa, ctOptions)
    }

    fun setHeaders(headers: Map<String, String>) {
        this.headers.putAll(headers)
        dPoPProvider.generateDpopProofJwt("POST", "https://${account.domain}/oauth/token")?.let {
            this.headers["DPoP"] = it
        }
    }

    public override fun resume(result: AuthorizeResult): Boolean {
        if (!result.isValid(requestCode)) {
            Log.w(TAG, "The Authorize Result is invalid.")
            return false
        }
        if (result.isCanceled) {
            //User cancelled the authentication
            val exception = AuthenticationException(
                AuthenticationException.ERROR_VALUE_AUTHENTICATION_CANCELED,
                "The user closed the browser app and the authentication was canceled."
            )
            callback.onFailure(exception)
            return true
        }
        val values = CallbackHelper.getValuesFromUri(result.intentData)
        if (values.isEmpty()) {
            Log.w(TAG, "The response didn't contain any of these values: code, state")
            return false
        }
        Log.d(TAG, "The parsed CallbackURI contains the following parameters: ${values.keys}")
        try {
            assertNoError(values[KEY_ERROR], values[KEY_ERROR_DESCRIPTION])
            assertValidState(parameters[KEY_STATE]!!, values[KEY_STATE])
        } catch (e: AuthenticationException) {
            callback.onFailure(e)
            return true
        }

        // response_type=code
        pkce!!.getToken(
            values[KEY_CODE],
            object : Callback<Credentials, AuthenticationException> {
                override fun onSuccess(credentials: Credentials) {
                    assertValidIdToken(
                        credentials.idToken,
                        object : Callback<Void?, Auth0Exception> {
                            override fun onSuccess(result: Void?) {
                                callback.onSuccess(credentials)
                            }

                            override fun onFailure(error: Auth0Exception) {
                                val wrappedError = AuthenticationException(
                                    ERROR_VALUE_ID_TOKEN_VALIDATION_FAILED, error
                                )
                                callback.onFailure(wrappedError)
                            }
                        })
                }

                override fun onFailure(error: AuthenticationException) {
                    if ("Unauthorized" == error.getDescription()) {
                        Log.e(
                            PKCE.TAG,
                            "Unable to complete authentication with PKCE. PKCE support can be enabled by setting Application Type to 'Native' and Token Endpoint Authentication Method to 'None' for this app at 'https://manage.auth0.com/#/applications/" + apiClient.clientId + "/settings'."
                        )
                    }
                    callback.onFailure(error)
                }
            })
        return true
    }

    public override fun failure(exception: AuthenticationException) {
        callback.onFailure(exception)
    }

    private fun assertValidIdToken(
        idToken: String?,
        validationCallback: Callback<Void?, Auth0Exception>
    ) {
        if (TextUtils.isEmpty(idToken)) {
            validationCallback.onFailure(IdTokenMissingException())
            return
        }
        val decodedIdToken: Jwt = try {
            Jwt(idToken!!)
        } catch (error: Exception) {
            validationCallback.onFailure(
                UnexpectedIdTokenException(error)
            )
            return
        }
        val signatureVerifierCallback: Callback<SignatureVerifier, TokenValidationException> =
            object : Callback<SignatureVerifier, TokenValidationException> {
                override fun onFailure(error: TokenValidationException) {
                    validationCallback.onFailure(error)
                }

                override fun onSuccess(result: SignatureVerifier) {
                    val options = IdTokenVerificationOptions(
                        idTokenVerificationIssuer!!,
                        apiClient.clientId,
                        result
                    )
                    val maxAge = parameters[KEY_MAX_AGE]
                    if (!TextUtils.isEmpty(maxAge)) {
                        options.maxAge = Integer.valueOf(maxAge!!)
                    }

                    options.clockSkew = idTokenVerificationLeeway
                    options.nonce = parameters[KEY_NONCE]
                    options.clock = Date(currentTimeInMillis)
                    options.organization = parameters[KEY_ORGANIZATION]
                    try {
                        IdTokenVerifier().verify(decodedIdToken, options, true)
                        validationCallback.onSuccess(null)
                    } catch (exc: TokenValidationException) {
                        validationCallback.onFailure(exc)
                    }
                }
            }
        val tokenKeyId = decodedIdToken.keyId
        SignatureVerifier.forAsymmetricAlgorithm(tokenKeyId, apiClient, signatureVerifierCallback)
    }

    internal fun toState(): OAuthManagerState {
        return OAuthManagerState(
            parameters = parameters.toMap(),
            headers = headers.toMap(),
            requestCode = requestCode,
            ctOptions = ctOptions,
            pkce = pkce,
            auth0 = account,
            idTokenVerificationIssuer = idTokenVerificationIssuer,
            idTokenVerificationLeeway = idTokenVerificationLeeway,
            customAuthorizeUrl = this.customAuthorizeUrl
        )
    }

    //Helper Methods
    @Throws(AuthenticationException::class)
    private fun assertNoError(errorValue: String?, errorDescription: String?) {
        if (errorValue == null) {
            return
        }
        Log.e(
            TAG,
            "Error, access denied. Check that the required Permissions are granted and that the Application has this Connection configured in Auth0 Dashboard."
        )
        val unknownErrorDescription = "An unexpected error occurred."
        when {
            ERROR_VALUE_ACCESS_DENIED.equals(errorValue, ignoreCase = true) -> {
                throw AuthenticationException(
                    ERROR_VALUE_ACCESS_DENIED,
                    errorDescription ?: "Permissions were not granted. Try again."
                )
            }

            ERROR_VALUE_UNAUTHORIZED.equals(errorValue, ignoreCase = true) -> {
                throw AuthenticationException(
                    ERROR_VALUE_UNAUTHORIZED,
                    errorDescription ?: unknownErrorDescription
                )
            }

            ERROR_VALUE_LOGIN_REQUIRED == errorValue -> {
                //Whitelist to allow SSO errors go through
                throw AuthenticationException(
                    errorValue,
                    errorDescription ?: unknownErrorDescription
                )
            }

            else -> {
                throw AuthenticationException(
                    errorValue,
                    errorDescription ?: unknownErrorDescription
                )
            }
        }
    }

    private fun buildAuthorizeUri(): Uri {
        val urlToUse = customAuthorizeUrl ?: account.authorizeUrl
        val authorizeUri = Uri.parse(urlToUse)
        val builder = authorizeUri.buildUpon()
        for ((key, value) in parameters) {
            builder.appendQueryParameter(key, value)
        }
        val uri = builder.build()
        Log.d(TAG, "Using the following Authorize URI: $uri")
        return uri
    }

    private fun addPKCEParameters(
        parameters: MutableMap<String, String>,
        redirectUri: String,
        headers: Map<String, String>
    ) {
        createPKCE(redirectUri, headers)
        val codeChallenge = pkce!!.codeChallenge
        parameters[KEY_CODE_CHALLENGE] = codeChallenge
        parameters[KEY_CODE_CHALLENGE_METHOD] = METHOD_SHA_256
        Log.v(TAG, "Using PKCE authentication flow")
    }

    private fun addValidationParameters(parameters: MutableMap<String, String>) {
        val state = getRandomString(parameters[KEY_STATE])
        val nonce = getRandomString(parameters[KEY_NONCE])
        parameters[KEY_STATE] = state
        parameters[KEY_NONCE] = nonce
    }

    private fun addDopParameter(parameters: MutableMap<String, String>) {
        dPoPProvider.getDpopJktValue()?.let {
            parameters["dpop_jkt"] = it
        }
    }

    private fun addClientParameters(parameters: MutableMap<String, String>, redirectUri: String) {
        parameters[KEY_AUTH0_CLIENT_INFO] = account.auth0UserAgent.value
        parameters[KEY_CLIENT_ID] = account.clientId
        parameters[KEY_REDIRECT_URI] = redirectUri
    }

    private fun createPKCE(redirectUri: String, headers: Map<String, String>) {
        if (pkce == null) {
            pkce = PKCE(apiClient, redirectUri, headers)
        }
    }

    companion object {
        private val TAG = OAuthManager::class.java.simpleName
        const val KEY_RESPONSE_TYPE = "response_type"
        const val KEY_STATE = "state"
        const val KEY_NONCE = "nonce"
        const val KEY_MAX_AGE = "max_age"
        const val KEY_CONNECTION = "connection"
        const val KEY_ORGANIZATION = "organization"
        const val KEY_INVITATION = "invitation"
        const val KEY_SCOPE = "scope"
        const val RESPONSE_TYPE_CODE = "code"
        private const val DEFAULT_SCOPE = "openid profile email"
        private const val REQUIRED_SCOPE = "openid"
        private const val ERROR_VALUE_INVALID_CONFIGURATION = "a0.invalid_configuration"
        private const val ERROR_VALUE_ACCESS_DENIED = "access_denied"
        private const val ERROR_VALUE_UNAUTHORIZED = "unauthorized"
        private const val ERROR_VALUE_LOGIN_REQUIRED = "login_required"
        private const val ERROR_VALUE_ID_TOKEN_VALIDATION_FAILED = "Could not verify the ID token"
        private const val METHOD_SHA_256 = "S256"
        private const val KEY_CODE_CHALLENGE = "code_challenge"
        private const val KEY_CODE_CHALLENGE_METHOD = "code_challenge_method"
        private const val KEY_CLIENT_ID = "client_id"
        private const val KEY_REDIRECT_URI = "redirect_uri"
        private const val KEY_AUTH0_CLIENT_INFO = "auth0Client"
        private const val KEY_ERROR = "error"
        private const val KEY_ERROR_DESCRIPTION = "error_description"
        private const val KEY_CODE = "code"

        @JvmStatic
        @VisibleForTesting(otherwise = VisibleForTesting.PACKAGE_PRIVATE)
        @Throws(AuthenticationException::class)
        fun assertValidState(requestState: String, responseState: String?) {
            if (requestState != responseState) {
                Log.e(
                    TAG,
                    String.format(
                        "Received state doesn't match. Received %s but expected %s",
                        responseState,
                        requestState
                    )
                )
                throw AuthenticationException(
                    ERROR_VALUE_ACCESS_DENIED,
                    "The received state is invalid. Try again."
                )
            }
        }

        @VisibleForTesting(otherwise = VisibleForTesting.PACKAGE_PRIVATE)
        fun getRandomString(defaultValue: String?): String {
            return defaultValue ?: secureRandomString()
        }

        private fun secureRandomString(): String {
            val sr = SecureRandom()
            val randomBytes = ByteArray(32)
            sr.nextBytes(randomBytes)
            return Base64.encodeToString(
                randomBytes,
                Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING
            )
        }
    }

    init {
        headers = HashMap()
        this.parameters = parameters.toMutableMap()
        this.parameters[KEY_RESPONSE_TYPE] = RESPONSE_TYPE_CODE
        apiClient = AuthenticationAPIClient(account)
        this.ctOptions = ctOptions
    }
}

internal fun OAuthManager.Companion.fromState(
    state: OAuthManagerState,
    callback: Callback<Credentials, AuthenticationException>
): OAuthManager {
    return OAuthManager(
        account = state.auth0,
        ctOptions = state.ctOptions,
        parameters = state.parameters,
        callback = callback,
        customAuthorizeUrl = state.customAuthorizeUrl
    ).apply {
        setHeaders(
            state.headers
        )
        setPKCE(state.pkce)
        setIdTokenVerificationIssuer(state.idTokenVerificationIssuer)
        setIdTokenVerificationLeeway(state.idTokenVerificationLeeway)
    }
}