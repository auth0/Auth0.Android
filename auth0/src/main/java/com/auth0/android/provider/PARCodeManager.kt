package com.auth0.android.provider

import android.content.Context
import android.net.Uri
import android.util.Log
import com.auth0.android.Auth0
import com.auth0.android.authentication.AuthenticationException
import com.auth0.android.callback.Callback
import com.auth0.android.result.AuthorizationCode

/**
 * Manager for handling PAR (Pushed Authorization Request) code-only flows.
 * This manager handles opening the authorize URL with a request_uri and
 * returns the authorization code to the caller for BFF token exchange.
 */
internal class PARCodeManager(
    private val account: Auth0,
    private val callback: Callback<AuthorizationCode, AuthenticationException>,
    private val requestUri: String,
    private val ctOptions: CustomTabsOptions = CustomTabsOptions.newBuilder().build()
) : ResumableManager() {

    private var requestCode = 0

    private companion object {
        private val TAG = PARCodeManager::class.java.simpleName
        private const val KEY_CLIENT_ID = "client_id"
        private const val KEY_REQUEST_URI = "request_uri"
        private const val KEY_CODE = "code"
        private const val KEY_ERROR = "error"
        private const val KEY_ERROR_DESCRIPTION = "error_description"
        private const val ERROR_VALUE_ACCESS_DENIED = "access_denied"
    }

    fun startAuthentication(context: Context, requestCode: Int) {
        this.requestCode = requestCode
        val uri = buildAuthorizeUri()
        AuthenticationActivity.authenticateUsingBrowser(context, uri, false, ctOptions)
    }

    override fun resume(result: AuthorizeResult): Boolean {
        if (!result.isValid(requestCode)) {
            Log.w(TAG, "The Authorize Result is invalid.")
            return false
        }

        if (result.isCanceled) {
            val exception = AuthenticationException(
                AuthenticationException.ERROR_VALUE_AUTHENTICATION_CANCELED,
                "The user closed the browser app and the authentication was canceled."
            )
            callback.onFailure(exception)
            return true
        }

        val values = CallbackHelper.getValuesFromUri(result.intentData)
        if (values.isEmpty()) {
            Log.w(TAG, "The response didn't contain any values: code")
            return false
        }

        Log.d(TAG, "The parsed CallbackURI contains the following parameters: ${values.keys}")

        // Check for error response
        val error = values[KEY_ERROR]
        if (error != null) {
            val description = values[KEY_ERROR_DESCRIPTION] ?: error
            val authError = AuthenticationException(error, description)
            callback.onFailure(authError)
            return true
        }

        // Extract code
        val code = values[KEY_CODE]
        if (code == null) {
            val exception = AuthenticationException(
                ERROR_VALUE_ACCESS_DENIED,
                "No authorization code was received in the callback."
            )
            callback.onFailure(exception)
            return true
        }

        // Success - return authorization code
        val authorizationCode = AuthorizationCode(code = code)
        callback.onSuccess(authorizationCode)
        return true
    }

    override fun failure(exception: AuthenticationException) {
        callback.onFailure(exception)
    }

    private fun buildAuthorizeUri(): Uri {
        val authorizeUri = Uri.parse(account.authorizeUrl)
        val builder = authorizeUri.buildUpon()

        // Only add client_id and request_uri for PAR flow
        builder.appendQueryParameter(KEY_CLIENT_ID, account.clientId)
        builder.appendQueryParameter(KEY_REQUEST_URI, requestUri)

        val uri = builder.build()
        Log.d(TAG, "Using the following PAR Authorize URI: $uri")
        return uri
    }
}
