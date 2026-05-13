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
    private val sessionTransferToken: String? = null,
    private val ctOptions: CustomTabsOptions = CustomTabsOptions.newBuilder().build()
) : ResumableManager() {

    private var requestCode = 0

    private companion object {
        private val TAG = PARCodeManager::class.java.simpleName
    }

    fun startAuthentication(context: Context, requestCode: Int) {
        this.requestCode = requestCode
        val additionalParams = buildMap {
            sessionTransferToken?.let { put("session_transfer_token", it) }
        }
        val uri = PARUtils.buildAuthorizeUri(account, requestUri, additionalParams)
        Log.d(TAG, "Using the following PAR Authorize URI: $uri")
        AuthenticationActivity.authenticateUsingBrowser(context, uri, false, ctOptions)
    }

    override fun resume(result: AuthorizeResult): Boolean {
        return when (val parsed = AuthorizeResultParser.parse(result, requestCode)) {
            is AuthorizeResultParser.CodeResult.Success -> {
                callback.onSuccess(AuthorizationCode(parsed.code, parsed.state))
                true
            }
            is AuthorizeResultParser.CodeResult.Error -> {
                callback.onFailure(parsed.exception)
                true
            }
            is AuthorizeResultParser.CodeResult.Canceled -> {
                callback.onFailure(
                    AuthenticationException(
                        AuthenticationException.ERROR_VALUE_AUTHENTICATION_CANCELED,
                        "The user closed the browser app and the authentication was canceled."
                    )
                )
                true
            }
            AuthorizeResultParser.CodeResult.Invalid -> false
        }
    }

    override fun failure(exception: AuthenticationException) {
        callback.onFailure(exception)
    }
}
