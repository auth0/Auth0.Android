package com.auth0.android.provider

import android.content.Context
import android.net.Uri
import android.util.Log
import com.auth0.android.Auth0
import com.auth0.android.authentication.AuthenticationException
import com.auth0.android.callback.Callback
import java.lang.ref.WeakReference
import java.util.*

internal class LogoutManager(
    private val account: Auth0,
    callback: Callback<Void?, AuthenticationException>,
    returnToUrl: String,
    ctOptions: CustomTabsOptions,
    federated: Boolean = false,
    private val launchAsTwa: Boolean = false,
    private val customLogoutUrl: String? = null
) : ResumableManager() {
    private val callbackRef = WeakReference(callback)

    private fun deliverSuccess() {
        val cb = callbackRef.get()
        if (cb != null) {
            cb.onSuccess(null)
        } else {
            WebAuthProvider.pendingLogoutResult =
                WebAuthProvider.PendingResult.Success(null)
        }
    }

    private fun deliverFailure(error: AuthenticationException) {
        val cb = callbackRef.get()
        if (cb != null) {
            cb.onFailure(error)
        } else {
            WebAuthProvider.pendingLogoutResult =
                WebAuthProvider.PendingResult.Failure(error)
        }
    }
    private val parameters: MutableMap<String, String>
    private val ctOptions: CustomTabsOptions
    fun startLogout(context: Context) {
        addClientParameters(parameters)
        val uri = buildLogoutUri()
        AuthenticationActivity.authenticateUsingBrowser(context, uri, launchAsTwa, ctOptions)
    }

    public override fun resume(result: AuthorizeResult): Boolean {
        if (result.isCanceled) {
            val exception = AuthenticationException(
                AuthenticationException.ERROR_VALUE_AUTHENTICATION_CANCELED,
                "The user closed the browser app so the logout was cancelled."
            )
            deliverFailure(exception)
        } else {
            deliverSuccess()
        }
        return true
    }

    override fun failure(exception: AuthenticationException) {
        deliverFailure(exception)
    }

    private fun buildLogoutUri(): Uri {
        val urlToUse = customLogoutUrl ?: account.logoutUrl
        val logoutUri = Uri.parse(urlToUse)
        val builder = logoutUri.buildUpon()
        for ((key, value) in parameters) {
            builder.appendQueryParameter(key, value)
        }
        val uri = builder.build()
        Log.d(TAG, "Using the following Logout URI: $uri")
        return uri
    }

    private fun addClientParameters(parameters: MutableMap<String, String>) {
        parameters[KEY_USER_AGENT] = account.auth0UserAgent.value
        parameters[KEY_CLIENT_ID] = account.clientId
    }

    companion object {
        private val TAG = LogoutManager::class.java.simpleName
        private const val KEY_CLIENT_ID = "client_id"
        private const val KEY_USER_AGENT = "auth0Client"
        private const val KEY_RETURN_TO_URL = "returnTo"
        private const val KEY_FEDERATED = "federated"
    }

    init {
        parameters = HashMap()
        parameters[KEY_RETURN_TO_URL] = returnToUrl
        if (federated) {
            // null or empty values are not included in the request
            parameters[KEY_FEDERATED] = "1"
        }
        this.ctOptions = ctOptions
    }
}