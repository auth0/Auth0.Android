package com.auth0.android.provider

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.annotation.VisibleForTesting
import com.auth0.android.authentication.AuthenticationException
import com.auth0.android.authentication.AuthenticationException.Companion.ERROR_KEY_CT_OPTIONS_NULL
import com.auth0.android.authentication.AuthenticationException.Companion.ERROR_KEY_URI_NULL
import com.auth0.android.authentication.AuthenticationException.Companion.ERROR_VALUE_AUTHORIZE_URI_INVALID
import com.auth0.android.authentication.AuthenticationException.Companion.ERROR_VALUE_CT_OPTIONS_INVALID
import com.auth0.android.callback.RunnableTask
import com.auth0.android.provider.WebAuthProvider.failure
import com.auth0.android.provider.WebAuthProvider.resume
import com.auth0.android.request.internal.CommonThreadSwitcher.Companion.getInstance
import com.google.androidbrowserhelper.trusted.TwaLauncher

public open class AuthenticationActivity : Activity() {
    private var intentLaunched = false
    private var customTabsController: CustomTabsController? = null
    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        setIntent(intent)
    }

    public override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        val resultData = if (resultCode == RESULT_CANCELED) Intent() else data
        deliverAuthenticationResult(resultData)
        finish()
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putBoolean(EXTRA_INTENT_LAUNCHED, intentLaunched)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (savedInstanceState != null) {
            intentLaunched = savedInstanceState.getBoolean(EXTRA_INTENT_LAUNCHED, false)
        }
    }

    override fun onResume() {
        super.onResume()
        val authenticationIntent = intent
        if (!intentLaunched && authenticationIntent.extras == null) {
            //Activity was launched in an unexpected way
            finish()
            return
        } else if (!intentLaunched) {
            intentLaunched = true
            launchAuthenticationIntent()
            return
        }
        val resultMissing = authenticationIntent.data == null
        if (resultMissing) {
            setResult(RESULT_CANCELED)
        }
        deliverAuthenticationResult(authenticationIntent)
        finish()
    }

    override fun onDestroy() {
        super.onDestroy()
        if (customTabsController != null) {
            customTabsController!!.unbindService()
            customTabsController = null
        }
    }

    private fun launchAuthenticationIntent() {
        val extras: Bundle? = intent.extras

        val authorizeUri = extras?.getParcelable<Uri>(EXTRA_AUTHORIZE_URI)
        authorizeUri ?: run {
            deliverAuthenticationFailure(
                AuthenticationException(
                    ERROR_KEY_URI_NULL, ERROR_VALUE_AUTHORIZE_URI_INVALID
                )
            )
            return
        }

        val customTabsOptions: CustomTabsOptions? = extras.getParcelable(EXTRA_CT_OPTIONS)
        customTabsOptions ?: run {
            deliverAuthenticationFailure(
                AuthenticationException(
                    ERROR_KEY_CT_OPTIONS_NULL, ERROR_VALUE_CT_OPTIONS_INVALID
                )
            )
            return
        }

        val launchAsTwa: Boolean = extras.getBoolean(EXTRA_LAUNCH_AS_TWA, false)
        customTabsController = createCustomTabsController(this, customTabsOptions)
        customTabsController!!.bindService()
        customTabsController!!.launchUri(authorizeUri,
            launchAsTwa,
            getInstance(),
            object : RunnableTask<AuthenticationException> {
                override fun apply(error: AuthenticationException) {
                    deliverAuthenticationFailure(error)
                }
            })
    }

    @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    internal open fun createCustomTabsController(
        context: Context, options: CustomTabsOptions
    ): CustomTabsController {
        return CustomTabsController(context, options, TwaLauncher(context))
    }

    @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    internal open fun deliverAuthenticationResult(result: Intent?) {
        resume(result)
    }

    internal open fun deliverAuthenticationFailure(ex: AuthenticationException) {
        failure(ex)
        finish()
    }

    internal companion object {
        const val EXTRA_AUTHORIZE_URI = "com.auth0.android.EXTRA_AUTHORIZE_URI"
        const val EXTRA_LAUNCH_AS_TWA = "com.auth0.android.EXTRA_LAUNCH_AS_TWA"
        const val EXTRA_CT_OPTIONS = "com.auth0.android.EXTRA_CT_OPTIONS"
        private const val EXTRA_INTENT_LAUNCHED = "com.auth0.android.EXTRA_INTENT_LAUNCHED"

        @JvmStatic
        internal fun authenticateUsingBrowser(
            context: Context, authorizeUri: Uri, launchAsTwa: Boolean, options: CustomTabsOptions
        ) {
            val intent = Intent(context, AuthenticationActivity::class.java)
            intent.putExtra(EXTRA_AUTHORIZE_URI, authorizeUri)
            intent.putExtra(EXTRA_LAUNCH_AS_TWA, launchAsTwa)
            intent.putExtra(EXTRA_CT_OPTIONS, options)
            intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP)
            context.startActivity(intent)
        }
    }
}