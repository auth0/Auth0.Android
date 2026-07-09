package com.auth0.android.provider

import android.app.Activity
import android.net.Uri
import androidx.browser.auth.AuthTabIntent
import com.auth0.android.authentication.AuthenticationException

internal class AuthTabResultHandler(
    private val onSuccess: (Uri?) -> Unit,
    private val onFailure: (AuthenticationException) -> Unit,
    private val onCancel: () -> Unit
) {
    fun handle(resultCode: Int, resultUri: Uri?) {
        when (resultCode) {
            Activity.RESULT_OK -> onSuccess(resultUri)
            AuthTabIntent.RESULT_VERIFICATION_FAILED,
            AuthTabIntent.RESULT_VERIFICATION_TIMED_OUT -> onFailure(
                AuthenticationException(
                    "a0.auth_tab_verification_failed",
                    "Auth Tab redirect URI scheme verification failed."
                )
            )
            else -> onCancel()
        }
    }
}
