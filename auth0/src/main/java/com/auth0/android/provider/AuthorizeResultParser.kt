package com.auth0.android.provider

import com.auth0.android.authentication.AuthenticationException

/**
 * Parses the result from an authorization redirect callback.
 */
internal object AuthorizeResultParser {

    sealed class CodeResult {
        data class Success(val code: String, val state: String?) : CodeResult()
        data class Error(val exception: AuthenticationException) : CodeResult()
        object Canceled : CodeResult()
        object Invalid : CodeResult()
    }

    private const val KEY_CODE = "code"
    private const val KEY_STATE = "state"
    private const val KEY_ERROR = "error"
    private const val KEY_ERROR_DESCRIPTION = "error_description"

    fun parse(result: AuthorizeResult, requestCode: Int): CodeResult {
        if (!result.isValid(requestCode)) {
            return CodeResult.Invalid
        }

        if (result.isCanceled) {
            return CodeResult.Canceled
        }

        val values = CallbackHelper.getValuesFromUri(result.intentData)
        if (values.isEmpty()) {
            return CodeResult.Invalid
        }

        val error = values[KEY_ERROR]
        if (error != null) {
            val description = values[KEY_ERROR_DESCRIPTION] ?: error
            return CodeResult.Error(AuthenticationException(error, description))
        }

        val code = values[KEY_CODE]
            ?: return CodeResult.Error(
                AuthenticationException(
                    "access_denied",
                    "No authorization code was received in the callback."
                )
            )

        return CodeResult.Success(code = code, state = values[KEY_STATE])
    }
}
