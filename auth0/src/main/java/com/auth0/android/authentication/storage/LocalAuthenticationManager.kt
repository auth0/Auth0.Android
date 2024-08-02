package com.auth0.android.authentication.storage

import android.os.Build
import android.os.Handler
import android.os.Looper
import androidx.annotation.VisibleForTesting
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.biometric.BiometricPrompt.AuthenticationCallback
import androidx.fragment.app.FragmentActivity
import com.auth0.android.callback.Callback
import java.util.concurrent.Executor


internal class LocalAuthenticationManager(
    private val activity: FragmentActivity,
    private val authenticationOptions: LocalAuthenticationOptions,
    private val biometricManager: BiometricManager = BiometricManager.from(activity),
    @get:VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    internal val resultCallback: Callback<Boolean, CredentialsManagerException>,
) : AuthenticationCallback() {

    private val uiThreadExecutor = UiThreadExecutor()

    fun authenticate() {
        // On Android API 29 and below, specifying DEVICE_CREDENTIAL alone as the authentication level is not supported.
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R && authenticationOptions.authenticationLevel.value == AuthenticationLevel.DEVICE_CREDENTIAL.value) {
            resultCallback.onFailure(CredentialsManagerException.BIOMETRIC_ERROR_DEVICE_CREDENTIAL_NOT_AVAILABLE)
            return
        }

        // On Android API 28 and 29, specifying BIOMETRIC_STRONG as the authentication level along with enabling device credential fallback is not supported.
        if (Build.VERSION.SDK_INT in Build.VERSION_CODES.P..Build.VERSION_CODES.Q &&
            authenticationOptions.authenticationLevel.value == AuthenticationLevel.STRONG.value &&
            authenticationOptions.enableDeviceCredentialFallback
        ) {
            resultCallback.onFailure(CredentialsManagerException.BIOMETRIC_ERROR_STRONG_AND_DEVICE_CREDENTIAL_NOT_AVAILABLE)
            return
        }

        val authenticationLevels = if (authenticationOptions.enableDeviceCredentialFallback) {
            authenticationOptions.authenticationLevel.value or AuthenticationLevel.DEVICE_CREDENTIAL.value
        } else {
            authenticationOptions.authenticationLevel.value
        }

        // canAuthenticate API doesn't work as expected on all the API levels, need to work on this.
        val isAuthenticationPossible = biometricManager.canAuthenticate(authenticationLevels)
        if (isAuthenticationPossible != BiometricManager.BIOMETRIC_SUCCESS) {
            resultCallback.onFailure(
                generateExceptionFromAuthenticationPossibilityError(
                    isAuthenticationPossible
                )
            )
            return
        }

        val bioMetricPromptInfoBuilder = BiometricPrompt.PromptInfo.Builder().apply {
            authenticationOptions.run {
                setTitle(title)
                setSubtitle(subtitle)
                setDescription(description)
                if (!enableDeviceCredentialFallback && authenticationLevel != AuthenticationLevel.DEVICE_CREDENTIAL) {
                    setNegativeButtonText(negativeButtonText)
                }
            }
            setAllowedAuthenticators(authenticationLevels)
        }

        val biometricPromptInfo = bioMetricPromptInfoBuilder.build()
        val biometricPrompt = BiometricPrompt(
            activity,
            uiThreadExecutor,
            this
        )
        biometricPrompt.authenticate(biometricPromptInfo)
    }

    override fun onAuthenticationFailed() {
        super.onAuthenticationFailed()
        resultCallback.onFailure(CredentialsManagerException.BIOMETRICS_INVALID_USER)
    }

    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
        super.onAuthenticationSucceeded(result)
        resultCallback.onSuccess(true)
    }

    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
        super.onAuthenticationError(errorCode, errString)
        resultCallback.onFailure(generateExceptionFromAuthenticationError(errorCode))
    }

    private fun generateExceptionFromAuthenticationPossibilityError(errorCode: Int): CredentialsManagerException {
        val exceptionCode = mapOf(
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE to CredentialsManagerException.BIOMETRIC_ERROR_HW_UNAVAILABLE,
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED to CredentialsManagerException.BIOMETRIC_ERROR_NONE_ENROLLED,
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE to CredentialsManagerException.BIOMETRIC_ERROR_NO_HARDWARE,
            BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED to CredentialsManagerException.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED,
            BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED to CredentialsManagerException.BIOMETRIC_ERROR_UNSUPPORTED,
            BiometricManager.BIOMETRIC_STATUS_UNKNOWN to CredentialsManagerException.BIOMETRIC_ERROR_STATUS_UNKNOWN
        )
        return exceptionCode[errorCode]
            ?: CredentialsManagerException.BIOMETRIC_AUTHENTICATION_CHECK_FAILED
    }

    private fun generateExceptionFromAuthenticationError(errorCode: Int): CredentialsManagerException {
        val exceptionCode = mapOf(
            BiometricPrompt.ERROR_HW_UNAVAILABLE to CredentialsManagerException.BIOMETRIC_ERROR_HW_UNAVAILABLE,
            BiometricPrompt.ERROR_UNABLE_TO_PROCESS to CredentialsManagerException.BIOMETRIC_ERROR_UNABLE_TO_PROCESS,
            BiometricPrompt.ERROR_TIMEOUT to CredentialsManagerException.BIOMETRIC_ERROR_TIMEOUT,
            BiometricPrompt.ERROR_NO_SPACE to CredentialsManagerException.BIOMETRIC_ERROR_NO_SPACE,
            BiometricPrompt.ERROR_CANCELED to CredentialsManagerException.BIOMETRIC_ERROR_CANCELED,
            BiometricPrompt.ERROR_LOCKOUT to CredentialsManagerException.BIOMETRIC_ERROR_LOCKOUT,
            BiometricPrompt.ERROR_VENDOR to CredentialsManagerException.BIOMETRIC_ERROR_VENDOR,
            BiometricPrompt.ERROR_LOCKOUT_PERMANENT to CredentialsManagerException.BIOMETRIC_ERROR_LOCKOUT_PERMANENT,
            BiometricPrompt.ERROR_USER_CANCELED to CredentialsManagerException.BIOMETRIC_ERROR_USER_CANCELED,
            BiometricPrompt.ERROR_NO_BIOMETRICS to CredentialsManagerException.BIOMETRIC_ERROR_NO_BIOMETRICS,
            BiometricPrompt.ERROR_HW_NOT_PRESENT to CredentialsManagerException.BIOMETRIC_ERROR_HW_NOT_PRESENT,
            BiometricPrompt.ERROR_NEGATIVE_BUTTON to CredentialsManagerException.BIOMETRIC_ERROR_NEGATIVE_BUTTON,
            BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL to CredentialsManagerException.BIOMETRIC_ERROR_NO_DEVICE_CREDENTIAL,
        )
        return exceptionCode[errorCode]
            ?: CredentialsManagerException.BIOMETRIC_AUTHENTICATION_FAILED
    }

    class UiThreadExecutor : Executor {
        private val handler = Handler(Looper.getMainLooper())

        override fun execute(command: Runnable) {
            handler.post(command)
        }
    }
}