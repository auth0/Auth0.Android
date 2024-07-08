package com.auth0.android.authentication.storage

import android.os.Build
import android.os.Handler
import android.os.Looper
import androidx.annotation.VisibleForTesting
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import com.auth0.android.callback.Callback
import java.util.concurrent.Executor


internal class LocalAuthenticationManager(
    private val activity: FragmentActivity,
    private val authenticationOptions: LocalAuthenticationOptions,
    private val executor: Executor,
    private val biometricManager: BiometricManager = BiometricManager.from(activity),
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
            executor,
            biometricPromptAuthenticationCallback(resultCallback)
        )
        biometricPrompt.authenticate(biometricPromptInfo)
    }


    private fun generateExceptionFromAuthenticationPossibilityError(errorCode: Int): CredentialsManagerException {
        val exceptionCode = mapOf(
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE to CredentialsManagerException.BIOMETRIC_ERROR_HW_UNAVAILABLE,
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED to CredentialsManagerException.BIOMETRIC_ERROR_NONE_ENROLLED,
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE to CredentialsManagerException.BIOMETRIC_ERROR_NO_HARDWARE,
            BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED to CredentialsManagerException.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED,
            BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED to CredentialsManagerException.BIOMETRIC_ERROR_UNSUPPORTED,
            BiometricManager.BIOMETRIC_STATUS_UNKNOWN to CredentialsManagerException.BIOMETRIC_STATUS_UNKNOWN
        )
        return exceptionCode[errorCode]
            ?: CredentialsManagerException.BIOMETRIC_AUTHENTICATION_CHECK_FAILED
    }

    private val biometricPromptAuthenticationCallback =
        { callback: Callback<Boolean, CredentialsManagerException> ->
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    callback.onSuccess(true)
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    callback.onFailure(
                        CredentialsManagerException(
                            CredentialsManagerException.Code.BIOMETRICS_FAILED,
                            "Biometrics Authentication Failed with error code $errorCode due to $errString"
                        )
                    )
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    callback.onFailure(CredentialsManagerException.BIOMETRICS_FAILED)
                }
            }
        }

    internal companion object {
        private val TAG = LocalAuthenticationManager::class.java.simpleName
    }
}