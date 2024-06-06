package com.auth0.android.authentication.storage

import android.util.Log
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import com.auth0.android.callback.Callback
import java.util.concurrent.Executor


internal class LocalAuthenticationManager(
    private val activity: FragmentActivity,
    private val authenticationOptions: LocalAuthenticationOptions,
    private val executor: Executor,
) {
    private val biometricManager = BiometricManager.from(activity)

    fun authenticate(resultCallback: Callback<Boolean, CredentialsManagerException>) {
        val authenticationLevels = if (authenticationOptions.enableDeviceCredentialFallback) {
            authenticationOptions.authenticationLevel.value or AuthenticationLevel.DEVICE_CREDENTIAL.value
        } else {
            authenticationOptions.authenticationLevel.value
        }

        // canAuthenticate API doesn't work as expected on all the API levels, need to work on this.
        val isAuthenticationPossible = biometricManager.canAuthenticate(authenticationLevels)
        if (isAuthenticationPossible != BiometricManager.BIOMETRIC_SUCCESS) {
            logAuthenticatorErrorStatus(isAuthenticationPossible)
            resultCallback.onFailure(CredentialsManagerException("Supplied Authenticators are not possible"))
            return
        }

        val bioMetricPromptInfoBuilder = BiometricPrompt.PromptInfo.Builder().apply {
            authenticationOptions.run {
                setTitle(title)
                setSubtitle(subtitle)
                setDescription(description)
                if (!enableDeviceCredentialFallback) {
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

    private fun logAuthenticatorErrorStatus(authenticatorStatus: Int) {
        val errorMessages = mapOf(
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE to "The hardware is unavailable. Try again later.",
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED to "The user does not have any biometrics enrolled.",
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE to "There is no biometric hardware.",
            BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED to "A security vulnerability has been discovered and the sensor is unavailable until a security update has addressed this issue."
        )

        val errorMessage = errorMessages[authenticatorStatus]
        if (errorMessage != null) {
            Log.e(TAG, errorMessage)
        }
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
                    callback.onFailure(CredentialsManagerException("Biometrics Authentication Failed with error code $errorCode due to $errString"))
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    callback.onFailure(CredentialsManagerException("The user didn't pass the authentication challenge."))
                }
            }
        }

    internal companion object {
        private val TAG = LocalAuthenticationManager::class.java.simpleName
    }
}