package com.auth0.android.authentication.biometrics


import android.hardware.biometrics.BiometricManager.Authenticators
public enum class BiometricAuthenticators private constructor (public val value: Int) {
    STRONG (Authenticators.BIOMETRIC_STRONG),
    WEAK (Authenticators.BIOMETRIC_WEAK),
    DEVICE_CREDENTIAL (Authenticators.DEVICE_CREDENTIAL);
}