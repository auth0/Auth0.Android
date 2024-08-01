package com.auth0.android.authentication.storage

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import com.auth0.android.callback.Callback
import com.nhaarman.mockitokotlin2.KArgumentCaptor
import com.nhaarman.mockitokotlin2.any
import com.nhaarman.mockitokotlin2.argumentCaptor
import com.nhaarman.mockitokotlin2.verify
import org.hamcrest.MatcherAssert
import org.hamcrest.Matchers
import org.hamcrest.core.Is
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.Mock
import org.mockito.Mockito
import org.mockito.MockitoAnnotations
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config


@RunWith(RobolectricTestRunner::class)
public class LocalAuthenticationManagerTest {

    private lateinit var fragmentActivity: FragmentActivity

    @Mock
    private lateinit var biometricManager: BiometricManager

    @Mock
    private lateinit var callback: Callback<Boolean, CredentialsManagerException>

    @Mock
    private lateinit var authenticationResult: BiometricPrompt.AuthenticationResult

    private val exceptionCaptor: KArgumentCaptor<CredentialsManagerException> = argumentCaptor()

    @Before
    public fun setUp() {
        MockitoAnnotations.openMocks(this)
        fragmentActivity =
            Mockito.spy(
                Robolectric.buildActivity(FragmentActivity::class.java).create().start().resume()
                    .get()
            )

    }

    @Test
    @Config(sdk = [29])
    public fun testFailureOfDeviceCredentialsAuthenticationLevelOnAPILessThan30() {
        val localAuthenticationManager = LocalAuthenticationManager(
            fragmentActivity,
            getAuthenticationOptions(authenticator = AuthenticationLevel.DEVICE_CREDENTIAL),
            biometricManager,
            callback
        )

        localAuthenticationManager.authenticate()
        verify(callback).onFailure(exceptionCaptor.capture())

        val exception = exceptionCaptor.firstValue
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`(CredentialsManagerException.BIOMETRIC_ERROR_DEVICE_CREDENTIAL_NOT_AVAILABLE.message)
        )
    }

    @Test
    @Config(sdk = [30])
    public fun testSuccessOfDeviceCredentialsAuthenticationLevelOnAPI30() {
        val localAuthenticationManager = LocalAuthenticationManager(
            fragmentActivity,
            getAuthenticationOptions(authenticator = AuthenticationLevel.DEVICE_CREDENTIAL),
            biometricManager,
            callback
        )

        localAuthenticationManager.authenticate()
        localAuthenticationManager.onAuthenticationSucceeded(authenticationResult)
        val argumentCaptor = argumentCaptor<Int>()
        verify(biometricManager).canAuthenticate(argumentCaptor.capture())
        verify(callback).onSuccess(true)

        val authenticationLevels = argumentCaptor.firstValue
        MatcherAssert.assertThat(authenticationLevels, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            authenticationLevels,
            Is.`is`(AuthenticationLevel.DEVICE_CREDENTIAL.value)
        )
    }

    @Test
    @Config(sdk = [28, 29])
    public fun testFailureOfBiometricStrongAndDeviceCredentialsFallbackOnAPILevel28and29() {
        val localAuthenticationManager = LocalAuthenticationManager(
            fragmentActivity,
            getAuthenticationOptions(
                authenticator = AuthenticationLevel.STRONG,
                enableDeviceCredentialFallback = true
            ),
            biometricManager,
            callback
        )

        localAuthenticationManager.authenticate()
        verify(callback).onFailure(exceptionCaptor.capture())

        val exception = exceptionCaptor.firstValue
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            exception,
            Is.`is`(CredentialsManagerException.BIOMETRIC_ERROR_STRONG_AND_DEVICE_CREDENTIAL_NOT_AVAILABLE)
        )
    }

    @Test
    @Config(sdk = [27, 30])
    public fun testSuccessOfBiometricStrongAndDeviceCredentialsFallbackOnAPILevel27and30() {
        val localAuthenticationManager = LocalAuthenticationManager(
            fragmentActivity,
            getAuthenticationOptions(
                authenticator = AuthenticationLevel.STRONG,
                enableDeviceCredentialFallback = true
            ),
            biometricManager,
            callback
        )

        localAuthenticationManager.authenticate()
        localAuthenticationManager.onAuthenticationSucceeded(authenticationResult)
        val argumentCaptor = argumentCaptor<Int>()
        verify(biometricManager).canAuthenticate(argumentCaptor.capture())
        verify(callback).onSuccess(true)

        val authenticationLevels = argumentCaptor.firstValue
        MatcherAssert.assertThat(authenticationLevels, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            authenticationLevels,
            Is.`is`(AuthenticationLevel.STRONG.value or AuthenticationLevel.DEVICE_CREDENTIAL.value)
        )
    }

    @Test
    @Config(sdk = [27, 28, 29, 30])
    public fun testSuccessOfBiometricWeakAndDeviceCredentialsFallbackAcrossMultipleLevels() {
        val localAuthenticationManager = LocalAuthenticationManager(
            fragmentActivity,
            getAuthenticationOptions(
                authenticator = AuthenticationLevel.WEAK,
                enableDeviceCredentialFallback = true
            ),
            biometricManager,
            callback
        )

        localAuthenticationManager.authenticate()
        localAuthenticationManager.onAuthenticationSucceeded(authenticationResult)
        val argumentCaptor = argumentCaptor<Int>()
        verify(biometricManager).canAuthenticate(argumentCaptor.capture())
        verify(callback).onSuccess(true)

        val authenticationLevels = argumentCaptor.firstValue
        MatcherAssert.assertThat(authenticationLevels, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            authenticationLevels,
            Is.`is`(AuthenticationLevel.WEAK.value or AuthenticationLevel.DEVICE_CREDENTIAL.value)
        )
    }

    @Test
    @Config(sdk = [27, 28, 29, 30])
    public fun testSuccessOfBiometricStrongAuthenticationAcrossMultipleLevels() {
        val localAuthenticationManager = LocalAuthenticationManager(
            fragmentActivity,
            getAuthenticationOptions(authenticator = AuthenticationLevel.STRONG),
            biometricManager,
            callback
        )

        localAuthenticationManager.authenticate()
        localAuthenticationManager.onAuthenticationSucceeded(authenticationResult)
        val argumentCaptor = argumentCaptor<Int>()
        verify(biometricManager).canAuthenticate(argumentCaptor.capture())
        verify(callback).onSuccess(true)

        val authenticationLevels = argumentCaptor.firstValue
        MatcherAssert.assertThat(authenticationLevels, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            authenticationLevels,
            Is.`is`(AuthenticationLevel.STRONG.value)
        )
    }

    @Test
    @Config(sdk = [27, 28, 29, 30])
    public fun testSuccessOfBiometricWeakAuthenticationAcrossMultipleLevels() {
        val localAuthenticationManager = LocalAuthenticationManager(
            fragmentActivity,
            getAuthenticationOptions(authenticator = AuthenticationLevel.WEAK),
            biometricManager,
            callback
        )

        localAuthenticationManager.authenticate()
        localAuthenticationManager.onAuthenticationSucceeded(authenticationResult)
        val argumentCaptor = argumentCaptor<Int>()
        verify(biometricManager).canAuthenticate(argumentCaptor.capture())
        verify(callback).onSuccess(true)

        val authenticationLevels = argumentCaptor.firstValue
        MatcherAssert.assertThat(authenticationLevels, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            authenticationLevels,
            Is.`is`(AuthenticationLevel.WEAK.value)
        )
    }


    @Test
    public fun testCanAuthenticateReturnsBIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED() {
        val localAuthenticationManager = LocalAuthenticationManager(
            fragmentActivity,
            getAuthenticationOptions(),
            biometricManager,
            callback
        )

        Mockito.`when`(biometricManager.canAuthenticate(any()))
            .thenReturn(BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED)

        localAuthenticationManager.authenticate()
        verify(callback).onFailure(exceptionCaptor.capture())

        val exception = exceptionCaptor.firstValue
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`(CredentialsManagerException.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED.message)
        )
    }

    @Test
    public fun testCanAuthenticateReturnsBIOMETRIC_ERROR_NO_HARDWARE() {
        val localAuthenticationManager = LocalAuthenticationManager(
            fragmentActivity,
            getAuthenticationOptions(),
            biometricManager,
            callback
        )

        Mockito.`when`(biometricManager.canAuthenticate(any()))
            .thenReturn(BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE)

        localAuthenticationManager.authenticate()
        verify(callback).onFailure(exceptionCaptor.capture())

        val exception = exceptionCaptor.firstValue
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`(CredentialsManagerException.BIOMETRIC_ERROR_NO_HARDWARE.message)
        )
    }

    @Test
    public fun testCanAuthenticateReturnsBIOMETRIC_ERROR_NONE_ENROLLED() {
        val localAuthenticationManager = LocalAuthenticationManager(
            fragmentActivity,
            getAuthenticationOptions(),
            biometricManager,
            callback
        )

        Mockito.`when`(biometricManager.canAuthenticate(any()))
            .thenReturn(BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED)

        localAuthenticationManager.authenticate()
        verify(callback).onFailure(exceptionCaptor.capture())

        val exception = exceptionCaptor.firstValue
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`(CredentialsManagerException.BIOMETRIC_ERROR_NONE_ENROLLED.message)
        )
    }

    @Test
    public fun testCanAuthenticateReturnsBIOMETRIC_ERROR_UNSUPPORTED() {
        val localAuthenticationManager = LocalAuthenticationManager(
            fragmentActivity,
            getAuthenticationOptions(),
            biometricManager,
            callback
        )

        Mockito.`when`(biometricManager.canAuthenticate(any()))
            .thenReturn(BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED)

        localAuthenticationManager.authenticate()
        verify(callback).onFailure(exceptionCaptor.capture())

        val exception = exceptionCaptor.firstValue
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`(CredentialsManagerException.BIOMETRIC_ERROR_UNSUPPORTED.message)
        )
    }

    @Test
    public fun testCanAuthenticateReturnsBIOMETRIC_ERROR_STATUS_UNKNOWN() {
        val localAuthenticationManager = LocalAuthenticationManager(
            fragmentActivity,
            getAuthenticationOptions(),
            biometricManager,
            callback
        )

        Mockito.`when`(biometricManager.canAuthenticate(any()))
            .thenReturn(BiometricManager.BIOMETRIC_STATUS_UNKNOWN)

        localAuthenticationManager.authenticate()
        verify(callback).onFailure(exceptionCaptor.capture())

        val exception = exceptionCaptor.firstValue
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`(CredentialsManagerException.BIOMETRIC_ERROR_STATUS_UNKNOWN.message)
        )
    }

    @Test
    public fun testCanAuthenticateReturnsBIOMETRIC_ERROR_HW_UNAVAILABLE() {
        val localAuthenticationManager = LocalAuthenticationManager(
            fragmentActivity,
            getAuthenticationOptions(),
            biometricManager,
            callback
        )

        Mockito.`when`(biometricManager.canAuthenticate(any()))
            .thenReturn(BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE)

        localAuthenticationManager.authenticate()
        verify(callback).onFailure(exceptionCaptor.capture())

        val exception = exceptionCaptor.firstValue
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`(CredentialsManagerException.BIOMETRIC_ERROR_HW_UNAVAILABLE.message)
        )
    }

    @Test
    public fun testInvalidAuthenticationScenario() {
        val localAuthenticationManager = LocalAuthenticationManager(
            fragmentActivity,
            getAuthenticationOptions(),
            biometricManager,
            callback
        )

        localAuthenticationManager.authenticate()
        Mockito.`when`(biometricManager.canAuthenticate(any()))
            .thenReturn(BiometricManager.BIOMETRIC_SUCCESS)
        localAuthenticationManager.onAuthenticationFailed()
        verify(callback).onFailure(CredentialsManagerException.BIOMETRICS_INVALID_USER)
    }

    @Test
    public fun testAuthenticationErrorWithBIOMETRIC_ERROR_NO_DEVICE_CREDENTIAL() {
        val localAuthenticationManager = LocalAuthenticationManager(
            fragmentActivity,
            getAuthenticationOptions(),
            biometricManager,
            callback
        )

        localAuthenticationManager.authenticate()
        localAuthenticationManager.onAuthenticationError(
            BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL,
            "error"
        )
        verify(callback).onFailure(CredentialsManagerException.BIOMETRIC_ERROR_NO_DEVICE_CREDENTIAL)
    }

    @Test
    public fun testAuthenticationErrorWithBIOMETRIC_ERROR_NEGATIVE_BUTTON() {
        val localAuthenticationManager = LocalAuthenticationManager(
            fragmentActivity,
            getAuthenticationOptions(),
            biometricManager,
            callback
        )

        localAuthenticationManager.authenticate()
        localAuthenticationManager.onAuthenticationError(
            BiometricPrompt.ERROR_NEGATIVE_BUTTON,
            "error"
        )
        verify(callback).onFailure(CredentialsManagerException.BIOMETRIC_ERROR_NEGATIVE_BUTTON)
    }

    @Test
    public fun testAuthenticationErrorWithBIOMETRIC_ERROR_HW_NOT_PRESENT() {
        val localAuthenticationManager = LocalAuthenticationManager(
            fragmentActivity,
            getAuthenticationOptions(),
            biometricManager,
            callback
        )

        localAuthenticationManager.authenticate()
        localAuthenticationManager.onAuthenticationError(
            BiometricPrompt.ERROR_HW_NOT_PRESENT,
            "error"
        )
        verify(callback).onFailure(CredentialsManagerException.BIOMETRIC_ERROR_HW_NOT_PRESENT)
    }

    @Test
    public fun testAuthenticationErrorWithBIOMETRIC_ERROR_NO_BIOMETRICS() {
        val localAuthenticationManager = LocalAuthenticationManager(
            fragmentActivity,
            getAuthenticationOptions(),
            biometricManager,
            callback
        )

        localAuthenticationManager.authenticate()
        localAuthenticationManager.onAuthenticationError(
            BiometricPrompt.ERROR_NO_BIOMETRICS,
            "error"
        )
        verify(callback).onFailure(CredentialsManagerException.BIOMETRIC_ERROR_NO_BIOMETRICS)
    }

    @Test
    public fun testAuthenticationErrorWithBIOMETRIC_ERROR_USER_CANCELED() {
        val localAuthenticationManager = LocalAuthenticationManager(
            fragmentActivity,
            getAuthenticationOptions(),
            biometricManager,
            callback
        )

        localAuthenticationManager.authenticate()
        localAuthenticationManager.onAuthenticationError(
            BiometricPrompt.ERROR_USER_CANCELED,
            "error"
        )
        verify(callback).onFailure(CredentialsManagerException.BIOMETRIC_ERROR_USER_CANCELED)
    }


    @Test
    public fun testAuthenticationErrorWithBIOMETRIC_ERROR_LOCKOUT_PERMANENT() {
        val localAuthenticationManager = LocalAuthenticationManager(
            fragmentActivity,
            getAuthenticationOptions(),
            biometricManager,
            callback
        )

        localAuthenticationManager.authenticate()
        localAuthenticationManager.onAuthenticationError(
            BiometricPrompt.ERROR_LOCKOUT_PERMANENT,
            "error"
        )
        verify(callback).onFailure(CredentialsManagerException.BIOMETRIC_ERROR_LOCKOUT_PERMANENT)
    }

    @Test
    public fun testAuthenticationErrorWithBIOMETRIC_ERROR_VENDOR() {
        val localAuthenticationManager = LocalAuthenticationManager(
            fragmentActivity,
            getAuthenticationOptions(),
            biometricManager,
            callback
        )

        localAuthenticationManager.authenticate()
        localAuthenticationManager.onAuthenticationError(BiometricPrompt.ERROR_VENDOR, "error")
        verify(callback).onFailure(CredentialsManagerException.BIOMETRIC_ERROR_VENDOR)
    }

    @Test
    public fun testAuthenticationErrorWithBIOMETRIC_ERROR_LOCKOUT() {
        val localAuthenticationManager = LocalAuthenticationManager(
            fragmentActivity,
            getAuthenticationOptions(),
            biometricManager,
            callback
        )

        localAuthenticationManager.authenticate()
        localAuthenticationManager.onAuthenticationError(BiometricPrompt.ERROR_LOCKOUT, "error")
        verify(callback).onFailure(CredentialsManagerException.BIOMETRIC_ERROR_LOCKOUT)
    }

    @Test
    public fun testAuthenticationErrorWithBIOMETRIC_ERROR_CANCELED() {
        val localAuthenticationManager = LocalAuthenticationManager(
            fragmentActivity,
            getAuthenticationOptions(),
            biometricManager,
            callback
        )

        localAuthenticationManager.authenticate()
        localAuthenticationManager.onAuthenticationError(BiometricPrompt.ERROR_CANCELED, "error")
        verify(callback).onFailure(CredentialsManagerException.BIOMETRIC_ERROR_CANCELED)
    }

    @Test
    public fun testAuthenticationErrorWithBIOMETRIC_ERROR_NO_SPACE() {
        val localAuthenticationManager = LocalAuthenticationManager(
            fragmentActivity,
            getAuthenticationOptions(),
            biometricManager,
            callback
        )

        localAuthenticationManager.authenticate()
        localAuthenticationManager.onAuthenticationError(BiometricPrompt.ERROR_NO_SPACE, "error")
        verify(callback).onFailure(CredentialsManagerException.BIOMETRIC_ERROR_NO_SPACE)
    }

    @Test
    public fun testAuthenticationErrorWithBIOMETRIC_ERROR_TIMEOUT() {
        val localAuthenticationManager = LocalAuthenticationManager(
            fragmentActivity,
            getAuthenticationOptions(),
            biometricManager,
            callback
        )

        localAuthenticationManager.authenticate()
        localAuthenticationManager.onAuthenticationError(BiometricPrompt.ERROR_TIMEOUT, "error")
        verify(callback).onFailure(CredentialsManagerException.BIOMETRIC_ERROR_TIMEOUT)
    }

    @Test
    public fun testAuthenticationErrorWithBIOMETRIC_ERROR_UNABLE_TO_PROCESS() {
        val localAuthenticationManager = LocalAuthenticationManager(
            fragmentActivity,
            getAuthenticationOptions(),
            biometricManager,
            callback
        )

        localAuthenticationManager.authenticate()
        localAuthenticationManager.onAuthenticationError(
            BiometricPrompt.ERROR_UNABLE_TO_PROCESS,
            "error"
        )
        verify(callback).onFailure(CredentialsManagerException.BIOMETRIC_ERROR_UNABLE_TO_PROCESS)
    }

    @Test
    public fun testAuthenticationErrorWithBIOMETRIC_ERROR_HW_UNAVAILABLE() {
        val localAuthenticationManager = LocalAuthenticationManager(
            fragmentActivity,
            getAuthenticationOptions(),
            biometricManager,
            callback
        )

        localAuthenticationManager.authenticate()
        localAuthenticationManager.onAuthenticationError(
            BiometricPrompt.ERROR_HW_UNAVAILABLE,
            "error"
        )
        verify(callback).onFailure(CredentialsManagerException.BIOMETRIC_ERROR_HW_UNAVAILABLE)
    }

    private fun getAuthenticationOptions(
        title: String = "title",
        description: String = "description",
        subtitle: String = "subtitle",
        negativeButtonText: String = "negativeButtonText",
        authenticator: AuthenticationLevel = AuthenticationLevel.STRONG,
        enableDeviceCredentialFallback: Boolean = false
    ): LocalAuthenticationOptions {

        val builder = LocalAuthenticationOptions.Builder()
        builder.apply {
            setTitle(title)
            setSubTitle(subtitle)
            setDescription(description)
            setNegativeButtonText(negativeButtonText)
            setAuthenticationLevel(authenticator)
            setDeviceCredentialFallback(enableDeviceCredentialFallback)
        }
        return builder.build()
    }
}

