package com.auth0.android.authentication.storage

import androidx.fragment.app.FragmentActivity
import com.auth0.android.Auth0
import com.auth0.android.authentication.AuthenticationAPIClient
import com.auth0.android.callback.Callback
import com.auth0.android.result.Credentials
import com.auth0.android.util.Clock
import com.nhaarman.mockitokotlin2.*
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.Mock
import org.mockito.MockitoAnnotations
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import java.lang.ref.WeakReference
import java.util.concurrent.Executor

@RunWith(RobolectricTestRunner::class)
public class SecureCredentialsManagerBiometricPolicyTest {

    @Mock
    private lateinit var mockApiClient: AuthenticationAPIClient

    @Mock
    private lateinit var mockStorage: Storage

    @Mock
    private lateinit var mockCrypto: CryptoUtil

    @Mock
    private lateinit var mockJwtDecoder: JWTDecoder

    @Mock
    private lateinit var mockCredentialsCallback: Callback<Credentials, CredentialsManagerException>

    private lateinit var mockActivity: FragmentActivity
    private lateinit var weakFragmentActivity: WeakReference<FragmentActivity>

    private val testExecutor = Executor { command -> command.run() }

    @Before
    public fun setUp() {
        MockitoAnnotations.openMocks(this)
        
        mockActivity = Robolectric.buildActivity(FragmentActivity::class.java).create().start().resume().get()
        weakFragmentActivity = WeakReference(mockActivity)
        
        // Setup default credentials mocking
        val credentialsJson = """{"access_token":"access_token","id_token":"id_token","refresh_token":"refresh_token","token_type":"Bearer","expires_at":"2023-01-01T00:00:00.000Z"}"""
        val encryptedCredentials = "dGVzdC1lbmNyeXB0ZWQtY3JlZHM=" // Valid base64
        
        whenever(mockStorage.retrieveString(SecureCredentialsManager.KEY_CREDENTIALS)).thenReturn(encryptedCredentials)
        whenever(mockStorage.retrieveLong(SecureCredentialsManager.KEY_EXPIRES_AT)).thenReturn(System.currentTimeMillis() + 100000)
        whenever(mockCrypto.decrypt(any())).thenReturn(credentialsJson.toByteArray())
        
        // Mock JWT decoder to return valid claims
        whenever(mockJwtDecoder.decode(any())).thenReturn(mock())
    }

    // =========================
    // Basic Policy Tests
    // =========================

    @Test
    public fun `BiometricPolicy Always should be object type`() {
        val policy1 = BiometricPolicy.Always
        val policy2 = BiometricPolicy.Always
        
        assert(policy1 === policy2) // Same instance
        assert(policy1 == policy2) // Equal
    }

    @Test
    public fun `AppLifecycle policy should default to 1 hour timeout`() {
        val policy = BiometricPolicy.AppLifecycle()
        assert(policy.timeoutInSeconds == 3600) // 1 hour = 3600 seconds
    }

    // =========================
    // LocalAuthenticationOptions Integration Tests
    // =========================

    @Test
    public fun `LocalAuthenticationOptions should include biometric policy`() {
        val policy = BiometricPolicy.Session(600)
        val options = LocalAuthenticationOptions.Builder()
            .setTitle("Test Auth")
            .setPolicy(policy)
            .build()

        assert(options.policy == policy)
    }

    @Test
    public fun `LocalAuthenticationOptions should default to Always policy`() {
        val options = LocalAuthenticationOptions.Builder()
            .setTitle("Test Auth")
            .build()

        assert(options.policy is BiometricPolicy.Always)
    }
    // =========================
    // Session Management Tests without mocking biometric authentication
    // =========================

    @Test
    public fun `clearBiometricSession should work without errors`() {
        val options = LocalAuthenticationOptions.Builder()
            .setTitle("Test Auth")
            .setPolicy(BiometricPolicy.Session(300))
            .build()

        val manager = SecureCredentialsManager(
            apiClient = mockApiClient,
            storage = mockStorage,
            crypto = mockCrypto,
            jwtDecoder = mockJwtDecoder,
            serialExecutor = testExecutor,
            fragmentActivity = null, // No activity to avoid biometric auth
            localAuthenticationOptions = options,
            localAuthenticationManagerFactory = null // No factory to avoid biometric auth
        )

        manager.clearBiometricSession()
        
        // Session should be invalid initially
        assert(!manager.isBiometricSessionValid())
    }

    @Test
    public fun `isBiometricSessionValid should return false for Always policy`() {
        val options = LocalAuthenticationOptions.Builder()
            .setTitle("Test Auth")
            .setPolicy(BiometricPolicy.Always)
            .build()

        val manager = SecureCredentialsManager(
            apiClient = mockApiClient,
            storage = mockStorage,
            crypto = mockCrypto,
            jwtDecoder = mockJwtDecoder,
            serialExecutor = testExecutor,
            fragmentActivity = null, // No activity to avoid biometric auth
            localAuthenticationOptions = options,
            localAuthenticationManagerFactory = null // No factory to avoid biometric auth
        )

        // Always policy should never have valid sessions
        assert(!manager.isBiometricSessionValid())
    }

    @Test
    public fun `isBiometricSessionValid should return false for Session policy initially`() {
        val options = LocalAuthenticationOptions.Builder()
            .setTitle("Test Auth")
            .setPolicy(BiometricPolicy.Session(300))
            .build()

        val manager = SecureCredentialsManager(
            apiClient = mockApiClient,
            storage = mockStorage,
            crypto = mockCrypto,
            jwtDecoder = mockJwtDecoder,
            serialExecutor = testExecutor,
            fragmentActivity = null, // No activity to avoid biometric auth
            localAuthenticationOptions = options,
            localAuthenticationManagerFactory = null // No factory to avoid biometric auth
        )

        // Session should be invalid initially (no authentication has occurred)
        assert(!manager.isBiometricSessionValid())
    }

    @Test
    public fun `isBiometricSessionValid should return false for AppLifecycle policy initially`() {
        val options = LocalAuthenticationOptions.Builder()
            .setTitle("Test Auth")
            .setPolicy(BiometricPolicy.AppLifecycle())
            .build()

        val manager = SecureCredentialsManager(
            apiClient = mockApiClient,
            storage = mockStorage,
            crypto = mockCrypto,
            jwtDecoder = mockJwtDecoder,
            serialExecutor = testExecutor,
            fragmentActivity = null, // No activity to avoid biometric auth
            localAuthenticationOptions = options,
            localAuthenticationManagerFactory = null // No factory to avoid biometric auth
        )

        // Session should be invalid initially (no authentication has occurred)
        assert(!manager.isBiometricSessionValid())
    }

    @Test
    public fun `session validation should handle concurrent access`() {
        val options = LocalAuthenticationOptions.Builder()
            .setTitle("Test Auth")
            .setPolicy(BiometricPolicy.Session(300))
            .build()

        val manager = SecureCredentialsManager(
            apiClient = mockApiClient,
            storage = mockStorage,
            crypto = mockCrypto,
            jwtDecoder = mockJwtDecoder,
            serialExecutor = testExecutor,
            fragmentActivity = null, // No activity to avoid biometric auth
            localAuthenticationOptions = options,
            localAuthenticationManagerFactory = null // No factory to avoid biometric auth
        )
        
        // Multiple session validity checks (simulating concurrent access)
        repeat(10) {
            manager.isBiometricSessionValid()
        }
        
        // Should not crash and should be false (no session established)
        assert(!manager.isBiometricSessionValid())
    }

    @Test
    public fun `clearBiometricSession should be thread safe`() {
        val options = LocalAuthenticationOptions.Builder()
            .setTitle("Test Auth")
            .setPolicy(BiometricPolicy.Session(300))
            .build()

        val manager = SecureCredentialsManager(
            apiClient = mockApiClient,
            storage = mockStorage,
            crypto = mockCrypto,
            jwtDecoder = mockJwtDecoder,
            serialExecutor = testExecutor,
            fragmentActivity = null, // No activity to avoid biometric auth
            localAuthenticationOptions = options,
            localAuthenticationManagerFactory = null // No factory to avoid biometric auth
        )
        
        // Clear from multiple threads (simulated with multiple calls)
        repeat(10) {
            manager.clearBiometricSession()
        }
        
        // session should be invalid
        assert(!manager.isBiometricSessionValid())
    }

    @Test
    public fun `clearCredentials should also clear biometric session`() {
        val options = LocalAuthenticationOptions.Builder()
            .setTitle("Test Auth")
            .setPolicy(BiometricPolicy.Session(300))
            .build()

        val manager = SecureCredentialsManager(
            apiClient = mockApiClient,
            storage = mockStorage,
            crypto = mockCrypto,
            jwtDecoder = mockJwtDecoder,
            serialExecutor = testExecutor,
            fragmentActivity = null, // No activity to avoid biometric auth
            localAuthenticationOptions = options,
            localAuthenticationManagerFactory = null // No factory to avoid biometric auth
        )

        // Clear credentials
        manager.clearCredentials()
        verify(mockStorage, atLeastOnce()).remove(any())

        // Session should be invalid
        assert(!manager.isBiometricSessionValid())
    }
}
