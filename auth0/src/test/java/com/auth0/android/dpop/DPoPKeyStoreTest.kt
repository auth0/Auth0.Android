package com.auth0.android.dpop

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.Matchers.`is`
import org.hamcrest.Matchers.notNullValue
import org.hamcrest.Matchers.nullValue
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.MockedStatic
import org.mockito.Mockito
import org.mockito.Mockito.doNothing
import org.mockito.Mockito.times
import org.mockito.Mockito.`when`
import org.mockito.kotlin.any
import org.mockito.kotlin.anyOrNull
import org.mockito.kotlin.argumentCaptor
import org.mockito.kotlin.mock
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.security.InvalidAlgorithmParameterException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.PrivateKey
import java.security.ProviderException
import java.security.PublicKey
import java.security.cert.Certificate

/**
 * Using a subclass of [DPoPKeyStore] to help with mocking the lazy initialized keyStore property
 */
internal class MockableDPoPKeyStore(private val mockKeyStore: KeyStore) : DPoPKeyStore() {
    override val keyStore: KeyStore by lazy { mockKeyStore }
}

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [Build.VERSION_CODES.P])
public class DPoPKeyStoreTest {

    private lateinit var mockKeyStore: KeyStore
    private lateinit var mockKeyPairGenerator: KeyPairGenerator
    private lateinit var mockContext: Context
    private lateinit var mockPackageManager: PackageManager

    private lateinit var dpopKeyStore: DPoPKeyStore

    private lateinit var keyStoreMock: MockedStatic<KeyStore>
    private lateinit var keyPairGeneratorMock: MockedStatic<KeyPairGenerator>

    @Before
    public fun setUp() {

        mockKeyStore = mock()
        mockKeyPairGenerator = mock()
        mockContext = mock()
        mockPackageManager = mock()

        keyStoreMock = Mockito.mockStatic(KeyStore::class.java)
        keyPairGeneratorMock = Mockito.mockStatic(KeyPairGenerator::class.java)

        keyStoreMock.`when`<KeyStore> { KeyStore.getInstance("AndroidKeyStore") }
            .thenReturn(mockKeyStore)
        doNothing().whenever(mockKeyStore).load(anyOrNull())
        keyPairGeneratorMock.`when`<KeyPairGenerator> {
            KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                "AndroidKeyStore"
            )
        }.thenReturn(mockKeyPairGenerator)

        whenever(mockContext.packageManager).thenReturn(mockPackageManager)
        whenever(mockPackageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)).thenReturn(
            true
        )

        dpopKeyStore = MockableDPoPKeyStore(mockKeyStore)
    }

    @After
    public fun tearDown() {
        keyStoreMock.close()
        keyPairGeneratorMock.close()
    }

    @Test
    public fun `generateKeyPair should generate a key pair successfully`() {
        whenever(mockPackageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)).thenReturn(
            false
        )
        dpopKeyStore.generateKeyPair(mockContext)

        verify(mockKeyPairGenerator).initialize(anyOrNull<KeyGenParameterSpec>())
        verify(mockKeyPairGenerator).generateKeyPair()
    }

    @Test
    public fun `generateKeyPair should enable StrongBox when available`() {
        val specCaptor = argumentCaptor<KeyGenParameterSpec>()

        dpopKeyStore.generateKeyPair(mockContext)

        verify(mockKeyPairGenerator).initialize(specCaptor.capture())
        verify(mockKeyPairGenerator).generateKeyPair()

        assertThat(specCaptor.firstValue.isStrongBoxBacked, `is`(true))
    }

    @Test
    public fun `generateKeyPair should throw KEY_GENERATION_ERROR when failed to generate key pair`() {
        val cause = InvalidAlgorithmParameterException("Exception")
        `when`(mockKeyPairGenerator.initialize(anyOrNull<KeyGenParameterSpec>())).thenThrow(cause)

        val exception = assertThrows(DPoPException::class.java) {
            dpopKeyStore.generateKeyPair(mockContext)
        }
        assertEquals(exception.message, DPoPException.KEY_GENERATION_ERROR.message)
        assertThat(exception.cause, `is`(cause))
    }

    @Test
    public fun `generateKeyPair should throw UNKNOWN_ERROR when any unhandled exception occurs`() {
        val cause = RuntimeException("Exception")
        `when`(mockKeyPairGenerator.initialize(anyOrNull<KeyGenParameterSpec>())).thenThrow(cause)

        val exception = assertThrows(DPoPException::class.java) {
            dpopKeyStore.generateKeyPair(mockContext)
        }
        assertEquals(exception.message, DPoPException.UNKNOWN_ERROR.message)
        assertThat(exception.cause, `is`(cause))
    }

    @Test
    public fun `getKeyPair should return key pair when it exists`() {
        val mockPrivateKey = mock<PrivateKey>()
        val mockPublicKey = mock<PublicKey>()
        val mockCertificate = mock<Certificate>()

        whenever(mockKeyStore.getKey(any(), anyOrNull())).thenReturn(mockPrivateKey)
        whenever(mockKeyStore.getCertificate(any())).thenReturn(mockCertificate)
        whenever(mockCertificate.publicKey).thenReturn(mockPublicKey)

        val keyPair = dpopKeyStore.getKeyPair()

        assertThat(keyPair, `is`(notNullValue()))
        assertThat(keyPair!!.first, `is`(mockPrivateKey))
        assertThat(keyPair.second, `is`(mockPublicKey))
    }

    @Test
    public fun `getKeyPair should return null when certificate is null`() {
        val mockPrivateKey = mock<PrivateKey>()
        whenever(mockKeyStore.getKey(any(), anyOrNull())).thenReturn(mockPrivateKey)
        whenever(mockKeyStore.getCertificate(any())).thenReturn(null)

        val keyPair = dpopKeyStore.getKeyPair()
        assertThat(keyPair, `is`(nullValue()))
    }

    @Test
    public fun `getKeyPair should throw KEY_STORE_ERROR on KeyStoreException`() {
        val cause = KeyStoreException("Test Exception")
        whenever(mockKeyStore.getKey(any(), anyOrNull())).thenThrow(cause)

        val exception = assertThrows(DPoPException::class.java) {
            dpopKeyStore.getKeyPair()
        }
        assertEquals(exception.message, DPoPException.KEY_STORE_ERROR.message)
        assertThat(exception.cause, `is`(cause))
    }

    @Test
    public fun `hasKeyPair should return true when alias exists`() {
        whenever(mockKeyStore.containsAlias(any())).thenReturn(true)
        val result = dpopKeyStore.hasKeyPair()
        assertThat(result, `is`(true))
    }

    @Test
    public fun `hasKeyPair should return false when alias does not exist`() {
        whenever(mockKeyStore.containsAlias(any())).thenReturn(false)
        val result = dpopKeyStore.hasKeyPair()
        assertThat(result, `is`(false))
    }

    @Test
    public fun `hasKeyPair should throw KEY_STORE_ERROR on KeyStoreException`() {
        val cause = KeyStoreException("Test Exception")
        whenever(mockKeyStore.containsAlias(any())).thenThrow(cause)

        val exception = assertThrows(DPoPException::class.java) {
            dpopKeyStore.hasKeyPair()
        }
        assertEquals(exception.message, DPoPException.KEY_STORE_ERROR.message)
        assertThat(exception.cause, `is`(cause))
    }

    @Test
    public fun `deleteKeyPair should call deleteEntry`() {
        dpopKeyStore.deleteKeyPair()
        verify(mockKeyStore).deleteEntry(any())
    }

    @Test
    public fun `deleteKeyPair should throw KEY_STORE_ERROR on KeyStoreException`() {
        val cause = KeyStoreException("Test Exception")
        whenever(mockKeyStore.deleteEntry(any())).thenThrow(cause)

        val exception = assertThrows(DPoPException::class.java) {
            dpopKeyStore.deleteKeyPair()
        }
        assertEquals(exception.message, DPoPException.KEY_STORE_ERROR.message)
        assertThat(exception.cause, `is`(cause))
    }

    @Test
    public fun `generateKeyPair should retry without StrongBox when ProviderException occurs with StrongBox enabled`() {
        val providerException = ProviderException("StrongBox attestation failed")
        val specCaptor = argumentCaptor<KeyGenParameterSpec>()

        `when`(mockKeyPairGenerator.generateKeyPair()).thenThrow(providerException)
            .thenReturn(mock())

        dpopKeyStore.generateKeyPair(mockContext)

        verify(mockKeyPairGenerator, times(2)).initialize(specCaptor.capture())
        verify(mockKeyPairGenerator, times(2)).generateKeyPair()

        assertThat(specCaptor.allValues[0].isStrongBoxBacked, `is`(true))
        assertThat(specCaptor.allValues[1].isStrongBoxBacked, `is`(false))
    }

    @Test
    public fun `generateKeyPair should throw KEY_GENERATION_ERROR when ProviderException occurs without StrongBox`() {
        val providerException = ProviderException("Key generation failed")
        `when`(mockKeyPairGenerator.initialize(anyOrNull<KeyGenParameterSpec>())).thenThrow(
            providerException
        )

        val exception = assertThrows(DPoPException::class.java) {
            dpopKeyStore.generateKeyPair(mockContext, useStrongBox = false)
        }

        assertEquals(DPoPException.KEY_GENERATION_ERROR.message, exception.message)
        assertThat(exception.cause, `is`(providerException))

        verify(mockKeyPairGenerator, times(1)).initialize(anyOrNull<KeyGenParameterSpec>())
    }

    @Test
    public fun `generateKeyPair should throw KEY_GENERATION_ERROR when ProviderException occurs on retry`() {
        val firstException = ProviderException("StrongBox failed")
        val secondException = ProviderException("Retry also failed")

        `when`(mockKeyPairGenerator.initialize(anyOrNull<KeyGenParameterSpec>()))
            .thenThrow(firstException)
            .thenThrow(secondException)

        val exception = assertThrows(DPoPException::class.java) {
            dpopKeyStore.generateKeyPair(mockContext, useStrongBox = true)
        }

        assertEquals(DPoPException.KEY_GENERATION_ERROR.message, exception.message)
        assertThat(exception.cause, `is`(secondException))

        verify(mockKeyPairGenerator, times(2)).initialize(anyOrNull<KeyGenParameterSpec>())
    }
}