package com.auth0.android.dpop

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import com.nhaarman.mockitokotlin2.any
import com.nhaarman.mockitokotlin2.anyOrNull
import com.nhaarman.mockitokotlin2.mock
import com.nhaarman.mockitokotlin2.never
import com.nhaarman.mockitokotlin2.verify
import com.nhaarman.mockitokotlin2.whenever
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.Matchers.`is`
import org.hamcrest.Matchers.notNullValue
import org.hamcrest.Matchers.nullValue
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.Mockito.doNothing
import org.powermock.api.mockito.PowerMockito
import org.powermock.core.classloader.annotations.PrepareForTest
import org.powermock.modules.junit4.PowerMockRunner
import org.powermock.reflect.Whitebox
import java.security.InvalidAlgorithmParameterException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.Certificate
import javax.security.auth.x500.X500Principal

/**
 * Using a subclass of [DPoPKeyStore] to help with mocking the lazy initialized keyStore property
 */
internal class MockableDPoPKeyStore(private val mockKeyStore: KeyStore) : DPoPKeyStore() {
    override val keyStore: KeyStore by lazy { mockKeyStore }
}

@RunWith(PowerMockRunner::class)
@PrepareForTest(
    DPoPKeyStore::class,
    KeyStore::class,
    KeyPairGenerator::class,
    KeyGenParameterSpec.Builder::class,
    Build.VERSION::class,
    X500Principal::class,
    Log::class
)
public class DPoPKeyStoreTest {

    private lateinit var mockKeyStore: KeyStore
    private lateinit var mockKeyPairGenerator: KeyPairGenerator
    private lateinit var mockContext: Context
    private lateinit var mockPackageManager: PackageManager
    private lateinit var mockSpecBuilder: KeyGenParameterSpec.Builder

    private lateinit var dpopKeyStore: DPoPKeyStore

    @Before
    public fun setUp() {

        mockKeyStore = mock()
        mockKeyPairGenerator = mock()
        mockContext = mock()
        mockPackageManager = mock()
        mockSpecBuilder = mock()

        PowerMockito.mockStatic(KeyStore::class.java)
        PowerMockito.mockStatic(KeyPairGenerator::class.java)
        PowerMockito.mockStatic(Log::class.java)
        PowerMockito.mockStatic(Build.VERSION::class.java)
        Whitebox.setInternalState(Build.VERSION::class.java, "SDK_INT", Build.VERSION_CODES.P)

        PowerMockito.whenNew(KeyGenParameterSpec.Builder::class.java).withAnyArguments()
            .thenReturn(mockSpecBuilder)

        PowerMockito.`when`(KeyStore.getInstance("AndroidKeyStore")).thenReturn(mockKeyStore)
        doNothing().whenever(mockKeyStore).load(anyOrNull())
        PowerMockito.`when`(
            KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                "AndroidKeyStore"
            )
        ).thenReturn(mockKeyPairGenerator)

        whenever(mockSpecBuilder.setAlgorithmParameterSpec(any())).thenReturn(mockSpecBuilder)
        whenever(mockSpecBuilder.setDigests(any())).thenReturn(mockSpecBuilder)
        whenever(mockSpecBuilder.setCertificateSubject(any())).thenReturn(mockSpecBuilder)
        whenever(mockSpecBuilder.setCertificateNotBefore(any())).thenReturn(mockSpecBuilder)
        whenever(mockSpecBuilder.setCertificateNotAfter(any())).thenReturn(mockSpecBuilder)
        whenever(mockSpecBuilder.setIsStrongBoxBacked(any())).thenReturn(mockSpecBuilder)
        whenever(mockContext.packageManager).thenReturn(mockPackageManager)
        whenever(mockPackageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)).thenReturn(
            true
        )

        dpopKeyStore = MockableDPoPKeyStore(mockKeyStore)
    }

    @Test
    public fun `generateKeyPair should generate a key pair successfully`() {
        whenever(mockPackageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)).thenReturn(
            false
        )
        dpopKeyStore.generateKeyPair(mockContext)

        verify(mockKeyPairGenerator).initialize(mockSpecBuilder.build())
        verify(mockKeyPairGenerator).generateKeyPair()
        verify(mockSpecBuilder, never()).setIsStrongBoxBacked(true)
    }

    @Test
    public fun `generateKeyPair should enable StrongBox when available`() {
        dpopKeyStore.generateKeyPair(mockContext)
        verify(mockSpecBuilder).setIsStrongBoxBacked(true)
    }

    @Test
    public fun `generateKeyPair should throw KEY_GENERATION_ERROR when failed to generate key pair`() {
        val cause = InvalidAlgorithmParameterException("Exception")
        PowerMockito.`when`(
            mockKeyPairGenerator.initialize(mockSpecBuilder.build())
        ).thenThrow(cause)

        val exception = assertThrows(DPoPException::class.java) {
            dpopKeyStore.generateKeyPair(mockContext)
        }
        assertEquals(exception.message, DPoPException.KEY_GENERATION_ERROR.message)
        assertThat(exception.cause, `is`(cause))
    }

    @Test
    public fun `generateKeyPair should throw UNKNOWN_ERROR when any unhandled exception occurs`() {
        val cause = RuntimeException("Exception")
        PowerMockito.`when`(
            mockKeyPairGenerator.initialize(mockSpecBuilder.build())
        ).thenThrow(cause)

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
}