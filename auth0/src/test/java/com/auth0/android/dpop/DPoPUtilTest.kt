package com.auth0.android.dpop

import android.content.Context
import com.auth0.android.request.internal.Jwt
import com.google.gson.internal.LinkedTreeMap
import com.nhaarman.mockitokotlin2.any
import com.nhaarman.mockitokotlin2.mock
import com.nhaarman.mockitokotlin2.never
import com.nhaarman.mockitokotlin2.verify
import com.nhaarman.mockitokotlin2.verifyNoMoreInteractions
import com.nhaarman.mockitokotlin2.whenever
import okhttp3.Response
import org.hamcrest.CoreMatchers.`is`
import org.hamcrest.CoreMatchers.notNullValue
import org.hamcrest.CoreMatchers.nullValue
import org.hamcrest.MatcherAssert.assertThat
import org.junit.Assert
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.security.PrivateKey

@RunWith(RobolectricTestRunner::class)
public class DPoPUtilTest {

    private lateinit var mockContext: Context
    private lateinit var mockPrivateKey: PrivateKey
    private lateinit var mockResponse: Response
    private lateinit var mockKeyStore: DPoPKeyStore

    private val testHttpUrl = "https://api.example.com/resource"
    private val testHttpMethod = "POST"
    private val testAccessToken = "test-access-token"
    private val testNonce = "test-nonce"
    private val fakePrivateKey = FakeECPrivateKey()
    private val fakePublicKey = FakeECPublicKey()
    private val testEncodedAccessToken = "WXSA1LYsphIZPxnnP-TMOtF_C_nPwWp8v0tQZBMcSAU"
    private val testPublicJwkHash = "KQ-r0YQMCm0yVnGippcsZK4zO7oGIjOkNRbvILjjBAo"
    private val testProofJwk =
        "{crv=P-256, kty=EC, x=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE, y=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI}"
    private val algTyp = "dpop+jwt"
    private val alg = "ES256"

    @Before
    public fun setUp() {

        mockKeyStore = mock()
        mockPrivateKey = mock()
        mockContext = mock()
        mockResponse = mock()

        DPoPUtil.keyStore = mockKeyStore
    }

    @Test
    public fun `generateProof should return null when keyStore has no key pair`() {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(false)

        val result = DPoPUtil.generateProof(testHttpUrl, testHttpMethod)

        assertThat(result, `is`(nullValue()))
        verify(mockKeyStore).hasKeyPair()
        verifyNoMoreInteractions(mockKeyStore)
    }

    @Test
    public fun `generateProof should return null when keyStore returns null key pair`() {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(true)
        whenever(mockKeyStore.getKeyPair()).thenReturn(null)

        val result = DPoPUtil.generateProof(testHttpUrl, testHttpMethod)

        assertThat(result, `is`(nullValue()))
        verify(mockKeyStore).hasKeyPair()
        verify(mockKeyStore).getKeyPair()
    }


    @Test
    public fun `generateProof should remove query parameters from URL`() {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(true)
        whenever(mockKeyStore.getKeyPair()).thenReturn(Pair(fakePrivateKey, fakePublicKey))

        val urlWithQuery = "https://api.example.com/resource?param1=value1&param2=value2"
        val expectedCleanUrl = "https://api.example.com/resource"

        val result = DPoPUtil.generateProof(urlWithQuery, testHttpMethod)

        assertThat(result, `is`(notNullValue()))
        val proof = Jwt(result!!)
        Assert.assertEquals(expectedCleanUrl, proof.decodedPayload["htu"] as String)
    }

    @Test
    public fun `generateProof should remove fragment from URL`() {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(true)
        whenever(mockKeyStore.getKeyPair()).thenReturn(Pair(fakePrivateKey, fakePublicKey))

        val urlWithFragment = "https://api.example.com/resource#section1"
        val expectedCleanUrl = "https://api.example.com/resource"

        val result = DPoPUtil.generateProof(urlWithFragment, testHttpMethod)

        assertThat(result, `is`(notNullValue()))
        val proof = Jwt(result!!)
        Assert.assertEquals(expectedCleanUrl, proof.decodedPayload["htu"] as String)
    }

    @Test
    public fun `generateProof should remove both query parameters and fragment from URL`() {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(true)
        whenever(mockKeyStore.getKeyPair()).thenReturn(Pair(fakePrivateKey, fakePublicKey))

        val urlWithQueryAndFragment = "https://api.example.com/resource?param=value#section"
        val expectedCleanUrl = "https://api.example.com/resource"

        val result = DPoPUtil.generateProof(urlWithQueryAndFragment, testHttpMethod)

        assertThat(result, `is`(notNullValue()))
        val proof = Jwt(result!!)
        Assert.assertEquals(expectedCleanUrl, proof.decodedPayload["htu"] as String)
    }

    @Test
    public fun `generateProof should preserve path in URL when cleaning`() {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(true)
        whenever(mockKeyStore.getKeyPair()).thenReturn(Pair(fakePrivateKey, fakePublicKey))

        val urlWithPath = "https://api.example.com/v1/users/123?fields=name,email#profile"
        val expectedCleanUrl = "https://api.example.com/v1/users/123"

        val result = DPoPUtil.generateProof(urlWithPath, testHttpMethod)

        assertThat(result, `is`(notNullValue()))
        val proof = Jwt(result!!)
        Assert.assertEquals(expectedCleanUrl, proof.decodedPayload["htu"] as String)
    }

    @Test
    public fun `generateProof should preserve port in URL when cleaning`() {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(true)
        whenever(mockKeyStore.getKeyPair()).thenReturn(Pair(fakePrivateKey, fakePublicKey))

        val urlWithPort = "https://api.example.com:8443/resource?query=value#fragment"
        val expectedCleanUrl = "https://api.example.com:8443/resource"

        val result = DPoPUtil.generateProof(urlWithPort, testHttpMethod)

        assertThat(result, `is`(notNullValue()))
        val proof = Jwt(result!!)
        Assert.assertEquals(expectedCleanUrl, proof.decodedPayload["htu"] as String)
    }

    @Test
    public fun `generateProof should handle malformed URL gracefully`() {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(true)
        whenever(mockKeyStore.getKeyPair()).thenReturn(Pair(fakePrivateKey, fakePublicKey))

        val malformedUrl = "not-a-valid-url"

        val result = DPoPUtil.generateProof(malformedUrl, testHttpMethod)

        assertThat(result, `is`(notNullValue()))
        val proof = Jwt(result!!)
        // Should use the original URL if parsing fails
        Assert.assertEquals(malformedUrl, proof.decodedPayload["htu"] as String)
    }

    @Test
    public fun `generateProof should handle URL with no path`() {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(true)
        whenever(mockKeyStore.getKeyPair()).thenReturn(Pair(fakePrivateKey, fakePublicKey))

        val urlWithoutPath = "https://api.example.com?query=value#fragment"
        val expectedCleanUrl = "https://api.example.com"

        val result = DPoPUtil.generateProof(urlWithoutPath, testHttpMethod)

        assertThat(result, `is`(notNullValue()))
        val proof = Jwt(result!!)
        Assert.assertEquals(expectedCleanUrl, proof.decodedPayload["htu"] as String)
    }

    @Test
    public fun `generateProof should generate valid proof with minimal parameters`() {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(true)
        whenever(mockKeyStore.getKeyPair()).thenReturn(Pair(fakePrivateKey, fakePublicKey))

        val result = DPoPUtil.generateProof(testHttpUrl, testHttpMethod)

        assertThat(result, `is`(notNullValue()))
        val proof = Jwt(result!!)
        Assert.assertEquals(proof.decodedHeader["typ"] as String, algTyp)
        Assert.assertEquals(proof.decodedHeader["alg"] as String, alg)
        Assert.assertEquals(
            (proof.decodedHeader["jwk"] as LinkedTreeMap<*, *>).toString(),
            testProofJwk
        )
        Assert.assertEquals(proof.decodedPayload["htm"] as String, testHttpMethod)
        Assert.assertEquals(proof.decodedPayload["htu"] as String, testHttpUrl)
        Assert.assertNull(proof.decodedPayload["ath"])
        Assert.assertNull(proof.decodedPayload["nonce"])
    }

    @Test
    public fun `generateProof should include all required header fields`() {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(true)
        whenever(mockKeyStore.getKeyPair()).thenReturn(Pair(fakePrivateKey, fakePublicKey))

        val proof = DPoPUtil.generateProof(testHttpUrl, testHttpMethod)
        assertThat(proof, `is`(notNullValue()))
        val decodedProof = Jwt(proof!!)
        assertNotNull(decodedProof.decodedHeader["typ"])
        assertNotNull(decodedProof.decodedHeader["alg"])
        assertNotNull(decodedProof.decodedHeader["jwk"])
    }

    @Test
    public fun `generateProof should include all required payload fields`() {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(true)
        whenever(mockKeyStore.getKeyPair()).thenReturn(Pair(fakePrivateKey, fakePublicKey))

        val proof =
            DPoPUtil.generateProof(testHttpUrl, testHttpMethod, testAccessToken, testNonce)
        assertThat(proof, `is`(notNullValue()))
        val decodedProof = Jwt(proof!!)
        assertNotNull(decodedProof.decodedPayload["jti"])
        assertNotNull(decodedProof.decodedPayload["htm"])
        assertNotNull(decodedProof.decodedPayload["htu"])
        assertNotNull(decodedProof.decodedPayload["iat"])
        assertNotNull(decodedProof.decodedPayload["ath"])
        assertNotNull(decodedProof.decodedPayload["nonce"])
    }

    @Test
    public fun `generateProof should generate valid proof with access token`() {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(true)
        whenever(mockKeyStore.getKeyPair()).thenReturn(Pair(fakePrivateKey, fakePublicKey))

        val result = DPoPUtil.generateProof(testHttpUrl, testHttpMethod, testAccessToken)

        assertThat(result, `is`(notNullValue()))
        val proof = Jwt(result!!)

        Assert.assertEquals(proof.decodedHeader["typ"] as String, algTyp)
        Assert.assertEquals(proof.decodedHeader["alg"] as String, alg)
        Assert.assertEquals(
            (proof.decodedHeader["jwk"] as LinkedTreeMap<*, *>).toString(),
            testProofJwk
        )
        Assert.assertEquals(proof.decodedPayload["htm"] as String, testHttpMethod)
        Assert.assertEquals(proof.decodedPayload["htu"] as String, testHttpUrl)
        Assert.assertEquals(proof.decodedPayload["ath"] as String, testEncodedAccessToken)
        Assert.assertNull(proof.decodedPayload["nonce"])
    }

    @Test
    public fun `generateProof should generate valid proof with nonce`() {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(true)
        whenever(mockKeyStore.getKeyPair()).thenReturn(Pair(fakePrivateKey, fakePublicKey))

        val result =
            DPoPUtil.generateProof(testHttpUrl, testHttpMethod, testAccessToken, testNonce)

        assertThat(result, `is`(notNullValue()))
        assertThat(result, `is`(notNullValue()))
        val proof = Jwt(result!!)

        Assert.assertEquals(proof.decodedHeader["typ"] as String, algTyp)
        Assert.assertEquals(proof.decodedHeader["alg"] as String, alg)
        Assert.assertEquals(
            (proof.decodedHeader["jwk"] as LinkedTreeMap<*, *>).toString(),
            testProofJwk
        )
        Assert.assertEquals(proof.decodedPayload["htm"] as String, testHttpMethod)
        Assert.assertEquals(proof.decodedPayload["htu"] as String, testHttpUrl)
        Assert.assertEquals(proof.decodedPayload["ath"] as String, testEncodedAccessToken)
        Assert.assertEquals(proof.decodedPayload["nonce"] as String, testNonce)
    }


    @Test
    public fun `generateProof should throw DPoPException when signature fails`() {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(true)
        whenever(mockKeyStore.getKeyPair()).thenReturn(Pair(mockPrivateKey, fakePublicKey))
        val exception = assertThrows(DPoPException::class.java) {
            DPoPUtil.generateProof(testHttpUrl, testHttpMethod)
        }
        Assert.assertEquals("Error while signing the DPoP proof.", exception.message)
    }

    @Test
    public fun `clearKeyPair should delegate to keyStore`() {
        DPoPUtil.clearKeyPair()
        verify(mockKeyStore).deleteKeyPair()
    }

    @Test
    public fun `clearKeyPair should propagate DPoPException from keyStore`() {
        whenever(mockKeyStore.deleteKeyPair()).thenThrow(DPoPException(DPoPException.Code.KEY_STORE_ERROR))
        val exception = assertThrows(DPoPException::class.java) {
            DPoPUtil.clearKeyPair()
        }
        Assert.assertEquals(
            "Error while accessing the key pair in the keystore.",
            exception.message
        )
    }

    @Test
    public fun `getPublicKeyJWK should return null when no key pair exists`() {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(false)
        val result = DPoPUtil.getPublicKeyJWK()
        assertThat(result, `is`(nullValue()))
        verify(mockKeyStore).hasKeyPair()
        verifyNoMoreInteractions(mockKeyStore)
    }

    @Test
    public fun `getPublicKeyJWK should return null when key pair is null`() {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(true)
        whenever(mockKeyStore.getKeyPair()).thenReturn(null)
        val result = DPoPUtil.getPublicKeyJWK()
        assertThat(result, `is`(nullValue()))
        verify(mockKeyStore).hasKeyPair()
        verify(mockKeyStore).getKeyPair()
    }

    @Test
    public fun `getPublicKeyJWK should return null when public key is not ECPublicKey`() {
        val mockNonECKey = mock<java.security.PublicKey>()
        whenever(mockKeyStore.hasKeyPair()).thenReturn(true)
        whenever(mockKeyStore.getKeyPair()).thenReturn(Pair(mockPrivateKey, mockNonECKey))
        val result = DPoPUtil.getPublicKeyJWK()
        assertThat(result, `is`(nullValue()))
        verify(mockKeyStore).hasKeyPair()
        verify(mockKeyStore).getKeyPair()
    }

    @Test
    public fun `getPublicKeyJWK should return hash of JWK when valid ECPublicKey exists`() {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(true)
        whenever(mockKeyStore.getKeyPair()).thenReturn(Pair(fakePrivateKey, fakePublicKey))

        val result = DPoPUtil.getPublicKeyJWK()

        assertThat(result, `is`(notNullValue()))
        assertThat(result, `is`(testPublicJwkHash))
    }

    @Test
    public fun `generateKeyPair should return early when key pair already exists`() {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(true)
        DPoPUtil.generateKeyPair(mockContext)
        verify(mockKeyStore).hasKeyPair()
        verify(mockKeyStore, never()).generateKeyPair(any())
    }

    @Test
    public fun `generateKeyPair should generate new key pair when none exists`() {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(false)
        DPoPUtil.generateKeyPair(mockContext)
        verify(mockKeyStore).hasKeyPair()
        verify(mockKeyStore).generateKeyPair(mockContext)
    }

    @Test
    public fun `generateKeyPair should propagate DPoPException from keyStore`() {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(false)
        whenever(mockKeyStore.generateKeyPair(mockContext)).thenThrow(DPoPException(DPoPException.Code.KEY_GENERATION_ERROR))

        val exception = assertThrows(DPoPException::class.java) {
            DPoPUtil.generateKeyPair(mockContext)
        }
        Assert.assertEquals("Error generating DPoP key pair.", exception.message)
    }
}