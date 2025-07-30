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
import okhttp3.Headers
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
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
public class DPoPProviderTest {

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

        DPoPProvider.keyStore = mockKeyStore
    }

    @Test
    public fun `generateProof should return null when keyStore has no key pair`() {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(false)

        val result = DPoPProvider.generateProof(testHttpUrl, testHttpMethod)

        assertThat(result, `is`(nullValue()))
        verify(mockKeyStore).hasKeyPair()
        verifyNoMoreInteractions(mockKeyStore)
    }

    @Test
    public fun `generateProof should return null when keyStore returns null key pair`() {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(true)
        whenever(mockKeyStore.getKeyPair()).thenReturn(null)

        val result = DPoPProvider.generateProof(testHttpUrl, testHttpMethod)

        assertThat(result, `is`(nullValue()))
        verify(mockKeyStore).hasKeyPair()
        verify(mockKeyStore).getKeyPair()
    }

    @Test
    public fun `generateProof should generate valid proof with minimal parameters`() {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(true)
        whenever(mockKeyStore.getKeyPair()).thenReturn(Pair(fakePrivateKey, fakePublicKey))

        val result = DPoPProvider.generateProof(testHttpUrl, testHttpMethod)

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

        val proof = DPoPProvider.generateProof(testHttpUrl, testHttpMethod)
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
            DPoPProvider.generateProof(testHttpUrl, testHttpMethod, testAccessToken, testNonce)
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

        val result = DPoPProvider.generateProof(testHttpUrl, testHttpMethod, testAccessToken)

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
            DPoPProvider.generateProof(testHttpUrl, testHttpMethod, testAccessToken, testNonce)

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
            DPoPProvider.generateProof(testHttpUrl, testHttpMethod)
        }
        Assert.assertEquals("Error while signing the DPoP proof.", exception.message)
    }

    @Test
    public fun `clearKeyPair should delegate to keyStore`() {
        DPoPProvider.clearKeyPair()
        verify(mockKeyStore).deleteKeyPair()
    }

    @Test
    public fun `clearKeyPair should propagate DPoPException from keyStore`() {
        whenever(mockKeyStore.deleteKeyPair()).thenThrow(DPoPException(DPoPException.Code.KEY_STORE_ERROR))
        val exception = assertThrows(DPoPException::class.java) {
            DPoPProvider.clearKeyPair()
        }
        Assert.assertEquals(
            "Error while accessing the key pair in the keystore.",
            exception.message
        )
    }

    @Test
    public fun `getPublicKeyJWK should return null when no key pair exists`() {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(false)
        val result = DPoPProvider.getPublicKeyJWK()
        assertThat(result, `is`(nullValue()))
        verify(mockKeyStore).hasKeyPair()
        verifyNoMoreInteractions(mockKeyStore)
    }

    @Test
    public fun `getPublicKeyJWK should return null when key pair is null`() {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(true)
        whenever(mockKeyStore.getKeyPair()).thenReturn(null)
        val result = DPoPProvider.getPublicKeyJWK()
        assertThat(result, `is`(nullValue()))
        verify(mockKeyStore).hasKeyPair()
        verify(mockKeyStore).getKeyPair()
    }

    @Test
    public fun `getPublicKeyJWK should return null when public key is not ECPublicKey`() {
        val mockNonECKey = mock<java.security.PublicKey>()
        whenever(mockKeyStore.hasKeyPair()).thenReturn(true)
        whenever(mockKeyStore.getKeyPair()).thenReturn(Pair(mockPrivateKey, mockNonECKey))
        val result = DPoPProvider.getPublicKeyJWK()
        assertThat(result, `is`(nullValue()))
        verify(mockKeyStore).hasKeyPair()
        verify(mockKeyStore).getKeyPair()
    }

    @Test
    public fun `getPublicKeyJWK should return hash of JWK when valid ECPublicKey exists`() {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(true)
        whenever(mockKeyStore.getKeyPair()).thenReturn(Pair(fakePrivateKey, fakePublicKey))

        val result = DPoPProvider.getPublicKeyJWK()

        assertThat(result, `is`(notNullValue()))
        assertThat(result, `is`(testPublicJwkHash))
    }

    @Test
    public fun `generateKeyPair should return early when key pair already exists`() {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(true)
        DPoPProvider.generateKeyPair(mockContext)
        verify(mockKeyStore).hasKeyPair()
        verify(mockKeyStore, never()).generateKeyPair(any())
    }

    @Test
    public fun `generateKeyPair should generate new key pair when none exists`() {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(false)
        DPoPProvider.generateKeyPair(mockContext)
        verify(mockKeyStore).hasKeyPair()
        verify(mockKeyStore).generateKeyPair(mockContext)
    }

    @Test
    public fun `generateKeyPair should propagate DPoPException from keyStore`() {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(false)
        whenever(mockKeyStore.generateKeyPair(mockContext)).thenThrow(DPoPException(DPoPException.Code.KEY_GENERATION_ERROR))

        val exception = assertThrows(DPoPException::class.java) {
            DPoPProvider.generateKeyPair(mockContext)
        }
        Assert.assertEquals("Error generating DPoP key pair.", exception.message)
    }

    @Test
    public fun `getHeaderData should return bearer token when tokenType is not DPoP`() {
        val tokenType = "Bearer"
        val result =
            DPoPProvider.getHeaderData(testHttpMethod, testHttpUrl, testAccessToken, tokenType)
        assertThat(result.authorizationHeader, `is`("Bearer $testAccessToken"))
        assertThat(result.dpopProof, `is`(nullValue()))
    }

    @Test
    public fun `getHeaderData should return DPoP token with proof when tokenType is DPoP`() {
        val tokenType = "DPoP"
        whenever(mockKeyStore.hasKeyPair()).thenReturn(true)
        whenever(mockKeyStore.getKeyPair()).thenReturn(Pair(fakePrivateKey, fakePublicKey))

        val result =
            DPoPProvider.getHeaderData(testHttpMethod, testHttpUrl, testAccessToken, tokenType)

        assertThat(result.authorizationHeader, `is`("DPoP $testAccessToken"))
        assertThat(result.dpopProof, `is`(notNullValue()))
        val proof = Jwt(result.dpopProof!!)

        Assert.assertEquals(proof.decodedHeader["typ"] as String, algTyp)
        Assert.assertEquals(proof.decodedHeader["alg"] as String, alg)
        Assert.assertEquals(
            (proof.decodedHeader["jwk"] as LinkedTreeMap<*, *>).toString(),
            testProofJwk
        )
        Assert.assertEquals(proof.decodedPayload["htm"] as String, testHttpMethod)
        Assert.assertEquals(proof.decodedPayload["htu"] as String, testHttpUrl)
        Assert.assertEquals(proof.decodedPayload["ath"] as String, testEncodedAccessToken)
    }

    @Test
    public fun `getHeaderData should return DPoP token with proof including nonce when provided`() {
        val tokenType = "DPoP"
        whenever(mockKeyStore.hasKeyPair()).thenReturn(true)
        whenever(mockKeyStore.getKeyPair()).thenReturn(Pair(fakePrivateKey, fakePublicKey))

        val result = DPoPProvider.getHeaderData(
            testHttpMethod,
            testHttpUrl,
            testAccessToken,
            tokenType,
            testNonce
        )

        assertThat(result.authorizationHeader, `is`("DPoP $testAccessToken"))
        assertThat(result.dpopProof, `is`(notNullValue()))

        val proof = Jwt(result.dpopProof!!)
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
    public fun `isNonceRequiredError should return true for 400 response with nonce required error`() {
        whenever(mockResponse.peekBody(Long.MAX_VALUE)).thenReturn("{\"error\":\"use_dpop_nonce\"}".toResponseBody())
        whenever(mockResponse.code).thenReturn(400)

        val result = DPoPProvider.isNonceRequiredError(mockResponse)
        assertThat(result, `is`(true))
    }

    @Test
    public fun `isNonceRequiredError should return true for 401 response with resource server nonce error`() {
        whenever(mockResponse.code).thenReturn(401)
        whenever(mockResponse.headers).thenReturn(
            Headers.Builder().add("WWW-Authenticate", "DPoP error=\"use_dpop_nonce\"").build()
        )
        val result = DPoPProvider.isNonceRequiredError(mockResponse)
        assertThat(result, `is`(true))
    }

    @Test
    public fun `isNonceRequiredError should return false for 400 response with different error`() {
        whenever(mockResponse.peekBody(Long.MAX_VALUE)).thenReturn("{\"error\":\"different_error\"}".toResponseBody())
        whenever(mockResponse.code).thenReturn(400)

        val result = DPoPProvider.isNonceRequiredError(mockResponse)
        assertThat(result, `is`(false))
    }

    @Test
    public fun `isNonceRequiredError should return false for 401 response without WWW-Authenticate header`() {
        whenever(mockResponse.headers).thenReturn(
            Headers.Builder().build()
        )
        whenever(mockResponse.code).thenReturn(401)

        val result = DPoPProvider.isNonceRequiredError(mockResponse)
        assertThat(result, `is`(false))
    }

    @Test
    public fun `isNonceRequiredError should return false for 401 response with different WWW-Authenticate error`() {
        whenever(mockResponse.headers).thenReturn(
            Headers.Builder().add("WWW-Authenticate", "error=\"different_error\"").build()
        )
        whenever(mockResponse.code).thenReturn(401)

        val result = DPoPProvider.isNonceRequiredError(mockResponse)
        assertThat(result, `is`(false))
    }

    @Test
    public fun `isNonceRequiredError should return false for different response codes`() {
        whenever(mockResponse.code).thenReturn(500)

        val result = DPoPProvider.isNonceRequiredError(mockResponse)
        assertThat(result, `is`(false))
    }

    @Test
    public fun `storeNonce should store nonce from response headers`() {
        whenever(mockResponse.headers).thenReturn(
            Headers.Builder().add("dpop-nonce", "stored-nonce-value").build()
        )

        DPoPProvider.storeNonce(mockResponse)
        assertThat(DPoPProvider.auth0Nonce, `is`("stored-nonce-value"))
    }

    @Test
    public fun `isResourceServerNonceError should parse WWW-Authenticate header correctly`() {
        whenever(mockResponse.headers).thenReturn(
            Headers.Builder().add(
                "WWW-Authenticate",
                "DPoP error=\"use_dpop_nonce\", error_description=\"DPoP proof requires nonce\""
            ).build()
        )
        whenever(mockResponse.code).thenReturn(401)

        val result = DPoPProvider.isNonceRequiredError(mockResponse)
        assertThat(result, `is`(true))
    }
}