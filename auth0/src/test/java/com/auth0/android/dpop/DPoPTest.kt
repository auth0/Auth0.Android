package com.auth0.android.dpop

import android.content.Context
import com.auth0.android.request.HttpMethod
import com.auth0.android.request.internal.Jwt
import com.nhaarman.mockitokotlin2.any
import com.nhaarman.mockitokotlin2.mock
import com.nhaarman.mockitokotlin2.never
import com.nhaarman.mockitokotlin2.verify
import com.nhaarman.mockitokotlin2.whenever
import okhttp3.Headers
import okhttp3.Response
import okhttp3.ResponseBody
import okhttp3.ResponseBody.Companion.toResponseBody
import org.hamcrest.CoreMatchers.`is`
import org.hamcrest.CoreMatchers.notNullValue
import org.hamcrest.CoreMatchers.nullValue
import org.hamcrest.MatcherAssert.assertThat
import org.junit.After
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
public class DPoPTest {

    private lateinit var mockContext: Context
    private lateinit var mockResponse: Response
    private lateinit var mockKeyStore: DPoPKeyStore
    private lateinit var mockResponseBody: ResponseBody
    private lateinit var dPoP: DPoP

    private val testHttpUrl = "https://api.example.com/token"
    private val testNonTokenUrl = "https://api.example.com/userinfo"
    private val testAccessToken = "test-access-token"
    private val testNonce = "test-nonce"
    private val fakePrivateKey = FakeECPrivateKey()
    private val fakePublicKey = FakeECPublicKey()
    private val testPublicJwkHash = "KQ-r0YQMCm0yVnGippcsZK4zO7oGIjOkNRbvILjjBAo"
    private val testEncodedAccessToken = "WXSA1LYsphIZPxnnP-TMOtF_C_nPwWp8v0tQZBMcSAU"

    @Before
    public fun setUp() {
        mockContext = mock()
        mockResponse = mock()
        mockKeyStore = mock()
        mockResponseBody = mock()
        dPoP = DPoP()

        DPoPUtil.keyStore = mockKeyStore
    }

    @Test
    public fun `shouldGenerateProof should return true for token endpoint with non-refresh grant type`() {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(true)

        val parameters = mapOf("grant_type" to "authorization_code")
        val result = dPoP.shouldGenerateProof(testHttpUrl, parameters)

        assertThat(result, `is`(true))
    }

    @Test
    public fun `shouldGenerateProof should return false for token endpoint with refresh grant type`() {
        val parameters = mapOf("grant_type" to "refresh_token")
        val result = dPoP.shouldGenerateProof(testHttpUrl, parameters)

        assertThat(result, `is`(false))
    }

    @Test
    public fun `shouldGenerateProof should return false for non-token endpoint`() {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(false)

        val parameters = mapOf("grant_type" to "authorization_code")
        val result = dPoP.shouldGenerateProof(testNonTokenUrl, parameters)

        assertThat(result, `is`(false))
    }

    @Test
    public fun `shouldGenerateProof should return hasKeyPair result for non-token endpoint`() {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(true)

        val parameters = mapOf("grant_type" to "authorization_code")
        val result = dPoP.shouldGenerateProof(testNonTokenUrl, parameters)

        assertThat(result, `is`(true))
        verify(mockKeyStore).hasKeyPair()
    }

    @Test
    public fun `shouldGenerateProof should handle missing grant_type parameter`() {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(true)

        val parameters = mapOf<String, Any>()
        val result = dPoP.shouldGenerateProof(testHttpUrl, parameters)

        assertThat(result, `is`(true))
    }

    @Test
    public fun `generateProof should extract access token from Authorization header`() {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(true)
        whenever(mockKeyStore.getKeyPair()).thenReturn(Pair(fakePrivateKey, fakePublicKey))

        val headers = mapOf("Authorization" to "Bearer test-access-token")
        val result = dPoP.generateProof(testHttpUrl, HttpMethod.POST, headers)

        assertThat(result, `is`(notNullValue()))
        val proof = Jwt(result!!)
        assertThat(proof.decodedPayload["ath"], `is`(notNullValue()))
        Assert.assertEquals(proof.decodedPayload["ath"], testEncodedAccessToken)
    }

    @Test
    public fun `generateProof should extract access token from DPoP Authorization header`() {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(true)
        whenever(mockKeyStore.getKeyPair()).thenReturn(Pair(fakePrivateKey, fakePublicKey))

        val headers = mapOf("Authorization" to "DPoP test-access-token")
        val result = dPoP.generateProof(testHttpUrl, HttpMethod.POST, headers)

        assertThat(result, `is`(notNullValue()))
        val proof = Jwt(result!!)
        assertThat(proof.decodedPayload["ath"], `is`(notNullValue()))
        Assert.assertEquals(proof.decodedPayload["ath"], testEncodedAccessToken)
    }

    @Test
    public fun `generateProof should handle missing Authorization header`() {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(true)
        whenever(mockKeyStore.getKeyPair()).thenReturn(Pair(fakePrivateKey, fakePublicKey))

        val headers = mapOf<String, String>()
        val result = dPoP.generateProof(testHttpUrl, HttpMethod.POST, headers)

        assertThat(result, `is`(notNullValue()))
        val proof = Jwt(result!!)
        assertThat(proof.decodedPayload["ath"], `is`(nullValue()))
    }

    @Test
    public fun `generateProof should return null when no key pair exists`() {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(false)

        val headers = mapOf("Authorization" to "Bearer test-token")
        val result = dPoP.generateProof(testHttpUrl, HttpMethod.POST, headers)

        assertThat(result, `is`(nullValue()))
    }

    @Test
    public fun `generateKeyPair should delegate to DPoPUtil`() {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(false)

        dPoP.generateKeyPair(mockContext)

        verify(mockKeyStore).generateKeyPair(mockContext)
    }

    @Test
    public fun `generateKeyPair should propagate DPoPException`() {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(false)
        val exception = DPoPException(DPoPException.Code.KEY_GENERATION_ERROR, "Key generation failed")
        whenever(mockKeyStore.generateKeyPair(mockContext)).thenThrow(
            exception
        )

        try {
            dPoP.generateKeyPair(mockContext)
            Assert.fail("Expected DPoPException to be thrown")
        } catch (e: DPoPException) {
            assertThat(e, `is`(exception))
            assertThat(e.message, `is`("Key generation failed"))
        }
    }

    @Test
    public fun `getPublicKeyJWK should generate key pair if not exists`() {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(false).thenReturn(true)
        whenever(mockKeyStore.getKeyPair()).thenReturn(Pair(fakePrivateKey, fakePublicKey))

        val result = dPoP.getPublicKeyJWK(mockContext)

        verify(mockKeyStore).generateKeyPair(mockContext)
        assertThat(result, `is`(testPublicJwkHash))
    }

    @Test
    public fun `getPublicKeyJWK should return JWK hash when key pair exists`() {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(true)
        whenever(mockKeyStore.getKeyPair()).thenReturn(Pair(fakePrivateKey, fakePublicKey))

        val result = dPoP.getPublicKeyJWK(mockContext)

        verify(mockKeyStore, never()).generateKeyPair(any())
        assertThat(result, `is`(testPublicJwkHash))
    }

    @Test
    public fun `getPublicKeyJWK should return null when key pair generation fails`() {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(false).thenReturn(false)

        val result = dPoP.getPublicKeyJWK(mockContext)

        verify(mockKeyStore).generateKeyPair(mockContext)
        assertThat(result, `is`(nullValue()))
    }

    @Test
    public fun `storeNonce should store nonce from response headers`() {
        val expectedNonce = "stored-nonce-value"
        whenever(mockResponse.headers).thenReturn(
            Headers.Builder().add("DPoP-Nonce", expectedNonce).build()
        )
        DPoP.storeNonce(mockResponse)
        assertThat(DPoP.auth0Nonce, `is`(expectedNonce))
    }

    @Test
    public fun `storeNonce should handle missing DPoP-Nonce header`() {
        whenever(mockResponse.headers).thenReturn(Headers.Builder().build())
        DPoP.storeNonce(mockResponse)
        assertThat(DPoP.auth0Nonce, `is`(nullValue()))
    }

    @Test
    public fun `storeNonce should overwrite existing nonce`() {
        val firstNonce = "first-nonce"
        val secondNonce = "second-nonce"

        val firstResponse = mock<Response>()
        whenever(firstResponse.headers).thenReturn(
            Headers.Builder().add("DPoP-Nonce", firstNonce).build()
        )
        DPoP.storeNonce(firstResponse)
        assertThat(DPoP.auth0Nonce, `is`(firstNonce))

        val secondResponse = mock<Response>()
        whenever(secondResponse.headers).thenReturn(
            Headers.Builder().add("DPoP-Nonce", secondNonce).build()
        )
        DPoP.storeNonce(secondResponse)
        assertThat(DPoP.auth0Nonce, `is`(secondNonce))
    }

    @Test
    public fun `isNonceRequiredError should return true for 400 response with nonce required error`() {
        whenever(mockResponse.peekBody(Long.MAX_VALUE)).thenReturn("{\"error\":\"use_dpop_nonce\"}".toResponseBody())
        whenever(mockResponse.code).thenReturn(400)

        val result = DPoP.isNonceRequiredError(mockResponse)
        assertThat(result, `is`(true))
    }

    @Test
    public fun `isNonceRequiredError should return true for 401 response with resource server nonce error`() {
        whenever(mockResponse.code).thenReturn(401)
        whenever(mockResponse.headers).thenReturn(
            Headers.Builder().add("WWW-Authenticate", "DPoP error=\"use_dpop_nonce\"").build()
        )

        val result = DPoP.isNonceRequiredError(mockResponse)
        assertThat(result, `is`(true))
    }

    @Test
    public fun `isNonceRequiredError should return true for 401 response with unquoted use_dpop_nonce error`() {
        whenever(mockResponse.code).thenReturn(401)
        whenever(mockResponse.headers).thenReturn(
            Headers.Builder().add("WWW-Authenticate", "DPoP error=use_dpop_nonce").build()
        )

        val result = DPoP.isNonceRequiredError(mockResponse)
        assertThat(result, `is`(true))
    }

    @Test
    public fun `isNonceRequiredError should return false for 400 response with different error`() {
        whenever(mockResponse.code).thenReturn(400)
        whenever(mockResponse.peekBody(Long.MAX_VALUE)).thenReturn("{\"error\":\"invalid_request\"}".toResponseBody())

        val result = DPoP.isNonceRequiredError(mockResponse)
        assertThat(result, `is`(false))
    }

    @Test
    public fun `isNonceRequiredError should return false for 401 response without WWW-Authenticate header`() {
        whenever(mockResponse.code).thenReturn(401)
        whenever(mockResponse.headers).thenReturn(Headers.Builder().build())

        val result = DPoP.isNonceRequiredError(mockResponse)
        assertThat(result, `is`(false))
    }

    @Test
    public fun `isNonceRequiredError should return false for 401 response with different WWW-Authenticate error`() {
        whenever(mockResponse.code).thenReturn(401)
        whenever(mockResponse.headers).thenReturn(
            Headers.Builder().add("WWW-Authenticate", "DPoP error=\"invalid_token\"").build()
        )

        val result = DPoP.isNonceRequiredError(mockResponse)
        assertThat(result, `is`(false))
    }

    @Test
    public fun `isNonceRequiredError should return false for 401 response with malformed WWW-Authenticate header`() {
        whenever(mockResponse.code).thenReturn(401)
        whenever(mockResponse.headers).thenReturn(
            Headers.Builder().add("WWW-Authenticate", "malformed-header-without-scheme").build()
        )

        val result = DPoP.isNonceRequiredError(mockResponse)
        assertThat(result, `is`(false))
    }

    @Test
    public fun `isNonceRequiredError should return false for 401 response with missing authentication scheme`() {
        whenever(mockResponse.code).thenReturn(401)
        whenever(mockResponse.headers).thenReturn(
            Headers.Builder().add("WWW-Authenticate", "error=\"use_dpop_nonce\"").build()
        )

        val result = DPoP.isNonceRequiredError(mockResponse)
        assertThat(result, `is`(false))
    }

    @Test
    public fun `isNonceRequiredError should return false for 401 response with Bearer scheme instead of DPoP`() {
        whenever(mockResponse.code).thenReturn(401)
        whenever(mockResponse.headers).thenReturn(
            Headers.Builder().add("WWW-Authenticate", "Bearer error=\"use_dpop_nonce\"").build()
        )

        val result = DPoP.isNonceRequiredError(mockResponse)
        assertThat(result, `is`(false))
    }

    @Test
    public fun `isNonceRequiredError should return false for different response codes`() {
        whenever(mockResponse.code).thenReturn(500)

        val result = DPoP.isNonceRequiredError(mockResponse)
        assertThat(result, `is`(false))
    }

    @Test
    public fun `getHeaderData should return bearer token when tokenType is not DPoP`() {
        val result = DPoP.getHeaderData(
            "POST", testHttpUrl, testAccessToken, "Bearer"
        )

        assertThat(result.authorizationHeader, `is`("Bearer $testAccessToken"))
        assertThat(result.dpopProof, `is`(nullValue()))
    }

    @Test
    public fun `getHeaderData should return DPoP token with proof when tokenType is DPoP`() {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(true)
        whenever(mockKeyStore.getKeyPair()).thenReturn(Pair(fakePrivateKey, fakePublicKey))

        val result = DPoP.getHeaderData(
            "POST", testHttpUrl, testAccessToken, "DPoP"
        )

        assertThat(result.authorizationHeader, `is`("DPoP $testAccessToken"))
        assertThat(result.dpopProof, `is`(notNullValue()))

        val proof = Jwt(result.dpopProof!!)
        assertThat(proof.decodedHeader["typ"], `is`("dpop+jwt"))
        assertThat(proof.decodedHeader["alg"], `is`("ES256"))
        assertThat(proof.decodedPayload["htm"], `is`("POST"))
        assertThat(proof.decodedPayload["htu"], `is`(testHttpUrl))
    }

    @Test
    public fun `getHeaderData should include nonce when provided`() {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(true)
        whenever(mockKeyStore.getKeyPair()).thenReturn(Pair(fakePrivateKey, fakePublicKey))

        val result = DPoP.getHeaderData(
            "POST", testHttpUrl, testAccessToken, "DPoP", testNonce
        )

        assertThat(result.authorizationHeader, `is`("DPoP $testAccessToken"))
        assertThat(result.dpopProof, `is`(notNullValue()))

        val proof = Jwt(result.dpopProof!!)
        assertThat(proof.decodedPayload["nonce"], `is`(testNonce))
    }

    @Test
    public fun `getHeaderData should handle case insensitive DPoP token type`() {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(true)
        whenever(mockKeyStore.getKeyPair()).thenReturn(Pair(fakePrivateKey, fakePublicKey))

        val result = DPoP.getHeaderData(
            "POST", testHttpUrl, testAccessToken, "dpop"
        )

        assertThat(result.authorizationHeader, `is`("dpop $testAccessToken"))
        assertThat(result.dpopProof, `is`(notNullValue()))
    }

    @Test
    public fun `getHeaderData should return null proof when no key pair exists`() {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(false)

        val result = DPoP.getHeaderData(
            "POST", testHttpUrl, testAccessToken, "DPoP"
        )

        assertThat(result.authorizationHeader, `is`("DPoP $testAccessToken"))
        assertThat(result.dpopProof, `is`(nullValue()))
    }

    @Test
    public fun `clearKeyPair should clear both key pair and nonce`() {
        val mockNonceResponse = mock<Response>()
        whenever(mockNonceResponse.headers).thenReturn(
            Headers.Builder().add("DPoP-Nonce", testNonce).build()
        )
        DPoP.storeNonce(mockNonceResponse)
        assertThat(DPoP.auth0Nonce, `is`(testNonce))

        DPoP.clearKeyPair()

        verify(mockKeyStore).deleteKeyPair()
        assertThat(DPoP.auth0Nonce, `is`(nullValue()))
    }

    @Test
    public fun `clearKeyPair should propagate DPoPException from keyStore`() {
        whenever(mockKeyStore.deleteKeyPair()).thenThrow(
            DPoPException.KEY_STORE_ERROR
        )

        try {
            DPoP.clearKeyPair()
            Assert.fail("Expected DPoPException to be thrown")
        } catch (e: DPoPException) {
            assertThat(e, `is`(DPoPException.KEY_STORE_ERROR))
            assertThat(e.message, `is`("Error while accessing the key pair in the keystore."))
        }
    }

    @Test
    public fun `nonce storage should be thread safe`() {
        val numThreads = 10
        val numIterations = 100
        val threads = mutableListOf<Thread>()

        repeat(numThreads) { threadIndex ->
            threads.add(Thread {
                repeat(numIterations) { iteration ->
                    val nonce = "nonce-$threadIndex-$iteration"
                    val response = mock<Response>()
                    whenever(response.headers).thenReturn(
                        Headers.Builder().add("DPoP-Nonce", nonce).build()
                    )
                    DPoP.storeNonce(response)
                }
            })
        }

        threads.forEach { it.start() }
        threads.forEach { it.join() }

        // Should not crash and should have some nonce value
        val finalNonce = DPoP.auth0Nonce
        assertThat(finalNonce, `is`(notNullValue()))
        assertThat(finalNonce!!.startsWith("nonce-"), `is`(true))
    }

    @Test
    public fun `full DPoP flow should work correctly`() {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(false).thenReturn(true)
        whenever(mockKeyStore.getKeyPair()).thenReturn(Pair(fakePrivateKey, fakePublicKey))

        // 1. Generate key pair
        dPoP.generateKeyPair(mockContext)
        verify(mockKeyStore).generateKeyPair(mockContext)

        // 2. Get JWK thumbprint
        val jwkThumbprint = dPoP.getPublicKeyJWK(mockContext)
        assertThat(jwkThumbprint, `is`(testPublicJwkHash))

        // 3. Store nonce from response
        val nonceResponse = mock<Response>()
        whenever(nonceResponse.headers).thenReturn(
            Headers.Builder().add("DPoP-Nonce", testNonce).build()
        )
        DPoP.storeNonce(nonceResponse)

        // 4. Generate DPoP proof
        val headers = mapOf("Authorization" to "DPoP $testAccessToken")
        val proof = dPoP.generateProof(testHttpUrl, HttpMethod.POST, headers)
        assertThat(proof, `is`(notNullValue()))

        val decodedProof = Jwt(proof!!)
        assertThat(decodedProof.decodedPayload["nonce"], `is`(testNonce))
        assertThat(decodedProof.decodedPayload["ath"], `is`(notNullValue()))

        // 5. Get header data
        val headerData = DPoP.getHeaderData("POST", testHttpUrl, testAccessToken, "DPoP")
        assertThat(headerData.authorizationHeader, `is`("DPoP $testAccessToken"))
        assertThat(headerData.dpopProof, `is`(notNullValue()))

        // 6. Clear key pair
        DPoP.clearKeyPair()
        verify(mockKeyStore).deleteKeyPair()
        assertThat(DPoP.auth0Nonce, `is`(nullValue()))
    }
}