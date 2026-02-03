package com.auth0.android.request

import com.auth0.android.dpop.DPoP
import com.auth0.android.dpop.DPoPKeyStore
import com.auth0.android.dpop.DPoPUtil
import com.auth0.android.dpop.FakeECPrivateKey
import com.auth0.android.dpop.FakeECPublicKey
import org.mockito.kotlin.any
import org.mockito.kotlin.argumentCaptor
import org.mockito.kotlin.mock
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import okhttp3.Interceptor
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import org.hamcrest.CoreMatchers.`is`
import org.hamcrest.CoreMatchers.not
import org.hamcrest.CoreMatchers.nullValue
import org.hamcrest.MatcherAssert.assertThat
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
public class RetryInterceptorTest {

    private lateinit var mockChain: Interceptor.Chain
    private lateinit var mockKeyStore: DPoPKeyStore

    private lateinit var retryInterceptor: RetryInterceptor

    @Before
    public fun setUp() {
        mockChain = mock()
        mockKeyStore = mock()

        DPoPUtil.keyStore = mockKeyStore
        retryInterceptor = RetryInterceptor()
    }

    @Test
    public fun `should proceed without retry if response is not a DPoP nonce error`() {
        val request = createRequest()
        val okResponse = createOkResponse(request)
        whenever(mockChain.request()).thenReturn(request)
        whenever(mockChain.proceed(request)).thenReturn(okResponse)

        val result = retryInterceptor.intercept(mockChain)

        assertThat(result, `is`(okResponse))
        verify(mockChain).proceed(request)
    }

    @Test
    public fun `should retry request when DPoP nonce error occurs and key pair is available`() {
        val initialRequest = createRequest(accessToken = "test-access-token")
        val errorResponse = createDpopNonceErrorResponse(initialRequest)
        val successResponse = createOkResponse(initialRequest)
        val newRequestCaptor = argumentCaptor<Request>()

        whenever(mockChain.request()).thenReturn(initialRequest)

        whenever(mockChain.proceed(any()))
            .thenReturn(errorResponse)
            .thenReturn(successResponse)

        val mockKeyPair = Pair(FakeECPrivateKey(), FakeECPublicKey())
        whenever(mockKeyStore.hasKeyPair()).thenReturn(true)
        whenever(mockKeyStore.getKeyPair()).thenReturn(mockKeyPair)

        val result = retryInterceptor.intercept(mockChain)

        assertThat(result, `is`(successResponse))
        verify(mockChain, times(2)).proceed(newRequestCaptor.capture())

        val retriedRequest = newRequestCaptor.secondValue
        assertThat(retriedRequest.header("DPoP"), not(nullValue()))
        assertThat(retriedRequest.header("X-Internal-Retry-Count"), `is`("1"))
        assertThat(DPoP.auth0Nonce, `is`("new-nonce-from-header"))
    }

    @Test
    public fun `should not retry request when DPoP nonce error occurs and retry count reaches max`() {
        val request = createRequest(retryCount = 1)
        val errorResponse = createDpopNonceErrorResponse(request)
        whenever(mockChain.request()).thenReturn(request)
        whenever(mockChain.proceed(request)).thenReturn(errorResponse)

        val result = retryInterceptor.intercept(mockChain)

        assertThat(result, `is`(errorResponse))
        verify(mockChain).proceed(request)
    }

    @Test
    public fun `should not retry request when DPoP nonce error occurs but proof generation fails`() {
        val request = createRequest()
        val errorResponse = createDpopNonceErrorResponse(request)
        whenever(mockChain.request()).thenReturn(request)
        whenever(mockChain.proceed(request)).thenReturn(errorResponse)

        whenever(mockKeyStore.hasKeyPair()).thenReturn(false)

        val result = retryInterceptor.intercept(mockChain)

        assertThat(result, `is`(errorResponse))
        verify(mockChain).proceed(request)
    }

    @Test
    public fun `should handle initial request with no retry header`() {
        val initialRequest = createRequest(accessToken = "test-access-token", retryCount = null)
        val errorResponse = createDpopNonceErrorResponse(initialRequest)
        val successResponse = createOkResponse(initialRequest)
        val newRequestCaptor = argumentCaptor<Request>()

        whenever(mockChain.request()).thenReturn(initialRequest)
        whenever(mockChain.proceed(any()))
            .thenReturn(errorResponse)
            .thenReturn(successResponse)

        val mockKeyPair = Pair(FakeECPrivateKey(), FakeECPublicKey())
        whenever(mockKeyStore.hasKeyPair()).thenReturn(true)
        whenever(mockKeyStore.getKeyPair()).thenReturn(mockKeyPair)

        val result = retryInterceptor.intercept(mockChain)

        assertThat(result, `is`(successResponse))
        verify(mockChain, times(2)).proceed(newRequestCaptor.capture())
        val retriedRequest = newRequestCaptor.secondValue
        assertThat(retriedRequest.header("X-Internal-Retry-Count"), `is`("1"))
    }

    private fun createRequest(accessToken: String? = null, retryCount: Int? = 0): Request {
        val builder = Request.Builder()
            .url("https://test.com/api")
            .method("POST", "{}".toRequestBody())

        if (accessToken != null) {
            builder.header("Authorization", "DPoP $accessToken")
        }
        if (retryCount != null) {
            builder.header("X-Internal-Retry-Count", retryCount.toString())
        }
        return builder.build()
    }

    private fun createOkResponse(request: Request): Response {
        return Response.Builder()
            .request(request)
            .protocol(Protocol.HTTP_2)
            .code(200)
            .message("OK")
            .body("{}".toResponseBody())
            .build()
    }

    private fun createDpopNonceErrorResponse(request: Request): Response {
        return Response.Builder()
            .request(request)
            .protocol(Protocol.HTTP_2)
            .code(401)
            .message("Unauthorized")
            .header("WWW-Authenticate", "DPoP error=\"use_dpop_nonce\"")
            .header("dpop-nonce", "new-nonce-from-header")
            .body("".toResponseBody())
            .build()
    }
}