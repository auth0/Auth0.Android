package com.auth0.android.request.internal

import com.auth0.android.Auth0Exception
import com.auth0.android.callback.Callback
import com.auth0.android.dpop.DPoP
import com.auth0.android.dpop.DPoPException
import com.auth0.android.dpop.DPoPUtil.DPOP_HEADER
import com.auth0.android.request.*
import com.google.gson.Gson
import com.google.gson.JsonIOException
import com.nhaarman.mockitokotlin2.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.hamcrest.MatcherAssert
import org.hamcrest.Matchers
import org.hamcrest.collection.IsMapContaining
import org.hamcrest.collection.IsMapWithSize
import org.hamcrest.core.IsCollectionContaining
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.Mock
import org.mockito.Mockito
import org.mockito.MockitoAnnotations
import org.mockito.internal.verification.VerificationModeFactory
import org.robolectric.RobolectricTestRunner
import org.robolectric.android.util.concurrent.PausedExecutorService
import org.robolectric.shadows.ShadowLooper
import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream
import java.io.Reader
import java.util.*

@RunWith(RobolectricTestRunner::class)
public class BaseRequestTest {
    private lateinit var baseRequest: BaseRequest<SimplePojo, Auth0Exception>
    private lateinit var resultAdapter: JsonAdapter<SimplePojo>
    private lateinit var errorAdapter: ErrorAdapter<Auth0Exception>

    @Mock
    private lateinit var client: NetworkingClient

    @Mock
    private lateinit var mockDPoP: DPoP

    /**
     * Whether the response InputStream was closed; only relevant for tests using the `mock...`
     * setup methods of this class.
     */
    private var wasResponseStreamClosed = false

    private val readAuth0Exception = Auth0Exception("read")
    private val readRawAuth0Exception = Auth0Exception("read-raw")
    private val wrappingAuth0Exception = Auth0Exception("wrapping")

    private val optionsCaptor: KArgumentCaptor<RequestOptions> = argumentCaptor()

    @Before
    public fun setUp() {
        MockitoAnnotations.openMocks(this)
        resultAdapter = Mockito.spy(GsonAdapter(SimplePojo::class.java, Gson()))
        errorAdapter = Mockito.spy(object : ErrorAdapter<Auth0Exception> {
            override fun fromJsonResponse(statusCode: Int, reader: Reader): Auth0Exception {
                reader.read() // Read to trigger exception thrown by Reader, if any
                return readAuth0Exception
            }

            override fun fromRawResponse(
                statusCode: Int,
                bodyText: String,
                headers: Map<String, List<String>>
            ): Auth0Exception {
                return readRawAuth0Exception
            }

            override fun fromException(cause: Throwable): Auth0Exception {
                return wrappingAuth0Exception
            }

        })
        baseRequest = createRequest()
    }

    private fun createRequest(): BaseRequest<SimplePojo, Auth0Exception> =
        BaseRequest(
            HttpMethod.POST,
            BASE_URL,
            client,
            resultAdapter,
            errorAdapter,
            CommonThreadSwitcher.getInstance(),
            null
        )

    @Test
    @Throws(Exception::class)
    public fun shouldAddHeaders() {
        mockSuccessfulServerResponse()
        baseRequest.addHeader("A", "1")
        baseRequest.execute()
        verify(client).load(eq(BASE_URL), optionsCaptor.capture())
        val values: Map<String, String> = optionsCaptor.firstValue.headers
        MatcherAssert.assertThat(values, IsMapWithSize.aMapWithSize(1))
        MatcherAssert.assertThat(values, IsMapContaining.hasEntry("A", "1"))
    }

    @Test
    @Throws(Exception::class)
    public fun shouldAddParameter() {
        mockSuccessfulServerResponse()
        baseRequest.addParameter("A", "1")
        baseRequest.execute()
        verify(client).load(eq(BASE_URL), optionsCaptor.capture())
        val values: Map<String, Any> = optionsCaptor.firstValue.parameters
        MatcherAssert.assertThat(values, IsMapWithSize.aMapWithSize(1))
        MatcherAssert.assertThat(values, IsMapContaining.hasEntry("A", "1"))
    }

    @Test
    @Throws(Exception::class)
    public fun shouldEnforceOidcScope() {
        mockSuccessfulServerResponse()
        createRequest()
            .addParameter("scope", "email profile")
            .execute()

        mockSuccessfulServerResponse()
        createRequest()
            .addParameter("scope", "")
            .execute()

        mockSuccessfulServerResponse()
        createRequest()
            .addParameters(mapOf("scope" to "name"))
            .execute()

        mockSuccessfulServerResponse()
        createRequest()
            .addParameters(mapOf("scope" to ""))
            .execute()

        verify(client, VerificationModeFactory.times(4))
            .load(
                eq(BASE_URL),
                optionsCaptor.capture()
            )

        val values1: Map<String, Any> = optionsCaptor.allValues[0].parameters
        MatcherAssert.assertThat(values1, IsMapWithSize.aMapWithSize(1))
        MatcherAssert.assertThat(values1, IsMapContaining.hasEntry("scope", "email profile openid"))

        val values2: Map<String, Any> = optionsCaptor.allValues[1].parameters
        MatcherAssert.assertThat(values2, IsMapWithSize.aMapWithSize(1))
        MatcherAssert.assertThat(values2, IsMapContaining.hasEntry("scope", "openid"))

        val values3: Map<String, Any> = optionsCaptor.allValues[2].parameters
        MatcherAssert.assertThat(values3, IsMapWithSize.aMapWithSize(1))
        MatcherAssert.assertThat(values3, IsMapContaining.hasEntry("scope", "name openid"))

        val values4: Map<String, Any> = optionsCaptor.allValues[3].parameters
        MatcherAssert.assertThat(values4, IsMapWithSize.aMapWithSize(1))
        MatcherAssert.assertThat(values4, IsMapContaining.hasEntry("scope", "openid"))
    }

    @Test
    @Throws(Exception::class)
    public fun shouldAddParameters() {
        mockSuccessfulServerResponse()
        val parameters = HashMap<String, String>()
        parameters["A"] = "1"
        parameters["B"] = "2"
        baseRequest.addParameters(parameters)
        baseRequest.execute()
        verify(client).load(eq(BASE_URL), optionsCaptor.capture())
        val values: Map<String, Any> = optionsCaptor.firstValue.parameters
        MatcherAssert.assertThat(values, IsMapWithSize.aMapWithSize(2))
        MatcherAssert.assertThat(values, IsMapContaining.hasEntry("A", "1"))
        MatcherAssert.assertThat(values, IsMapContaining.hasEntry("B", "2"))
    }

    @Test
    @Throws(Exception::class)
    public fun shouldBuildErrorFromException() {
        val networkError = IOException("Network error")
        Mockito.`when`(
            client.load(
                eq(BASE_URL), any()
            )
        ).thenThrow(networkError)
        var exception: Exception? = null
        var result: SimplePojo? = null
        try {
            result = baseRequest.execute()
        } catch (e: Auth0Exception) {
            exception = e
        }
        MatcherAssert.assertThat(exception, Matchers.`is`(wrappingAuth0Exception))
        MatcherAssert.assertThat(result, Matchers.`is`(Matchers.nullValue()))
        verify(errorAdapter).fromException(networkError)
        verifyZeroInteractions(resultAdapter)
        verifyNoMoreInteractions(errorAdapter)
    }

    @Test
    @Throws(Exception::class)
    public fun shouldBuildErrorFromResponseParseException() {
        mockSuccessfulServerResponse()
        @Suppress("UNCHECKED_CAST") // adapter is only used for throwing exceptions
        val resultAdapter = Mockito.mock(GsonAdapter::class.java) as JsonAdapter<SimplePojo>
        val baseRequest = BaseRequest(
            HttpMethod.POST,
            BASE_URL,
            client,
            resultAdapter,
            errorAdapter
        )
        val networkError = JsonIOException("Network error")
        Mockito.`when`(
            resultAdapter.fromJson(
                any(), any()
            )
        ).thenThrow(networkError)
        var exception: Exception? = null
        var result: SimplePojo? = null
        try {
            result = baseRequest.execute()
        } catch (e: Exception) {
            exception = e
        }
        MatcherAssert.assertThat(exception, Matchers.`is`(wrappingAuth0Exception))
        MatcherAssert.assertThat(result, Matchers.`is`(Matchers.nullValue()))
        verify(errorAdapter).fromException(eq(networkError))
        MatcherAssert.assertThat(wasResponseStreamClosed, Matchers.`is`(true))
        verifyNoMoreInteractions(errorAdapter)
    }

    @Test
    @Throws(Exception::class)
    public fun shouldBuildErrorFromUnsuccessfulJsonResponse() {
        mockFailedJsonServerResponse()
        var exception: Auth0Exception? = null
        var result: SimplePojo? = null
        try {
            result = baseRequest.execute()
        } catch (e: Auth0Exception) {
            exception = e
        }
        MatcherAssert.assertThat(result, Matchers.`is`(Matchers.nullValue()))
        MatcherAssert.assertThat(exception, Matchers.`is`(readAuth0Exception))
        verify(errorAdapter).fromJsonResponse(
            eq(422), any()
        )
        MatcherAssert.assertThat(wasResponseStreamClosed, Matchers.`is`(true))
        verifyZeroInteractions(resultAdapter)
        verifyNoMoreInteractions(errorAdapter)
    }

    @Test
    @Throws(Exception::class)
    public fun shouldBuildErrorFromUnsuccessfulRawResponse() {
        mockFailedRawServerResponse()
        var exception: Auth0Exception? = null
        var result: SimplePojo? = null
        try {
            result = baseRequest.execute()
        } catch (e: Auth0Exception) {
            exception = e
        }
        MatcherAssert.assertThat(result, Matchers.`is`(Matchers.nullValue()))
        MatcherAssert.assertThat(exception, Matchers.`is`(readRawAuth0Exception))
        val headersMapCaptor: KArgumentCaptor<Map<String, List<String>>> = argumentCaptor()
        verify(errorAdapter).fromRawResponse(
            eq(500),
            eq("Failure"),
            headersMapCaptor.capture()
        )
        val headersMap = headersMapCaptor.firstValue
        MatcherAssert.assertThat(headersMap, Matchers.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(headersMap, IsMapWithSize.aMapWithSize(1))
        MatcherAssert.assertThat(
            headersMap,
            IsMapContaining.hasEntry(
                Matchers.`is`("Content-Type"),
                IsCollectionContaining.hasItem("text/plain")
            )
        )
        MatcherAssert.assertThat(wasResponseStreamClosed, Matchers.`is`(true))
        verifyZeroInteractions(resultAdapter)
        verifyNoMoreInteractions(errorAdapter)
    }

    @Test
    @Throws(Exception::class)
    public fun shouldBuildResultFromSuccessfulResponse() {
        mockSuccessfulServerResponse()
        var exception: Exception? = null
        var result: SimplePojo? = null
        try {
            result = baseRequest.execute()
        } catch (e: Auth0Exception) {
            exception = e
        }
        MatcherAssert.assertThat(exception, Matchers.`is`(Matchers.nullValue()))
        MatcherAssert.assertThat(result, Matchers.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(result!!.prop, Matchers.`is`("test-value"))
        verify(resultAdapter).fromJson(any(), any())
        MatcherAssert.assertThat(wasResponseStreamClosed, Matchers.`is`(true))
        verifyNoMoreInteractions(resultAdapter)
        verifyZeroInteractions(errorAdapter)
    }

    @Test
    @Throws(Exception::class)
    public fun shouldBuildErrorFromNetworkErrorForUnsuccessfulJsonResponse() {
        val networkError = IOException("Network error")
        mockFailedJsonServerResponseNetworkError(networkError)
        var exception: Auth0Exception? = null
        var result: SimplePojo? = null
        try {
            result = baseRequest.execute()
        } catch (e: Auth0Exception) {
            exception = e
        }
        MatcherAssert.assertThat(result, Matchers.`is`(Matchers.nullValue()))
        MatcherAssert.assertThat(exception, Matchers.`is`(wrappingAuth0Exception))
        verify(errorAdapter).fromJsonResponse(eq(422), any())
        verify(errorAdapter).fromException(networkError)
        MatcherAssert.assertThat(wasResponseStreamClosed, Matchers.`is`(true))
        verifyZeroInteractions(resultAdapter)
        verifyNoMoreInteractions(errorAdapter)
    }

    @Test
    @Throws(Exception::class)
    public fun shouldBuildErrorFromNetworkErrorForUnsuccessfulRawResponse() {
        val networkError = IOException("Network error")
        mockFailedRawServerResponseNetworkError(networkError)
        var exception: Auth0Exception? = null
        var result: SimplePojo? = null
        try {
            result = baseRequest.execute()
        } catch (e: Auth0Exception) {
            exception = e
        }
        MatcherAssert.assertThat(result, Matchers.`is`(Matchers.nullValue()))
        MatcherAssert.assertThat(exception, Matchers.`is`(wrappingAuth0Exception))
        verify(errorAdapter).fromException(networkError)
        MatcherAssert.assertThat(wasResponseStreamClosed, Matchers.`is`(true))
        verifyZeroInteractions(resultAdapter)
        verifyNoMoreInteractions(errorAdapter)
    }

    @Test
    @Throws(Exception::class)
    public fun shouldBuildErrorFromNetworkErrorForSuccessfulResponse() {
        val networkError = IOException("Network error")
        mockSuccessfulServerResponseNetworkError(networkError)
        var exception: Exception? = null
        var result: SimplePojo? = null
        try {
            result = baseRequest.execute()
        } catch (e: Auth0Exception) {
            exception = e
        }
        MatcherAssert.assertThat(result, Matchers.`is`(Matchers.nullValue()))
        verify(resultAdapter).fromJson(any(), any())
        MatcherAssert.assertThat(exception, Matchers.`is`(wrappingAuth0Exception))
        verify(errorAdapter).fromException(networkError)
        MatcherAssert.assertThat(wasResponseStreamClosed, Matchers.`is`(true))
        verifyNoMoreInteractions(resultAdapter)
        verifyNoMoreInteractions(errorAdapter)
    }

    @Test
    @Throws(Exception::class)
    public fun shouldExecuteRequestOnBackgroundThreadAndPostSuccessToMainThread() {
        val pausedExecutorService = PausedExecutorService()
        val defaultThreadSwitcher =
            DefaultThreadSwitcher(pausedExecutorService)
        val threadSwitcher = Mockito.spy(CommonThreadSwitcher(defaultThreadSwitcher))

        val baseRequest = BaseRequest(
            HttpMethod.POST,
            BASE_URL,
            client,
            resultAdapter,
            errorAdapter,
            threadSwitcher
        )
        mockSuccessfulServerResponse()
        val callback: Callback<SimplePojo, Auth0Exception> = mock()

        // verify background thread is queued
        baseRequest.start(callback)
        verify(threadSwitcher).backgroundThread(
            any()
        )
        verify(threadSwitcher, Mockito.never()).mainThread(
            any()
        )

        // let the background thread run
        MatcherAssert.assertThat(pausedExecutorService.runNext(), Matchers.`is`(true))
        verify(threadSwitcher).mainThread(
            any()
        )
        verify(callback, Mockito.never()).onSuccess(
            any()
        )

        // Release the main thread queue
        ShadowLooper.shadowMainLooper().idle()
        val pojoCaptor = argumentCaptor<SimplePojo>()
        verify(callback).onSuccess(pojoCaptor.capture())
        MatcherAssert.assertThat(pojoCaptor.firstValue, Matchers.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(pojoCaptor.firstValue.prop, Matchers.`is`("test-value"))
        verify(callback, Mockito.never()).onFailure(
            any()
        )
    }

    @Test
    @Throws(Exception::class)
    public fun shouldExecuteRequestOnBackgroundThreadAndPostFailureToMainThread() {
        val pausedExecutorService = PausedExecutorService()
        val defaultThreadSwitcher =
            DefaultThreadSwitcher(pausedExecutorService)
        val threadSwitcher = Mockito.spy(CommonThreadSwitcher(defaultThreadSwitcher))

        val baseRequest = BaseRequest(
            HttpMethod.POST,
            BASE_URL,
            client,
            resultAdapter,
            errorAdapter,
            threadSwitcher
        )
        mockFailedRawServerResponse()
        val callback: Callback<SimplePojo, Auth0Exception> = mock()

        // verify background thread is queued
        baseRequest.start(callback)
        verify(threadSwitcher).backgroundThread(
            any()
        )
        verify(threadSwitcher, Mockito.never()).mainThread(
            any()
        )

        // let the background thread run
        MatcherAssert.assertThat(pausedExecutorService.runNext(), Matchers.`is`(true))
        verify(threadSwitcher).mainThread(
            any()
        )
        verify(callback, Mockito.never()).onFailure(
            any()
        )

        // Release the main thread queue
        ShadowLooper.shadowMainLooper().idle()
        verify(callback).onFailure(
            any()
        )
        verify(callback, Mockito.never()).onSuccess(
            any()
        )
    }

    //DPoP

    @Test
    @Throws(Exception::class)
    public fun shouldAddDPoPHeaderWhenDPoPProofIsGenerated() {
        mockSuccessfulServerResponse()
        val mockProof = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2In0.eyJqdGkiOiJ0ZXN0LWp0aSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwczovL2F1dGgwLmNvbSIsImlhdCI6MTY0MDk5NTIwMH0.signature"

        Mockito.`when`(mockDPoP.shouldGenerateProof(eq(BASE_URL), any())).thenReturn(true)
        Mockito.`when`(mockDPoP.generateProof(eq(BASE_URL), eq(HttpMethod.POST), any())).thenReturn(mockProof)

        val baseRequest = BaseRequest(
            HttpMethod.POST,
            BASE_URL,
            client,
            resultAdapter,
            errorAdapter,
            CommonThreadSwitcher.getInstance(),
            mockDPoP
        )

        baseRequest.execute()

        verify(client).load(eq(BASE_URL), optionsCaptor.capture())
        val headers = optionsCaptor.firstValue.headers
        MatcherAssert.assertThat(headers, IsMapContaining.hasEntry(DPOP_HEADER, mockProof))
    }

    @Test
    @Throws(Exception::class)
    public fun shouldNotAddDPoPHeaderWhenDPoPProofIsNotGenerated() {
        mockSuccessfulServerResponse()

        Mockito.`when`(mockDPoP.shouldGenerateProof(eq(BASE_URL), any())).thenReturn(true)
        Mockito.`when`(mockDPoP.generateProof(eq(BASE_URL), eq(HttpMethod.POST), any())).thenReturn(null)

        val baseRequest = BaseRequest(
            HttpMethod.POST,
            BASE_URL,
            client,
            resultAdapter,
            errorAdapter,
            CommonThreadSwitcher.getInstance(),
            mockDPoP
        )

        baseRequest.execute()

        verify(client).load(eq(BASE_URL), optionsCaptor.capture())
        val headers = optionsCaptor.firstValue.headers
        MatcherAssert.assertThat(headers, Matchers.not(IsMapContaining.hasKey(DPOP_HEADER)))
    }

    @Test
    @Throws(Exception::class)
    public fun shouldNotAddDPoPHeaderWhenShouldGenerateProofReturnsFalse() {
        mockSuccessfulServerResponse()

        Mockito.`when`(mockDPoP.shouldGenerateProof(eq(BASE_URL), any())).thenReturn(false)

        val baseRequest = BaseRequest(
            HttpMethod.POST,
            BASE_URL,
            client,
            resultAdapter,
            errorAdapter,
            CommonThreadSwitcher.getInstance(),
            mockDPoP
        )

        baseRequest.execute()

        verify(client).load(eq(BASE_URL), optionsCaptor.capture())
        val headers = optionsCaptor.firstValue.headers
        MatcherAssert.assertThat(headers, Matchers.not(IsMapContaining.hasKey(DPOP_HEADER)))
        verify(mockDPoP, never()).generateProof(any<String>(), any(), any())
    }

    @Test
    @Throws(Exception::class)
    public fun shouldNotCallDPoPMethodsWhenDPoPIsNull() {
        mockSuccessfulServerResponse()

        val baseRequest = BaseRequest(
            HttpMethod.POST,
            BASE_URL,
            client,
            resultAdapter,
            errorAdapter,
            CommonThreadSwitcher.getInstance(),
            null
        )

        baseRequest.execute()

        verify(client).load(eq(BASE_URL), optionsCaptor.capture())
        val headers = optionsCaptor.firstValue.headers
        MatcherAssert.assertThat(headers, Matchers.not(IsMapContaining.hasKey(DPOP_HEADER)))
    }

    @Test
    @Throws(Exception::class)
    public fun shouldPassCorrectParametersToShouldGenerateProof() {
        mockSuccessfulServerResponse()

        Mockito.`when`(mockDPoP.shouldGenerateProof(eq(BASE_URL), any())).thenReturn(false)

        val baseRequest = BaseRequest(
            HttpMethod.POST,
            BASE_URL,
            client,
            resultAdapter,
            errorAdapter,
            CommonThreadSwitcher.getInstance(),
            mockDPoP
        )

        baseRequest.addParameter("grant_type", "authorization_code")
        baseRequest.addParameter("code", "test-code")
        baseRequest.execute()

        val parametersCaptor: KArgumentCaptor<Map<String, Any>> = argumentCaptor()
        verify(mockDPoP).shouldGenerateProof(eq(BASE_URL), parametersCaptor.capture())

        val parameters = parametersCaptor.firstValue
        MatcherAssert.assertThat(parameters, IsMapContaining.hasEntry("grant_type", "authorization_code"))
        MatcherAssert.assertThat(parameters, IsMapContaining.hasEntry("code", "test-code"))
    }

    @Test
    @Throws(Exception::class)
    public fun shouldPassCorrectHeadersToGenerateProof() {
        mockSuccessfulServerResponse()

        Mockito.`when`(mockDPoP.shouldGenerateProof(eq(BASE_URL), any())).thenReturn(true)
        Mockito.`when`(mockDPoP.generateProof(eq(BASE_URL), eq(HttpMethod.POST), any())).thenReturn("test-proof")

        val baseRequest = BaseRequest(
            HttpMethod.POST,
            BASE_URL,
            client,
            resultAdapter,
            errorAdapter,
            CommonThreadSwitcher.getInstance(),
            mockDPoP
        )

        baseRequest.addHeader("Authorization", "Bearer test-token")
        baseRequest.addHeader("Content-Type", "application/json")
        baseRequest.execute()

        val headersCaptor: KArgumentCaptor<Map<String, String>> = argumentCaptor()
        verify(mockDPoP).generateProof(eq(BASE_URL), eq(HttpMethod.POST), headersCaptor.capture())

        val headers = headersCaptor.firstValue
        MatcherAssert.assertThat(headers, IsMapContaining.hasEntry("Authorization", "Bearer test-token"))
        MatcherAssert.assertThat(headers, IsMapContaining.hasEntry("Content-Type", "application/json"))
    }

    @Test
    @Throws(Exception::class)
    public fun shouldHandleDPoPExceptionDuringProofGeneration() {
        val dpopException = DPoPException(DPoPException.Code.SIGNING_ERROR, "Signing failed")

        Mockito.`when`(mockDPoP.shouldGenerateProof(eq(BASE_URL), any())).thenReturn(true)
        Mockito.`when`(mockDPoP.generateProof(eq(BASE_URL), eq(HttpMethod.POST), any())).thenThrow(dpopException)

        val baseRequest = BaseRequest(
            HttpMethod.POST,
            BASE_URL,
            client,
            resultAdapter,
            errorAdapter,
            CommonThreadSwitcher.getInstance(),
            mockDPoP
        )

        var exception: Exception? = null
        var result: SimplePojo? = null
        try {
            result = baseRequest.execute()
        } catch (e: Auth0Exception) {
            exception = e
        }

        MatcherAssert.assertThat(exception, Matchers.`is`(wrappingAuth0Exception))
        MatcherAssert.assertThat(result, Matchers.`is`(Matchers.nullValue()))
        verify(errorAdapter).fromException(dpopException)
        verify(client, never()).load(any<String>(), any())
    }

    @Test
    @Throws(Exception::class)
    public fun shouldHandleDPoPExceptionDuringShouldGenerateProofCheck() {
        val dpopException = DPoPException.KEY_STORE_ERROR

        Mockito.`when`(mockDPoP.shouldGenerateProof(eq(BASE_URL), any())).thenThrow(dpopException)

        val baseRequest = BaseRequest(
            HttpMethod.POST,
            BASE_URL,
            client,
            resultAdapter,
            errorAdapter,
            CommonThreadSwitcher.getInstance(),
            mockDPoP
        )

        var exception: Exception? = null
        var result: SimplePojo? = null
        try {
            result = baseRequest.execute()
        } catch (e: Auth0Exception) {
            exception = e
        }

        MatcherAssert.assertThat(exception, Matchers.`is`(wrappingAuth0Exception))
        MatcherAssert.assertThat(result, Matchers.`is`(Matchers.nullValue()))
        verify(errorAdapter).fromException(dpopException)
        verify(client, never()).load(any<String>(), any())
        verify(mockDPoP, never()).generateProof(any<String>(), any(), any())
    }

    @Test
    @Throws(Exception::class)
    public fun shouldAddDPoPHeaderToExistingHeaders() {
        mockSuccessfulServerResponse()
        val mockProof = "test-dpop-proof"

        Mockito.`when`(mockDPoP.shouldGenerateProof(eq(BASE_URL), any())).thenReturn(true)
        Mockito.`when`(mockDPoP.generateProof(eq(BASE_URL), eq(HttpMethod.POST), any())).thenReturn(mockProof)

        val baseRequest = BaseRequest(
            HttpMethod.POST,
            BASE_URL,
            client,
            resultAdapter,
            errorAdapter,
            CommonThreadSwitcher.getInstance(),
            mockDPoP
        )

        baseRequest.addHeader("Authorization", "Bearer test-token")
        baseRequest.addHeader("Content-Type", "application/json")
        baseRequest.execute()

        verify(client).load(eq(BASE_URL), optionsCaptor.capture())
        val headers = optionsCaptor.firstValue.headers
        MatcherAssert.assertThat(headers, IsMapWithSize.aMapWithSize(3))
        MatcherAssert.assertThat(headers, IsMapContaining.hasEntry("Authorization", "Bearer test-token"))
        MatcherAssert.assertThat(headers, IsMapContaining.hasEntry("Content-Type", "application/json"))
        MatcherAssert.assertThat(headers, IsMapContaining.hasEntry(DPOP_HEADER, mockProof))
    }

    @Test
    @ExperimentalCoroutinesApi
    public fun shouldAwaitOnIODispatcher(): Unit = runTest {
        val baseRequest = Mockito.spy(
            BaseRequest(
                HttpMethod.POST,
                BASE_URL,
                client,
                resultAdapter,
                errorAdapter
            )
        )
        Mockito.doReturn(SimplePojo("")).`when`(baseRequest).switchRequestContext(any(), any())
        mockSuccessfulServerResponse()
        baseRequest.await()
        verify(baseRequest).switchRequestContext(eq(Dispatchers.IO), any())
    }

    @Throws(Exception::class)
    private fun mockSuccessfulServerResponse() {
        val headers = Collections.singletonMap("Content-Type", listOf("application/json"))
        val jsonResponse = "{\"prop\":\"test-value\"}"
        val inputStream = AwareInputStream(jsonResponse) { wasResponseStreamClosed = true }
        val response = ServerResponse(200, inputStream, headers)
        Mockito.`when`(
            client.load(
                eq(BASE_URL), any()
            )
        ).thenReturn(response)
    }

    @Throws(Exception::class)
    private fun mockFailedRawServerResponse() {
        val headers = Collections.singletonMap("Content-Type", listOf("text/plain"))
        val textResponse = "Failure"
        val inputStream = AwareInputStream(textResponse) { wasResponseStreamClosed = true }
        val response = ServerResponse(500, inputStream, headers)
        Mockito.`when`(
            client.load(
                eq(BASE_URL), any()
            )
        ).thenReturn(response)
    }

    @Throws(Exception::class)
    private fun mockFailedJsonServerResponse() {
        val headers = Collections.singletonMap("Content-Type", listOf("application/json"))
        val jsonResponse = "{\"error_code\":\"invalid_token\"}"
        val inputStream = AwareInputStream(jsonResponse) { wasResponseStreamClosed = true }
        val response = ServerResponse(422, inputStream, headers)
        Mockito.`when`(
            client.load(
                eq(BASE_URL), any()
            )
        ).thenReturn(response)
    }

    @Throws(Exception::class)
    private fun mockSuccessfulServerResponseNetworkError(networkError: IOException) {
        val headers = Collections.singletonMap("Content-Type", listOf("application/json"))
        val inputStream = AwareThrowingInputStream(networkError) { wasResponseStreamClosed = true }
        val response = ServerResponse(200, inputStream, headers)
        Mockito.`when`(
            client.load(
                eq(BASE_URL), any()
            )
        ).thenReturn(response)
    }

    @Throws(Exception::class)
    private fun mockFailedRawServerResponseNetworkError(networkError: IOException) {
        val headers = Collections.singletonMap("Content-Type", listOf("text/plain"))
        val inputStream = AwareThrowingInputStream(networkError) { wasResponseStreamClosed = true }
        val response = ServerResponse(500, inputStream, headers)
        Mockito.`when`(
            client.load(
                eq(BASE_URL), any()
            )
        ).thenReturn(response)
    }

    @Throws(Exception::class)
    private fun mockFailedJsonServerResponseNetworkError(networkError: IOException) {
        val headers = Collections.singletonMap("Content-Type", listOf("application/json"))
        val inputStream = AwareThrowingInputStream(networkError) { wasResponseStreamClosed = true }
        val response = ServerResponse(422, inputStream, headers)
        Mockito.`when`(
            client.load(
                eq(BASE_URL), any()
            )
        ).thenReturn(response)
    }

    /**
     * `InputStream` which informs a callback when `close()` has been called.
     */
    private class AwareInputStream(
        data: String,
        private val closedCallback: () -> Unit
    ) : ByteArrayInputStream(data.toByteArray()) {

        override fun close() {
            super.close()
            closedCallback()
        }
    }

    /**
     * `InputStream` which always throws an exception when its reading methods are called,
     * and which informs a callback when `close()` has been called.
     */
    private class AwareThrowingInputStream(
        private val networkError: IOException,
        private val closedCallback: () -> Unit
    ) : InputStream() {

        override fun close() {
            super.close()
            closedCallback()
        }

        override fun read(): Int {
            throw networkError
        }
    }

    private class SimplePojo(val prop: String)
    private companion object {
        private const val BASE_URL = "https://auth0.com"
    }
}
