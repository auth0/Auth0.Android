package com.auth0.android.request.internal

import com.auth0.android.Auth0Exception
import com.auth0.android.callback.Callback
import com.auth0.android.request.*
import com.google.gson.Gson
import com.google.gson.JsonIOException
import com.nhaarman.mockitokotlin2.*
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
import java.util.concurrent.atomic.AtomicBoolean

@RunWith(RobolectricTestRunner::class)
public class BaseRequestTest {
    private lateinit var baseRequest: BaseRequest<SimplePojo, Auth0Exception>
    private lateinit var resultAdapter: JsonAdapter<SimplePojo>
    private lateinit var errorAdapter: ErrorAdapter<Auth0Exception>

    @Mock
    private lateinit var client: NetworkingClient

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
            errorAdapter
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
                any()
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
    }

    @Test
    @Throws(Exception::class)
    public fun shouldBuildErrorFromUnsuccessfulJsonResponse() {
        val checkWasBodyClosed = mockFailedJsonServerResponse()
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
        MatcherAssert.assertThat(checkWasBodyClosed(), Matchers.`is`(true))
        verifyZeroInteractions(resultAdapter)
        verifyNoMoreInteractions(errorAdapter)
    }

    @Test
    @Throws(Exception::class)
    public fun shouldBuildErrorFromUnsuccessfulRawResponse() {
        val checkWasBodyClosed = mockFailedRawServerResponse()
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
        MatcherAssert.assertThat(checkWasBodyClosed(), Matchers.`is`(true))
        verifyZeroInteractions(resultAdapter)
        verifyNoMoreInteractions(errorAdapter)
    }

    @Test
    @Throws(Exception::class)
    public fun shouldBuildResultFromSuccessfulResponse() {
        val checkWasBodyClosed = mockSuccessfulServerResponse()
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
        verify(resultAdapter).fromJson(any())
        MatcherAssert.assertThat(checkWasBodyClosed(), Matchers.`is`(true))
        verifyNoMoreInteractions(resultAdapter)
        verifyZeroInteractions(errorAdapter)
    }

    @Test
    @Throws(Exception::class)
    public fun shouldBuildErrorFromNetworkErrorForUnsuccessfulJsonResponse() {
        val networkError = IOException("Network error")
        val checkWasBodyClosed = mockFailedJsonServerResponseNetworkError(networkError)
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
        MatcherAssert.assertThat(checkWasBodyClosed(), Matchers.`is`(true))
        verifyZeroInteractions(resultAdapter)
        verifyNoMoreInteractions(errorAdapter)
    }

    @Test
    @Throws(Exception::class)
    public fun shouldBuildErrorFromNetworkErrorForUnsuccessfulRawResponse() {
        val networkError = IOException("Network error")
        val checkWasBodyClosed = mockFailedRawServerResponseNetworkError(networkError)
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
        MatcherAssert.assertThat(checkWasBodyClosed(), Matchers.`is`(true))
        verifyZeroInteractions(resultAdapter)
        verifyNoMoreInteractions(errorAdapter)
    }

    @Test
    @Throws(Exception::class)
    public fun shouldBuildErrorFromNetworkErrorForSuccessfulResponse() {
        val networkError = IOException("Network error")
        val checkWasBodyClosed = mockSuccessfulServerResponseNetworkError(networkError)
        var exception: Exception? = null
        var result: SimplePojo? = null
        try {
            result = baseRequest.execute()
        } catch (e: Auth0Exception) {
            exception = e
        }
        MatcherAssert.assertThat(result, Matchers.`is`(Matchers.nullValue()))
        verify(resultAdapter).fromJson(any())
        MatcherAssert.assertThat(exception, Matchers.`is`(wrappingAuth0Exception))
        verify(errorAdapter).fromException(networkError)
        MatcherAssert.assertThat(checkWasBodyClosed(), Matchers.`is`(true))
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

    /**
     * @return Function indicating whether the response body `InputStream` was closed
     */
    @Throws(Exception::class)
    private fun mockSuccessfulServerResponse(): () -> Boolean {
        val headers = Collections.singletonMap("Content-Type", listOf("application/json"))
        val jsonResponse = "{\"prop\":\"test-value\"}"
        val inputStream = AwareInputStream(jsonResponse)
        val response = ServerResponse(200, inputStream, headers)
        Mockito.`when`(
            client.load(
                eq(BASE_URL), any()
            )
        ).thenReturn(response)

        return inputStream::wasClosed
    }

    /**
     * @return Function indicating whether the response body `InputStream` was closed
     */
    @Throws(Exception::class)
    private fun mockFailedRawServerResponse(): () -> Boolean {
        val headers = Collections.singletonMap("Content-Type", listOf("text/plain"))
        val textResponse = "Failure"
        val inputStream = AwareInputStream(textResponse)
        val response = ServerResponse(500, inputStream, headers)
        Mockito.`when`(
            client.load(
                eq(BASE_URL), any()
            )
        ).thenReturn(response)

        return inputStream::wasClosed
    }

    /**
     * @return Function indicating whether the response body `InputStream` was closed
     */
    @Throws(Exception::class)
    private fun mockFailedJsonServerResponse(): () -> Boolean {
        val headers = Collections.singletonMap("Content-Type", listOf("application/json"))
        val jsonResponse = "{\"error_code\":\"invalid_token\"}"
        val inputStream = AwareInputStream(jsonResponse)
        val response = ServerResponse(422, inputStream, headers)
        Mockito.`when`(
            client.load(
                eq(BASE_URL), any()
            )
        ).thenReturn(response)

        return inputStream::wasClosed
    }

    /**
     * @return Function indicating whether the response body `InputStream` was closed
     */
    @Throws(Exception::class)
    private fun mockSuccessfulServerResponseNetworkError(networkError: IOException): () -> Boolean {
        val headers = Collections.singletonMap("Content-Type", listOf("application/json"))
        val inputStream = AwareThrowingInputStream(networkError)
        val response = ServerResponse(200, inputStream, headers)
        Mockito.`when`(
            client.load(
                eq(BASE_URL), any()
            )
        ).thenReturn(response)

        return inputStream::wasClosed
    }

    /**
     * @return Function indicating whether the response body `InputStream` was closed
     */
    @Throws(Exception::class)
    private fun mockFailedRawServerResponseNetworkError(networkError: IOException): () -> Boolean {
        val headers = Collections.singletonMap("Content-Type", listOf("text/plain"))
        val inputStream = AwareThrowingInputStream(networkError)
        val response = ServerResponse(500, inputStream, headers)
        Mockito.`when`(
            client.load(
                eq(BASE_URL), any()
            )
        ).thenReturn(response)

        return inputStream::wasClosed
    }

    /**
     * @return Function indicating whether the response body `InputStream` was closed
     */
    @Throws(Exception::class)
    private fun mockFailedJsonServerResponseNetworkError(networkError: IOException): () -> Boolean {
        val headers = Collections.singletonMap("Content-Type", listOf("application/json"))
        val inputStream = AwareThrowingInputStream(networkError)
        val response = ServerResponse(422, inputStream, headers)
        Mockito.`when`(
            client.load(
                eq(BASE_URL), any()
            )
        ).thenReturn(response)

        return inputStream::wasClosed
    }

    /**
     * `InputStream` which tracks whether `close()` has been called.
     */
    private class AwareInputStream(
        data: String
    ) : ByteArrayInputStream(data.toByteArray()) {
        private val wasClosed = AtomicBoolean(false)

        override fun close() {
            super.close()
            wasClosed.set(true)
        }

        fun wasClosed() = wasClosed.get()
    }

    /**
     * `InputStream` which always throws an exception when its reading methods are called,
     * and which tracks whether `close()` has been called.
     */
    private class AwareThrowingInputStream(private val networkError: IOException) : InputStream() {
        private val wasClosed = AtomicBoolean(false)

        override fun close() {
            wasClosed.set(true)
        }

        override fun read(): Int {
            throw networkError
        }

        fun wasClosed() = wasClosed.get()
    }

    private class SimplePojo(val prop: String)
    private companion object {
        private const val BASE_URL = "https://auth0.com"
    }
}
