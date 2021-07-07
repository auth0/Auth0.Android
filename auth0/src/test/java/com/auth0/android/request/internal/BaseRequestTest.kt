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
import org.mockito.ArgumentMatchers
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

    @Mock
    private lateinit var client: NetworkingClient

    @Mock
    private lateinit var errorAdapter: ErrorAdapter<Auth0Exception>

    @Mock
    private lateinit var auth0Exception: Auth0Exception

    private val optionsCaptor: KArgumentCaptor<RequestOptions> = argumentCaptor()

    private val readerCaptor: KArgumentCaptor<Reader> = argumentCaptor()

    @Before
    public fun setUp() {
        MockitoAnnotations.openMocks(this)
        resultAdapter = Mockito.spy(GsonAdapter(SimplePojo::class.java, Gson()))
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
        val networkError = mock<IOException>()
        Mockito.`when`(
            client.load(
                eq(BASE_URL), any()
            )
        ).thenThrow(networkError)
        Mockito.`when`(
            errorAdapter.fromException(
                any()
            )
        ).thenReturn(auth0Exception)
        var exception: Exception? = null
        var result: SimplePojo? = null
        try {
            result = baseRequest.execute()
        } catch (e: Exception) {
            exception = e
        }
        MatcherAssert.assertThat(exception, Matchers.`is`(auth0Exception))
        MatcherAssert.assertThat(result, Matchers.`is`(Matchers.nullValue()))
        verifyZeroInteractions(resultAdapter)
        verify(errorAdapter).fromException(eq(networkError))
    }

    @Test
    @Throws(Exception::class)
    public fun shouldBuildErrorFromResponseParseException() {
        mockSuccessfulServerResponse()
        val resultAdapter = Mockito.mock(GsonAdapter::class.java) as JsonAdapter<SimplePojo>
        val baseRequest = BaseRequest(
            HttpMethod.POST,
            BASE_URL,
            client,
            resultAdapter,
            errorAdapter
        )
        val networkError = mock<JsonIOException>()
        Mockito.`when`(
            resultAdapter.fromJson(
                any()
            )
        ).thenThrow(networkError)
        Mockito.`when`(
            errorAdapter.fromException(
                any()
            )
        ).thenReturn(auth0Exception)
        var exception: Exception? = null
        var result: SimplePojo? = null
        try {
            result = baseRequest.execute()
        } catch (e: Exception) {
            exception = e
        }
        MatcherAssert.assertThat(exception, Matchers.`is`(auth0Exception))
        MatcherAssert.assertThat(result, Matchers.`is`(Matchers.nullValue()))
        verify(errorAdapter).fromException(eq(networkError))
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
        MatcherAssert.assertThat(exception, Matchers.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(exception, Matchers.`is`(auth0Exception))
        verify(errorAdapter).fromJsonResponse(
            eq(422), any()
        )
        val reader = readerCaptor.firstValue
        MatcherAssert.assertThat(reader, Matchers.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            reader, Matchers.`is`(
                Matchers.instanceOf(
                    AwareInputStreamReader::class.java
                )
            )
        )
        val awareReader = reader as AwareInputStreamReader
        MatcherAssert.assertThat(awareReader.isClosed, Matchers.`is`(true))
        verifyZeroInteractions(resultAdapter)
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
        MatcherAssert.assertThat(exception, Matchers.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(exception, Matchers.`is`(auth0Exception))
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
        verifyZeroInteractions(resultAdapter)
    }

    @Test
    @Throws(Exception::class)
    public fun shouldBuildResultFromSuccessfulResponse() {
        mockSuccessfulServerResponse()
        var exception: Exception? = null
        var result: SimplePojo? = null
        try {
            result = baseRequest.execute()
        } catch (e: Exception) {
            exception = e
        }
        MatcherAssert.assertThat(exception, Matchers.`is`(Matchers.nullValue()))
        MatcherAssert.assertThat(result, Matchers.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(result!!.prop, Matchers.`is`("test-value"))
        verify(resultAdapter).fromJson(
            readerCaptor.capture()
        )
        val reader = readerCaptor.firstValue
        MatcherAssert.assertThat(reader, Matchers.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            reader, Matchers.`is`(
                Matchers.instanceOf(
                    AwareInputStreamReader::class.java
                )
            )
        )
        val awareReader = reader as AwareInputStreamReader
        MatcherAssert.assertThat(awareReader.isClosed, Matchers.`is`(true))
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

    @Throws(Exception::class)
    private fun mockSuccessfulServerResponse() {
        val headers = Collections.singletonMap("Content-Type", listOf("application/json"))
        val jsonResponse = "{\"prop\":\"test-value\"}"
        val inputStream: InputStream = ByteArrayInputStream(jsonResponse.toByteArray())
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
        val inputStream: InputStream = ByteArrayInputStream(textResponse.toByteArray())
        Mockito.`when`(
            errorAdapter.fromRawResponse(
                eq(500),
                ArgumentMatchers.anyString(),
                ArgumentMatchers.anyMap()
            )
        ).thenReturn(auth0Exception)
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
        val inputStream: InputStream = ByteArrayInputStream(jsonResponse.toByteArray())
        Mockito.`when`(
            errorAdapter.fromJsonResponse(
                eq(422),
                readerCaptor.capture()
            )
        ).thenReturn(auth0Exception)
        val response = ServerResponse(422, inputStream, headers)
        Mockito.`when`(
            client.load(
                eq(BASE_URL), any()
            )
        ).thenReturn(response)
    }

    private class SimplePojo(val prop: String)
    private companion object {
        private const val BASE_URL = "https://auth0.com"
    }
}
