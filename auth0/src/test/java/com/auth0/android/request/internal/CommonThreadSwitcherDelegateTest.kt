package com.auth0.android.request.internal

import com.auth0.android.Auth0Exception
import com.auth0.android.callback.Callback
import com.auth0.android.request.*
import com.auth0.android.util.CommonThreadSwitcherRule
import com.google.gson.Gson
import com.nhaarman.mockitokotlin2.*
import org.hamcrest.MatcherAssert
import org.hamcrest.Matchers
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TestWatcher
import org.mockito.ArgumentMatchers
import org.mockito.Mock
import org.mockito.Mockito
import org.mockito.MockitoAnnotations
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.util.*

public class CommonThreadSwitcherDelegateTest {

    @get:Rule
    public val commonThreadSwitcherRule: TestWatcher = CommonThreadSwitcherRule()

    private lateinit var baseRequest: BaseRequest<SimplePojo, Auth0Exception>
    private lateinit var resultAdapter: JsonAdapter<SimplePojo>

    @Mock
    private lateinit var client: NetworkingClient

    @Mock
    private lateinit var errorAdapter: ErrorAdapter<Auth0Exception>

    @Mock
    private lateinit var auth0Exception: Auth0Exception

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
    public fun shouldExecuteSuccessfulRequestSynchronously() {
        val baseRequest = BaseRequest(
            HttpMethod.POST,
            BASE_URL,
            client,
            resultAdapter,
            errorAdapter
        )
        mockSuccessfulServerResponse()
        val callback: Callback<SimplePojo, Auth0Exception> = mock()

        baseRequest.start(callback)
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
    public fun shouldReturnFailureSynchronously() {
        val baseRequest = BaseRequest(
            HttpMethod.POST,
            BASE_URL,
            client,
            resultAdapter,
            errorAdapter
        )
        mockFailedRawServerResponse()
        val callback: Callback<SimplePojo, Auth0Exception> = mock()

        baseRequest.start(callback)
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

    private class SimplePojo(val prop: String)
    private companion object {
        private const val BASE_URL = "https://auth0.com"
    }
}
