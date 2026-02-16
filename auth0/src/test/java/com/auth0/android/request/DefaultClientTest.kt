package com.auth0.android.request

import android.net.Uri
import com.auth0.android.util.SSLTestUtils
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import okhttp3.Interceptor
import okhttp3.logging.HttpLoggingInterceptor
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.hamcrest.CoreMatchers.*
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.Matchers.hasSize
import org.hamcrest.collection.IsMapContaining.hasEntry
import org.hamcrest.collection.IsMapWithSize.anEmptyMap
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.BufferedReader
import java.io.InputStreamReader
import java.nio.charset.StandardCharsets
import java.util.stream.Collectors

@RunWith(RobolectricTestRunner::class)
public class DefaultClientTest {

    private companion object {
        private const val STATUS_SUCCESS = 200
        private const val STATUS_FAILURE = 401
        private const val JSON_OK = """{"result":"OK"}"""
        private const val JSON_ERROR = """{"result":"error"}"""
        private const val URL_PATH = "/api/demo"
    }

    private lateinit var baseUrl: String
    private lateinit var mockServer: MockWebServer
    private val gson = Gson()

    private val defaultClient: NetworkingClient = SSLTestUtils.testClient

    @Before
    public fun setUp() {
        mockServer = SSLTestUtils.createMockWebServer()
        mockServer.start()
        baseUrl = mockServer.url("/").toString()
    }

    @After
    public fun tearDown() {
        mockServer.shutdown()
    }

    @Test
    public fun shouldAddDefaultHeadersToRequests() {
        enqueueMockResponse(STATUS_SUCCESS, JSON_OK)
        executeRequest(
            HttpMethod.GET,
            createDefaultClientForTest(defaultHeaders = mapOf("custom-header" to "custom-value"))
        )

        val sentRequest = mockServer.takeRequest()
        requestAssertions(sentRequest, HttpMethod.GET, mapOf("custom-header" to "custom-value"))
    }

    @Test
    public fun shouldOverrideDefaultHeadersWithRequestHeadersIfSameKey() {
        enqueueMockResponse(STATUS_SUCCESS, JSON_OK)

        executeRequest(
            HttpMethod.GET,
            createDefaultClientForTest(defaultHeaders = mapOf("a-header" to "a-value")),
            requestHeaders = mutableMapOf("a-header" to "updated-value")
        )

        val sentRequest = mockServer.takeRequest()
        requestAssertions(sentRequest, HttpMethod.GET, mapOf("a-header" to "updated-value"))
    }

    @Test
    @Suppress("DEPRECATION")
    public fun shouldHaveLoggingDisabledByDefault() {
        val netClient = DefaultClient(enableLogging = false)
        assertThat(netClient.okHttpClient.interceptors, hasSize(1))
        val interceptor: Interceptor = netClient.okHttpClient.interceptors[0]
        assert(
            interceptor is RetryInterceptor,
        )
    }

    @Test
    @Suppress("DEPRECATION")
    public fun shouldHaveRetryInterceptorEnabled() {
        val netClient = DefaultClient(enableLogging = false)
        assertThat(netClient.okHttpClient.interceptors, hasSize(1))
        val interceptor: Interceptor = netClient.okHttpClient.interceptors[0]
        assert(
            interceptor is RetryInterceptor,
        )
    }

    @Test
    @Suppress("DEPRECATION")
    public fun shouldHaveLoggingEnabledIfSpecified() {
        val netClient = DefaultClient(enableLogging = true)
        assertThat(netClient.okHttpClient.interceptors, hasSize(2))

        val interceptor: Interceptor = netClient.okHttpClient.interceptors[1]
        assertThat(
            (interceptor as HttpLoggingInterceptor).level,
            equalTo(HttpLoggingInterceptor.Level.BODY)
        )
    }

    @Test
    @Suppress("DEPRECATION")
    public fun shouldHaveDefaultTimeoutValues() {
        val client = DefaultClient()
        assertThat(client.okHttpClient.connectTimeoutMillis, equalTo(10 * 1000))
        assertThat(client.okHttpClient.readTimeoutMillis, equalTo(10 * 1000))
    }

    @Test
    @Suppress("DEPRECATION")
    public fun shouldUseTimeoutConfigIfSpecified() {
        val client = DefaultClient(connectTimeout = 100, readTimeout = 200)
        assertThat(client.okHttpClient.connectTimeoutMillis, equalTo(100 * 1000))
        assertThat(client.okHttpClient.readTimeoutMillis, equalTo(200 * 1000))
    }

    @Test
    public fun shouldHandleHttpGetSuccess() {
        enqueueMockResponse(STATUS_SUCCESS, JSON_OK)

        //Received response
        val response = executeRequest(HttpMethod.GET)
        responseAssertions(response, STATUS_SUCCESS, JSON_OK)

        //Sent request
        val sentRequest = mockServer.takeRequest()
        requestAssertions(sentRequest, HttpMethod.GET)
    }

    @Test
    public fun shouldHandleHttpGetFailure() {
        enqueueMockResponse(STATUS_FAILURE, JSON_ERROR)

        //Received response
        val response = executeRequest(HttpMethod.GET)
        responseAssertions(response, STATUS_FAILURE, JSON_ERROR)

        //Sent request
        val sentRequest = mockServer.takeRequest()
        requestAssertions(sentRequest, HttpMethod.GET)
    }

    @Test
    public fun shouldHandleHttpPostSuccess() {
        enqueueMockResponse(STATUS_SUCCESS, JSON_OK)

        //Received response
        val response = executeRequest(HttpMethod.POST)
        responseAssertions(response, STATUS_SUCCESS, JSON_OK)

        //Sent request
        val sentRequest = mockServer.takeRequest()
        requestAssertions(sentRequest, HttpMethod.POST)
    }

    @Test
    public fun shouldHandleHttpPostFailure() {
        enqueueMockResponse(STATUS_FAILURE, JSON_ERROR)

        //Received response
        val response = executeRequest(HttpMethod.POST)
        responseAssertions(response, STATUS_FAILURE, JSON_ERROR)

        //Sent request
        val sentRequest = mockServer.takeRequest()
        requestAssertions(sentRequest, HttpMethod.POST)
    }

    @Test
    public fun shouldHandleHttpDeleteSuccess() {
        enqueueMockResponse(STATUS_SUCCESS, JSON_OK)

        //Received response
        val response = executeRequest(HttpMethod.DELETE)
        responseAssertions(response, STATUS_SUCCESS, JSON_OK)

        //Sent request
        val sentRequest = mockServer.takeRequest()
        requestAssertions(sentRequest, HttpMethod.DELETE)
    }

    @Test
    public fun shouldHandleHttpDeleteFailure() {
        enqueueMockResponse(STATUS_FAILURE, JSON_ERROR)

        //Received response
        val response = executeRequest(HttpMethod.DELETE)
        responseAssertions(response, STATUS_FAILURE, JSON_ERROR)

        //Sent request
        val sentRequest = mockServer.takeRequest()
        requestAssertions(sentRequest, HttpMethod.DELETE)
    }

    @Test
    public fun shouldHandleHttpPatchSuccess() {
        enqueueMockResponse(STATUS_SUCCESS, JSON_OK)

        //Received response
        val response = executeRequest(HttpMethod.PATCH)
        responseAssertions(response, STATUS_SUCCESS, JSON_OK)

        //Sent request
        val sentRequest = mockServer.takeRequest()
        requestAssertions(sentRequest, HttpMethod.PATCH)
    }

    @Test
    public fun shouldHandleHttpPatchFailure() {
        enqueueMockResponse(STATUS_FAILURE, JSON_ERROR)

        //Received response
        val response = executeRequest(HttpMethod.PATCH)
        responseAssertions(response, STATUS_FAILURE, JSON_ERROR)

        //Sent request
        val sentRequest = mockServer.takeRequest()
        requestAssertions(sentRequest, HttpMethod.PATCH)
    }

    @Test
    public fun shouldHaveNonRetryableClientConfigured() {
        val client = createDefaultClientForTest(mapOf())

        assertThat(client.okHttpClient, notNullValue())
        assertThat(client.nonRetryableOkHttpClient, notNullValue())

        assertThat(client.okHttpClient.retryOnConnectionFailure, equalTo(true))
        assertThat(client.nonRetryableOkHttpClient.retryOnConnectionFailure, equalTo(false))
    }

    @Test
    public fun shouldShareSameConfigBetweenClients() {
        val client = createDefaultClientForTest(mapOf())

        assertThat(
            client.okHttpClient.interceptors.size,
            equalTo(client.nonRetryableOkHttpClient.interceptors.size)
        )

        assertThat(
            client.okHttpClient.interceptors[0] is RetryInterceptor,
            equalTo(true)
        )
        assertThat(
            client.nonRetryableOkHttpClient.interceptors[0] is RetryInterceptor,
            equalTo(true)
        )
        assertThat(
            client.okHttpClient.connectTimeoutMillis,
            equalTo(client.nonRetryableOkHttpClient.connectTimeoutMillis)
        )
        assertThat(
            client.okHttpClient.readTimeoutMillis,
            equalTo(client.nonRetryableOkHttpClient.readTimeoutMillis)
        )
    }

    //Helper methods
    private fun requestAssertions(
        request: RecordedRequest,
        method: HttpMethod,
        headers: Map<String, String> = mapOf("a-header" to "b-value")
    ) {
        val requestUri = Uri.parse(request.path)
        when (method) {
            HttpMethod.GET -> assertThat(request.method, equalTo("GET"))
            HttpMethod.POST -> assertThat(request.method, equalTo("POST"))
            HttpMethod.PATCH -> assertThat(request.method, equalTo("PATCH"))
            HttpMethod.DELETE -> assertThat(request.method, equalTo("DELETE"))
        }
        assertThat(requestUri.path, equalTo(URL_PATH))

        if (method == HttpMethod.GET) {
            assertThat(requestUri.getQueryParameter("customer"), equalTo("john-doe"))
            assertThat(request.bodyFromJson(), anEmptyMap())
        } else {
            assertThat(requestUri.query, nullValue())
            assertThat(request.bodyFromJson(), hasEntry("customer", "john-doe"))
        }
        val requestHeaders = request.headers.toMultimap()
        headers.forEach { (k, v) ->
            assertThat(
                requestHeaders, hasEntry(
                    equalTo(k), hasItem(v)
                )
            )
            assertThat(requestHeaders[k], hasSize(1))
        }
    }

    private fun responseAssertions(response: ServerResponse, httpStatus: Int, bodyJson: String) {
        assertThat(response.bodyToUtf8(), equalTo(bodyJson))
        assertThat(response.statusCode, equalTo(httpStatus))
        assertThat(
            response.headers,
            hasEntry(
                equalTo("content-type"),
                hasItem("application/json")
            )
        )
    }

    private fun executeRequest(
        method: HttpMethod,
        client: NetworkingClient = defaultClient,
        requestHeaders: MutableMap<String, String> = mutableMapOf("a-header" to "b-value")
    ): ServerResponse {
        val options = RequestOptions(method)
        options.parameters["customer"] = "john-doe"
        options.headers.putAll(requestHeaders)

        //Server response
        val destination = Uri.parse(baseUrl).buildUpon()
            .path(URL_PATH)
            .build()
            .toString()
        return client.load(destination, options)
    }

    private fun enqueueMockResponse(responseCode: Int = STATUS_SUCCESS, jsonBody: String) {
        val response = MockResponse()
        response.setBody(jsonBody)
        response.setResponseCode(responseCode)
        response.setHeader("content-type", "application/json")
        mockServer.enqueue(response)
    }

    private fun ServerResponse.bodyToUtf8() =
        BufferedReader(InputStreamReader(this.body, StandardCharsets.UTF_8))
            .lines()
            .collect(Collectors.joining("\n"))

    private fun RecordedRequest.bodyFromJson(): Map<String, Any> {
        val text = this.body.readUtf8()
        if (text.isEmpty()) {
            return emptyMap()
        }
        val mapType = object : TypeToken<Map<String, Any>>() {}.type
        return gson.fromJson(text, mapType)
    }

    private fun createDefaultClientForTest(defaultHeaders: Map<String, String>): DefaultClient {
        return DefaultClient.Builder()
            .connectTimeout(10)
            .readTimeout(10)
            .defaultHeaders(defaultHeaders)
            .enableLogging(false)
            .gson(gson)
            .sslSocketFactory(
                SSLTestUtils.clientCertificates.sslSocketFactory(),
                SSLTestUtils.clientCertificates.trustManager
            )
            .build()
    }

    @Test
    public fun builderShouldCreateClientWithDefaultValues() {
        val client = DefaultClient.Builder().build()
        assertThat(client.okHttpClient.connectTimeoutMillis, equalTo(10 * 1000))
        assertThat(client.okHttpClient.readTimeoutMillis, equalTo(10 * 1000))
        assertThat(client.okHttpClient.writeTimeoutMillis, equalTo(10 * 1000))
        assertThat(client.okHttpClient.callTimeoutMillis, equalTo(0))
        assertThat(client.okHttpClient.interceptors, hasSize(1))
        assertThat(client.okHttpClient.interceptors[0] is RetryInterceptor, equalTo(true))
    }

    @Test
    public fun builderShouldSetConnectTimeout() {
        val client = DefaultClient.Builder()
            .connectTimeout(30)
            .build()
        assertThat(client.okHttpClient.connectTimeoutMillis, equalTo(30 * 1000))
    }

    @Test
    public fun builderShouldSetReadTimeout() {
        val client = DefaultClient.Builder()
            .readTimeout(45)
            .build()
        assertThat(client.okHttpClient.readTimeoutMillis, equalTo(45 * 1000))
    }

    @Test
    public fun builderShouldSetWriteTimeout() {
        val client = DefaultClient.Builder()
            .writeTimeout(20)
            .build()
        assertThat(client.okHttpClient.writeTimeoutMillis, equalTo(20 * 1000))
    }

    @Test
    public fun builderShouldSetCallTimeout() {
        val client = DefaultClient.Builder()
            .callTimeout(60)
            .build()
        assertThat(client.okHttpClient.callTimeoutMillis, equalTo(60 * 1000))
    }

    @Test
    public fun builderShouldSetAllTimeouts() {
        val client = DefaultClient.Builder()
            .connectTimeout(15)
            .readTimeout(25)
            .writeTimeout(35)
            .callTimeout(120)
            .build()
        assertThat(client.okHttpClient.connectTimeoutMillis, equalTo(15 * 1000))
        assertThat(client.okHttpClient.readTimeoutMillis, equalTo(25 * 1000))
        assertThat(client.okHttpClient.writeTimeoutMillis, equalTo(35 * 1000))
        assertThat(client.okHttpClient.callTimeoutMillis, equalTo(120 * 1000))
    }

    @Test
    public fun builderShouldEnableLoggingWithDefaultLevel() {
        val client = DefaultClient.Builder()
            .enableLogging(true)
            .build()
        assertThat(client.okHttpClient.interceptors, hasSize(2))
        val loggingInterceptor = client.okHttpClient.interceptors[1] as HttpLoggingInterceptor
        assertThat(loggingInterceptor.level, equalTo(HttpLoggingInterceptor.Level.BODY))
    }

    @Test
    public fun builderShouldNotAddLoggingInterceptorWhenDisabled() {
        val client = DefaultClient.Builder()
            .enableLogging(false)
            .build()
        assertThat(client.okHttpClient.interceptors, hasSize(1))
        assertThat(client.okHttpClient.interceptors[0] is RetryInterceptor, equalTo(true))
    }

    @Test
    public fun builderShouldSetCustomLogger() {
        val logs = mutableListOf<String>()
        val customLogger = HttpLoggingInterceptor.Logger { message -> logs.add(message) }

        val client = DefaultClient.Builder()
            .enableLogging(true)
            .logger(customLogger)
            .sslSocketFactory(
                SSLTestUtils.clientCertificates.sslSocketFactory(),
                SSLTestUtils.clientCertificates.trustManager
            )
            .build()

        assertThat(client.okHttpClient.interceptors, hasSize(2))
        assertThat(client.okHttpClient.interceptors[1] is HttpLoggingInterceptor, equalTo(true))

        enqueueMockResponse(STATUS_SUCCESS, JSON_OK)
        executeRequest(HttpMethod.GET, client)
        assertThat(logs.isEmpty(), equalTo(false))
    }

    @Test
    public fun builderShouldSetDefaultHeaders() {
        enqueueMockResponse(STATUS_SUCCESS, JSON_OK)
        val client = DefaultClient.Builder()
            .defaultHeaders(mapOf("x-custom" to "test-value"))
            .sslSocketFactory(
                SSLTestUtils.clientCertificates.sslSocketFactory(),
                SSLTestUtils.clientCertificates.trustManager
            )
            .build()

        executeRequest(HttpMethod.GET, client)
        val sentRequest = mockServer.takeRequest()
        requestAssertions(sentRequest, HttpMethod.GET, mapOf("x-custom" to "test-value"))
    }

    @Test
    public fun builderNonRetryableClientShouldInheritConfiguration() {
        val client = DefaultClient.Builder()
            .connectTimeout(25)
            .readTimeout(35)
            .writeTimeout(45)
            .enableLogging(true)
            .build()

        assertThat(
            client.nonRetryableOkHttpClient.connectTimeoutMillis,
            equalTo(client.okHttpClient.connectTimeoutMillis)
        )
        assertThat(
            client.nonRetryableOkHttpClient.readTimeoutMillis,
            equalTo(client.okHttpClient.readTimeoutMillis)
        )
        assertThat(
            client.nonRetryableOkHttpClient.writeTimeoutMillis,
            equalTo(client.okHttpClient.writeTimeoutMillis)
        )
        assertThat(
            client.nonRetryableOkHttpClient.interceptors.size,
            equalTo(client.okHttpClient.interceptors.size)
        )
        assertThat(client.okHttpClient.retryOnConnectionFailure, equalTo(true))
        assertThat(client.nonRetryableOkHttpClient.retryOnConnectionFailure, equalTo(false))
    }

    @Test
    @Suppress("DEPRECATION")
    public fun legacyConstructorShouldStillWork() {
        val client = DefaultClient()
        assertThat(client.okHttpClient.connectTimeoutMillis, equalTo(10 * 1000))
        assertThat(client.okHttpClient.readTimeoutMillis, equalTo(10 * 1000))
        assertThat(client.okHttpClient.interceptors, hasSize(1))
        assertThat(client.okHttpClient.interceptors[0] is RetryInterceptor, equalTo(true))
    }

    @Test
    @Suppress("DEPRECATION")
    public fun legacyConstructorWithParamsShouldStillWork() {
        val client = DefaultClient(
            connectTimeout = 30,
            readTimeout = 45,
            defaultHeaders = mapOf("X-Test" to "value"),
            enableLogging = true
        )
        assertThat(client.okHttpClient.connectTimeoutMillis, equalTo(30 * 1000))
        assertThat(client.okHttpClient.readTimeoutMillis, equalTo(45 * 1000))
        assertThat(client.okHttpClient.interceptors, hasSize(2))
        assertThat(client.okHttpClient.interceptors[0] is RetryInterceptor, equalTo(true))
        assertThat(client.okHttpClient.interceptors[1] is HttpLoggingInterceptor, equalTo(true))
    }
}