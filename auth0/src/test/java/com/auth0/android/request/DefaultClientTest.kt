package com.auth0.android.request

import android.net.Uri
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.hamcrest.CoreMatchers.*
import org.hamcrest.MatcherAssert.assertThat
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
        private const val REQUEST_TIMEOUT_SECONDS = 123
        private const val STATUS_SUCCESS = 200
        private const val STATUS_FAILURE = 401
        private const val JSON_OK = """{"result":"OK"}"""
        private const val JSON_ERROR = """{"result":"error"}"""
        private const val URL_PATH = "/api/demo"
    }

    private lateinit var BASE_URL: String
    private lateinit var mockServer: MockWebServer
    private val client: NetworkingClient = DefaultClient(REQUEST_TIMEOUT_SECONDS)
    private val gson = Gson()

    @Before
    public fun setUp() {
        mockServer = MockWebServer()
        mockServer.start()
        BASE_URL = mockServer.url("/").toString()
    }

    @After
    public fun tearDown() {
        mockServer.shutdown()
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


    //Helper methods
    private fun requestAssertions(request: RecordedRequest, method: HttpMethod) {
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
        assertThat(
            request.headers.toMultimap(),
            hasEntry(
                equalTo("a-header"),
                hasItem("b-value")
            )
        )
    }

    private fun responseAssertions(response: ServerResponse, httpStatus: Int, bodyJson: String) {
        assertThat(response.bodyToUtf8(), equalTo(bodyJson))
        assertThat(response.statusCode, equalTo(httpStatus))
        assertThat(
            response.headers,
            hasEntry(
                equalTo("Content-Type"),
                hasItem("application/json")
            )
        )
    }

    private fun executeRequest(method: HttpMethod): ServerResponse {
        val options = RequestOptions(method)
        options.parameters["customer"] = "john-doe"
        options.headers["a-header"] = "b-value"

        //Server response
        val destination = Uri.parse(BASE_URL).buildUpon()
            .path(URL_PATH)
            .build()
            .toString()
        return client.load(destination, options)
    }

    private fun enqueueMockResponse(responseCode: Int = STATUS_SUCCESS, jsonBody: String) {
        val response = MockResponse()
        response.setBody(jsonBody)
        response.setResponseCode(responseCode)
        response.setHeader("Content-Type", "application/json")
        mockServer.enqueue(response)
    }

    private fun ServerResponse.bodyToUtf8() =
        BufferedReader(InputStreamReader(this.body, StandardCharsets.UTF_8))
            .lines()
            .collect(Collectors.joining("\n"))

    private fun RecordedRequest.bodyFromJson(): Map<String, Any> {
        val text = this.body.readUtf8()
        if (text.isNullOrEmpty()) {
            return emptyMap()
        }
        val mapType = object : TypeToken<Map<String, Any>>() {}.type
        return gson.fromJson(text, mapType)
    }
}