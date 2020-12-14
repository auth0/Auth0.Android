package com.auth0.android.request.kt

import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import com.squareup.okhttp.mockwebserver.MockResponse
import com.squareup.okhttp.mockwebserver.MockWebServer
import com.squareup.okhttp.mockwebserver.RecordedRequest
import org.hamcrest.CoreMatchers.equalTo
import org.hamcrest.CoreMatchers.hasItem
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.collection.IsMapContaining.hasEntry
import org.hamcrest.collection.IsMapWithSize.anEmptyMap
import org.junit.After
import org.junit.Before
import org.junit.Test
import java.io.BufferedReader
import java.io.InputStreamReader
import java.nio.charset.StandardCharsets
import java.util.stream.Collectors

public class DefaultClientTest {

    private companion object {
        private const val REQUEST_TIMEOUT_SECONDS = 123
        private const val STATUS_SUCCESS = 200
        private const val STATUS_FAILURE = 401
        private const val JSON_OK = """{"result":"OK"}"""
        private const val JSON_ERROR = """{"result":"error"}"""
    }

    private lateinit var BASE_URL: String
    private lateinit var mockServer: MockWebServer
    private val client: NetworkingClient = DefaultClient(REQUEST_TIMEOUT_SECONDS)
    private val gson = Gson()

    @Before
    public fun setUp() {
        mockServer = MockWebServer()
        BASE_URL = mockServer.hostName
        mockServer.start()
    }

    @After
    public fun tearDown() {
        mockServer.shutdown()
    }

    @Test
    public fun shouldHandleHttpGetSuccess() {
        enqueueMockResponse(JSON_OK, STATUS_SUCCESS)
        val options = RequestOptions(HttpMethod.GET)
        options.parameters["customer"] = "john-doe"
        options.headers["a-header"] = "b-value"

        //Server response
        val urlPath = "/api/demo"
        val response = client.load("$BASE_URL$urlPath", options)
        assertThat(response.bodyToUtf8(), equalTo(JSON_OK))
        assertThat(response.statusCode, equalTo(STATUS_SUCCESS))
        assertThat(
            response.headers,
            hasEntry(
                equalTo("Content-Type"),
                hasItem("application/json")
            )
        )

        //Sent request
        val sentRequest = mockServer.takeRequest()
        //TODO: Assert query parameters sent with latest MockWebServer dependency
        assertThat(sentRequest.path, equalTo(urlPath))
        assertThat(sentRequest.bodyFromJson(), anEmptyMap())
        assertThat(
            sentRequest.headers.toMultimap(),
            hasEntry(
                equalTo("a-header"),
                hasItem("b-value")
            )
        )
    }

    @Test
    public fun shouldHandleHttpGetFailure() {
        enqueueMockResponse(JSON_ERROR, STATUS_FAILURE)
        val options = RequestOptions(HttpMethod.GET)
        options.parameters["customer"] = "john-doe"
        options.headers["a-header"] = "b-value"

        //Server response
        val urlPath = "/api/demo"
        val response = client.load("$BASE_URL$urlPath", options)
        assertThat(response.bodyToUtf8(), equalTo(JSON_ERROR))
        assertThat(response.statusCode, equalTo(STATUS_FAILURE))
        assertThat(
            response.headers,
            hasEntry(
                equalTo("Content-Type"),
                hasItem("application/json")
            )
        )

        //Sent request
        val sentRequest = mockServer.takeRequest()
        //TODO: Assert query parameters sent with latest MockWebServer dependency
        assertThat(sentRequest.path, equalTo(urlPath))
        assertThat(sentRequest.bodyFromJson(), anEmptyMap())
        assertThat(
            sentRequest.headers.toMultimap(),
            hasEntry(
                equalTo("a-header"),
                hasItem("b-value")
            )
        )
    }

    //Helper methods

    private fun enqueueMockResponse(jsonBody: String, responseCode: Int = STATUS_SUCCESS) {
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
        val mapType = object : TypeToken<Map<String, Any>>() {}.type
        return gson.fromJson(text, mapType)
    }
}