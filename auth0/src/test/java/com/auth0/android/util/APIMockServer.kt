package com.auth0.android.util

import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import java.io.IOException

internal abstract class APIMockServer {
    val server: MockWebServer = SSLTestUtils.createMockWebServer()
    val domain: String
        get() = server.url("/").toString()

    @Throws(IOException::class)
    fun shutdown() {
        server.shutdown()
    }

    @Throws(InterruptedException::class)
    fun takeRequest(): RecordedRequest {
        return server.takeRequest()
    }

    fun responseWithJSON(json: String, statusCode: Int): MockResponse {
        return MockResponse()
            .setResponseCode(statusCode)
            .addHeader("Content-Type", "application/json")
            .setBody(json)
    }

    fun responseWithJSON(json: String, statusCode: Int, header: Map<String, String>): MockResponse {
        val response = MockResponse()
            .setResponseCode(statusCode)
            .addHeader("Content-Type", "application/json")
            .setBody(json)

        header.forEach { (key, value) ->
            response.addHeader(key, value)
        }
        return response
    }

    init {
        server.start()
    }
}