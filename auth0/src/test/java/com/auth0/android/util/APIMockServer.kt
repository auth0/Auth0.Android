package com.auth0.android.util

import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import mockwebserver3.RecordedRequest
import java.io.IOException

internal abstract class APIMockServer {
    val server: MockWebServer = SSLTestUtils.createMockWebServer()
    val domain: String
        get() = server.url("/").toString()

    @Throws(IOException::class)
    fun shutdown() {
        server.close()
    }

    @Throws(InterruptedException::class)
    fun takeRequest(): RecordedRequest {
        return server.takeRequest()
    }

    fun responseWithJSON(json: String, statusCode: Int): MockResponse {
        return MockResponse.Builder()
            .code(statusCode)
            .addHeader("Content-Type", "application/json")
            .body(json)
            .build()
    }

    fun responseWithJSON(json: String, statusCode: Int, header: Map<String, String>): MockResponse {
        val builder = MockResponse.Builder()
            .code(statusCode)
            .addHeader("Content-Type", "application/json")
            .body(json)

        header.forEach { (key, value) ->
            builder.addHeader(key, value)
        }
        return builder.build()
    }

    init {
        server.start()
    }
}