package com.auth0.android.request

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Ignore
import org.junit.Test
import org.mockito.Mockito.mock
import java.io.InputStream

@Ignore
public class ServerResponseTest {

    @Test
    public fun shouldDetectSuccessfulResponse() {
        val responseSuccess = ServerResponse(
            200,
            mock(InputStream::class.java),
            emptyMap()
        )
        val responseNoContent = ServerResponse(
            204,
            mock(InputStream::class.java),
            emptyMap()
        )
        assertTrue(responseSuccess.isSuccess())
        assertTrue(responseNoContent.isSuccess())
    }

    @Test
    public fun shouldDetectFailedResponse() {
        val responseMultipleChoices = ServerResponse(
            300,
            mock(InputStream::class.java),
            emptyMap()
        )
        val responseUnauthorized = ServerResponse(
            401,
            mock(InputStream::class.java),
            emptyMap()
        )
        assertFalse(responseMultipleChoices.isSuccess())
        assertFalse(responseUnauthorized.isSuccess())
    }

    @Test
    public fun shouldDetectJsonContentHeader() {
        val responseMixed = ServerResponse(
            200,
            mock(InputStream::class.java),
            mapOf("Content-Type" to listOf("application/json"))
        )
        val responseMixedCombined = ServerResponse(
            200,
            mock(InputStream::class.java),
            mapOf("Content-Type" to listOf("application/json; charset=UTF-8"))
        )
        val responseLower = ServerResponse(
            200,
            mock(InputStream::class.java),
            mapOf("content-type" to listOf("application/json"))
        )
        val responseUpper = ServerResponse(
            200,
            mock(InputStream::class.java),
            mapOf("CONTENT-TYPE" to listOf("application/json"))
        )
        val responseNotJSON = ServerResponse(
            200,
            mock(InputStream::class.java),
            mapOf("CONTENT-TYPE" to listOf("text/html"))
        )
        val responseEmpty = ServerResponse(
            200,
            mock(InputStream::class.java),
            mapOf()
        )

        assertTrue(responseMixed.isJson())
        assertTrue(responseMixedCombined.isJson())
        assertTrue(responseLower.isJson())
        assertTrue(responseUpper.isJson())
        assertFalse(responseNotJSON.isJson())
        assertFalse(responseEmpty.isJson())
    }
}