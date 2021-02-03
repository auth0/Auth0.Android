package com.auth0.android.util

import com.auth0.android.request.SSLTestUtils.createMockWebServer
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Paths

internal class AuthenticationAPIMockServer {
    private val server: MockWebServer = createMockWebServer()
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

    fun willReturnValidApplicationResponse(): AuthenticationAPIMockServer {
        return willReturnApplicationResponseWithBody(
            "Auth0.setClient({\"id\":\"CLIENTID\",\"tenant\":\"overmind\",\"subscription\":\"free\",\"authorize\":\"https://samples.auth0.com/authorize\",\"callback\":\"http://localhost:3000/\",\"hasAllowedOrigins\":true,\"strategies\":[{\"name\":\"twitter\",\"connections\":[{\"name\":\"twitter\"}]}]});",
            200
        )
    }

    fun willReturnSuccessfulChangePassword(): AuthenticationAPIMockServer {
        server.enqueue(responseWithJSON("NOT REALLY A JSON", 200))
        return this
    }

    fun willReturnSuccessfulPasswordlessStart(): AuthenticationAPIMockServer {
        val json = """{
          "phone+number": "+1098098098"
        }"""
        server.enqueue(responseWithJSON(json, 200))
        return this
    }

    fun willReturnNewIdToken(): AuthenticationAPIMockServer {
        val json = """{
          "id_token": "$NEW_ID_TOKEN",
          "expires_in": $EXPIRES_IN,
          "token_type": "$TOKEN_TYPE"
        }"""
        server.enqueue(responseWithJSON(json, 200))
        return this
    }

    fun willReturnSuccessfulSignUp(): AuthenticationAPIMockServer {
        val json = """{
          "_id": "gjsmgdkjs72jljsf2dsdhh", 
          "email": "support@auth0.com", 
          "email_verified": false, 
          "username": "support"
        }"""
        server.enqueue(responseWithJSON(json, 200))
        return this
    }

    fun willReturnSuccessfulEmptyBody(): AuthenticationAPIMockServer {
        server.enqueue(responseEmpty(200))
        return this
    }

    fun willReturnSuccessfulLogin(): AuthenticationAPIMockServer {
        val json = """{
          "refresh_token": "$REFRESH_TOKEN",
          "id_token": "$ID_TOKEN",
          "access_token": "$ACCESS_TOKEN",
          "token_type": "$BEARER"
        }"""
        server.enqueue(responseWithJSON(json, 200))
        return this
    }

    fun willReturnInvalidRequest(): AuthenticationAPIMockServer {
        val json = """{
          "error": "invalid_request",
          "error_description": "a random error"
        }"""
        server.enqueue(responseWithJSON(json, 400))
        return this
    }

    fun willReturnEmptyJsonWebKeys(): AuthenticationAPIMockServer {
        val json = """{
          "keys": []
        }"""
        server.enqueue(responseWithJSON(json, 200))
        return this
    }

    fun willReturnValidJsonWebKeys(): AuthenticationAPIMockServer {
        try {
            val encoded = Files.readAllBytes(Paths.get("src/test/resources/rsa_jwks.json"))
            val json = String(encoded)
            server.enqueue(responseWithJSON(json, 200))
        } catch (ignored: Exception) {
            println("File parsing error")
        }
        return this
    }

    fun willReturnUserInfo(): AuthenticationAPIMockServer {
        val json = """{
          "email": "p@p.xom",
          "email_verified": false,
          "picture": "https://secure.gravatar.com/avatar/cfacbe113a96fdfc85134534771d88b4?s=480&r=pg&d=https%3A%2F%2Fssl.gstatic.com%2Fs2%2Fprofiles%2Fimages%2Fsilhouette80.png",
          "user_id": "auth0|53b995f8bce68d9fc900099c",
          "name": "p@p.xom",
          "nickname": "p",
          "identities": [
            {
              "user_id": "53b995f8bce68d9fc900099c",
              "provider": "auth0",
              "connection": "Username-Password-Authentication",
              "isSocial": false
            }
         ],
          "created_at": "2014-07-06T18:33:49.005Z",
          "username": "p",
          "updated_at": "2015-09-30T19:43:48.499Z"
        }"""
        server.enqueue(responseWithJSON(json, 200))
        return this
    }

    fun willReturnPlainTextUnauthorized(): AuthenticationAPIMockServer {
        server.enqueue(responseWithPlainText("Unauthorized", 401))
        return this
    }

    fun willReturnTokens(): AuthenticationAPIMockServer {
        val json = """{
          "access_token": "$ACCESS_TOKEN",
          "refresh_token": "$REFRESH_TOKEN",
          "id_token": "$ID_TOKEN",
          "token_type": "Bearer"
        }"""
        server.enqueue(responseWithJSON(json, 200))
        return this
    }

    private fun willReturnApplicationResponseWithBody(
        body: String?,
        statusCode: Int
    ): AuthenticationAPIMockServer {
        val response = MockResponse()
            .setResponseCode(statusCode)
            .addHeader("Content-Type", "application/x-javascript")
            .setBody(body!!)
        server.enqueue(response)
        return this
    }

    private fun responseEmpty(statusCode: Int): MockResponse {
        return MockResponse()
            .setResponseCode(statusCode)
    }

    private fun responseWithPlainText(statusMessage: String, statusCode: Int): MockResponse {
        return MockResponse()
            .setResponseCode(statusCode)
            .addHeader("Content-Type", "text/plain")
            .setBody(statusMessage)
    }

    private fun responseWithJSON(json: String, statusCode: Int): MockResponse {
        return MockResponse()
            .setResponseCode(statusCode)
            .addHeader("Content-Type", "application/json")
            .setBody(json)
    }

    companion object {
        const val REFRESH_TOKEN = "REFRESH_TOKEN"
        const val ID_TOKEN = "ID_TOKEN"
        const val ACCESS_TOKEN = "ACCESS_TOKEN"
        private const val BEARER = "BEARER"
        const val GENERIC_TOKEN = "GENERIC_TOKEN"
        private const val NEW_ID_TOKEN = "NEW_ID_TOKEN"
        private const val TOKEN_TYPE = "TOKEN_TYPE"
        private const val EXPIRES_IN = 1234567890
    }

    init {
        server.start()
    }
}