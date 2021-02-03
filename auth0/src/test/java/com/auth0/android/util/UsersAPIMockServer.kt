package com.auth0.android.util

import com.auth0.android.request.SSLTestUtils.createMockWebServer
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import java.io.IOException

internal class UsersAPIMockServer {
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

    fun willReturnSuccessfulUnlink(): UsersAPIMockServer {
        val json = """[
          {
            "profileData": {
              "email": "asd@asd.asd",
              "email_verified": true,
              "nickname": "asdasd",
              "username": "asdasd"
            },
            "user_id": "123d123d123d123d123d123d",
            "provider": "auth0",
            "connection": "Username-Password-Authentication",
            "isSocial": false
          }
        ]"""
        server.enqueue(responseWithJSON(json, 200))
        return this
    }

    fun willReturnSuccessfulLink(): UsersAPIMockServer {
        val json = """[
          {
            "profileData": {
              "email": "asd@asd.asd",
              "email_verified": true,
              "nickname": "asdasd",
              "username": "asdasd"
            },
            "user_id": "5751d11a85a56dd86c460726",
            "provider": "auth0",
            "connection": "Username-Password-Authentication",
            "isSocial": false
          },
          {
            "profileData": {
              "name": "Asdasd️",
              "picture": "https://pbs.twimg.com/profile_images/some_invalid.jpeg",
              "created_at": "Fri May 20 17:13:23 +0000 2011",
              "description": "Something about us.",
              "lang": "es",
              "location": "Buenos Aires",
              "screen_name": "Aassdd",
              "time_zone": "Buenos Aires",
              "utc_offset": -10800
            },
            "access_token": "302132759-7CqPgySk321gltiQA2r4XC9byqWvxNdSPdM8Wzvu",
            "access_token_secret": "mYL3hcGKr6TrClvddSKapMJqsiSHKPwsdmAaOsdaRRbPYTm",
            "provider": "twitter",
            "user_id": "30303030",
            "connection": "twitter",
            "isSocial": true
          }
        ]"""
        server.enqueue(responseWithJSON(json, 200))
        return this
    }

    fun willReturnUserProfile(): UsersAPIMockServer {
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
          "user_metadata": 
            {
              "name": "name",
              "surname": "surname"
            },
          "created_at": "2014-07-06T18:33:49.005Z",
          "username": "p",
          "updated_at": "2015-09-30T19:43:48.499Z"
        }"""
        server.enqueue(responseWithJSON(json, 200))
        return this
    }

    private fun responseWithJSON(json: String, statusCode: Int): MockResponse {
        return MockResponse()
            .setResponseCode(statusCode)
            .addHeader("Content-Type", "application/json")
            .setBody(json)
    }

    init {
        server.start()
    }
}