package com.auth0.android.util

import okhttp3.mockwebserver.MockResponse

internal class AuthenticationAPIMockServer : APIMockServer() {

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

    fun willReturnSuccessfulLogin(idToken: String = ID_TOKEN): AuthenticationAPIMockServer {
        val json = """{
          "refresh_token": "$REFRESH_TOKEN",
          "id_token": "$idToken",
          "access_token": "$ACCESS_TOKEN",
          "token_type": "$BEARER",
          "expires_in": 86000
        }"""
        server.enqueue(responseWithJSON(json, 200))
        return this
    }

    fun willReturnSuccessfulPasskeyRegistration(): AuthenticationAPIMockServer {
        val json = """{
            "authn_params_public_key":{
                "challenge": "$CHALLENGE",
                "timeout": 6046456,
                "rp": {
                    "id": "auth0.passkey.com",
                    "name": "Passkey Test"
                },
                "pubKeyCredParams": [
                    {
                        "type": "public-key",
                        "alg": -7
                    },
                    {
                        "type": "public-key",
                        "alg": -257
                    }
                ],
                "authenticatorSelection": {
                    "authenticatorAttachment": "platform",
                    "residentKey": "required"
                },
                "user": {
                       "id": "53b995f8bce68d9fc900099c",
                       "name": "p",
                       "displayName": "d"
                   }
                },
                 "auth_session": "$SESSION_ID"
            }"""
        server.enqueue(responseWithJSON(json, 200))
        return this
    }

    fun willReturnSuccessfulPasskeyChallenge():AuthenticationAPIMockServer{
        val json = """{
            "authn_params_public_key":{
                "challenge": "$CHALLENGE",
                "timeout": 604645,
                "rpId": "domain",
                "userVerification":"preferred"
                },
                 "auth_session": "$SESSION_ID"
            }"""
        server.enqueue(responseWithJSON(json, 200))
        return this
    }

    fun willReturnSuccessfulLoginWithRecoveryCode(): AuthenticationAPIMockServer {
        val json = """{
          "refresh_token": "$REFRESH_TOKEN",
          "id_token": "$ID_TOKEN",
          "access_token": "$ACCESS_TOKEN",
          "token_type": "$BEARER",
          "expires_in": 86000,
          "recovery_code": "654321"
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
            // Use classloader to load resource file - works regardless of working directory
            val inputStream = this::class.java.classLoader?.getResourceAsStream("rsa_jwks.json")
                ?: throw IllegalStateException("Could not find rsa_jwks.json in test resources")
            val json = inputStream.bufferedReader().use { it.readText() }
            server.enqueue(responseWithJSON(json, 200))
        } catch (e: Exception) {
            println("File parsing error: ${e.message}")
            throw e
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
          "token_type": "Bearer",
          "expires_in": 86000
        }"""
        server.enqueue(responseWithJSON(json, 200))
        return this
    }

    fun willReturnSuccessfulMFAChallenge(): AuthenticationAPIMockServer {
        val json = """{
          "challenge_type":"oob",
          "binding_method":"prompt",
          "oob_code": "abcdefg"
        }"""
        server.enqueue(responseWithJSON(json, 200))
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

    companion object {
        const val REFRESH_TOKEN = "REFRESH_TOKEN"
        const val ID_TOKEN = "ID_TOKEN"
        const val ACCESS_TOKEN = "ACCESS_TOKEN"
        const val SESSION_ID = "SESSION_ID"
        private const val BEARER = "Bearer"
        private const val CHALLENGE = "CHALLENGE"
    }
}