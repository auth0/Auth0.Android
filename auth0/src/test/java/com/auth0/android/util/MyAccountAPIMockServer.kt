package com.auth0.android.util

internal class MyAccountAPIMockServer : APIMockServer() {


    fun willReturnPasskeyChallengeWithoutHeader(): MyAccountAPIMockServer {
        val json = """
            {
              "auth_session": "$SESSION_ID",
              "authn_params_public_key": {
                "authenticatorSelection": {
                  "residentKey": "required",
                  "userVerification": "preferred"
                },
                "challenge": "$CHALLENGE",
                "pubKeyCredParams": [
                  {
                    "alg": -7,
                    "type": "public-key"
                  },
                  {
                    "alg": -257,
                    "type": "public-key"
                  }
                ],
                "rp": {
                  "id": "example.auth0.com",
                  "name": "Example Application"
                },
                "timeout": 60000,
                "user": {
                  "displayName": "John Doe",
                  "id": "dXNlcklkUmFuZG9tQnl0ZXNFbmNvZGVkSW5CYXNlNjQ=",
                  "name": "johndoe@example.com"
                }
              }
            }
        """.trimIndent()
        server.enqueue(responseWithJSON(json, 200))
        return this
    }

    fun willReturnPasskeyChallenge(): MyAccountAPIMockServer {
        val json = """
            {
              "auth_session": "$SESSION_ID",
              "authn_params_public_key": {
                "authenticatorSelection": {
                  "residentKey": "required",
                  "userVerification": "preferred"
                },
                "challenge": "$CHALLENGE",
                "pubKeyCredParams": [
                  {
                    "alg": -7,
                    "type": "public-key"
                  },
                  {
                    "alg": -257,
                    "type": "public-key"
                  }
                ],
                "rp": {
                  "id": "rpId",
                  "name": "rpName"
                },
                "timeout": 60000,
                "user": {
                  "displayName": "John Doe",
                  "id": "dXNlcklkUmFuZG9tQnl0ZXNFbmNvZGVkSW5CYXNlNjQ=",
                  "name": "johndoe@example.com"
                }
              }
            }
        """.trimIndent()
        server.enqueue(responseWithJSON(json, 200, mapOf("location" to "passkey|new")))
        return this
    }

    fun willReturnPasskeyAuthenticationMethod(): MyAccountAPIMockServer {
        val json = """
            {
              "created_at": "2023-06-15T14:30:25.000Z",
              "credential_backed_up": true,
              "credential_device_type": "phone",
              "id": "auth_method_123456789",
              "identity_user_id": "user_98765432",
              "key_id": "key_abcdef1234567890",
              "public_key": "publickey",
              "transports": ["internal"],
              "type": "passkey",
              "user_agent": "Android",
              "user_handle": "userHandle"
            }
        """.trimIndent()
        server.enqueue(responseWithJSON(json, 200))
        return this
    }

   private companion object {
        const val REFRESH_TOKEN = "REFRESH_TOKEN"
        const val ID_TOKEN = "ID_TOKEN"
        const val ACCESS_TOKEN = "ACCESS_TOKEN"
        const val SESSION_ID = "SESSION_ID"
        private const val BEARER = "BEARER"
        private const val CHALLENGE = "CHALLENGE"
    }
}