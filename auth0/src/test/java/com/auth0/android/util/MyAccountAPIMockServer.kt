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

    fun willReturnPasswordEnrollmentChallenge(): MyAccountAPIMockServer {
        val json = """
            {
              "id": "$PASSWORD_METHOD_ID",
              "auth_session": "$SESSION_ID",
              "policy": {
                "complexity": {
                  "min_length": 8,
                  "character_types": ["uppercase", "lowercase", "number", "special"],
                  "character_type_rule": "three_of_four",
                  "identical_characters": "block",
                  "sequential_characters": "block",
                  "max_length_exceeded": "error"
                },
                "profile_data": {
                  "active": true,
                  "blocked_fields": ["name", "email"]
                },
                "history": {
                  "active": true,
                  "size": 5
                },
                "dictionary": {
                  "active": true,
                  "default": "en_10k"
                }
              }
            }
        """.trimIndent()
        server.enqueue(responseWithJSON(json, 202))
        return this
    }

    fun willReturnPasswordAuthenticationMethod(): MyAccountAPIMockServer {
        val json = """
            {
              "id": "$PASSWORD_METHOD_ID",
              "type": "password",
              "created_at": "2023-06-15T14:30:25.000Z",
              "usage": ["authentication"],
              "identity_user_id": "user_98765432",
              "last_password_reset": "2023-06-15T14:30:25.000Z"
            }
        """.trimIndent()
        server.enqueue(responseWithJSON(json, 201))
        return this
    }

    fun willReturnErrorForBadRequest(): MyAccountAPIMockServer {
        val responseBody = """
        {
            "type": "validation_error",
            "status": 400,
            "title": "Bad Request",
            "detail": "The provided data contains validation errors",
            "validation_errors": [
                {
                    "detail": "Invalid attestation object format",
                    "field": "authn_response.response.attestationObject",
                    "pointer": "/authn_response/response/attestationObject",
                    "source": "request"
                }
            ]
        }
        """
        server.enqueue(responseWithJSON(responseBody, 400))
        return this
    }

    fun willReturnUnauthorizedError(): MyAccountAPIMockServer {
        val responseBody = """
            {
            "type": "unauthorized_error",
            "status": 401,
            "title": "Unauthorized",
            "detail": "The access token is invalid or has expired",
            "validation_errors": null
        }
        """.trimIndent()
        server.enqueue(responseWithJSON(responseBody, 401))
        return this
    }

    fun willReturnForbiddenError(): MyAccountAPIMockServer {
        val responseBody = """
            {
             "type": "access_denied",
            "status": 403,
            "title": "Forbidden",
            "detail": "You do not have permission to perform this operation",
            "validation_errors": null
        }
        """.trimIndent()
        server.enqueue(responseWithJSON(responseBody, 403))
        return this
    }

    private companion object {
        private const val SESSION_ID = "SESSION_ID"
        private const val CHALLENGE = "CHALLENGE"
        private const val PASSWORD_METHOD_ID = "password|123"
    }
}