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
              "id": "$PASSWORD_VERIFIED_METHOD_ID",
              "type": "password",
              "created_at": "2023-06-15T14:30:25.000Z",
              "usage": ["primary"],
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

    fun willReturnUserProfile(): MyAccountAPIMockServer {
        val json = """
            {
              "user_id": "auth0|123",
              "given_name": "Jane",
              "family_name": "Doe",
              "name": "Jane Doe",
              "nickname": "jane",
              "picture": "https://example.com/jane.png",
              "email": "jane@example.com",
              "email_verified": true,
              "phone_number": "+15555550100",
              "phone_verified": false,
              "username": "janedoe",
              "created_at": "2026-01-01T00:00:00.000Z",
              "updated_at": "2026-02-01T00:00:00.000Z",
              "profile_policy": {
                "/given_name": {
                  "access": "read_only",
                  "source": "idp",
                  "reason": "managed_by_identity_provider"
                },
                "/nickname": {
                  "access": "read_write",
                  "source": "user"
                },
                "/created_at": {
                  "access": "read_only",
                  "source": "system",
                  "reason": "system_managed"
                }
              }
            }
        """.trimIndent()
        server.enqueue(responseWithJSON(json, 200))
        return this
    }

    fun willReturnUserProfileWithoutPolicy(): MyAccountAPIMockServer {
        val json = """
            {
              "given_name": "Jane",
              "picture": "https://example.com/jane.png"
            }
        """.trimIndent()
        server.enqueue(responseWithJSON(json, 200))
        return this
    }

    fun willReturnUserProfileWithUnknownPolicyValues(): MyAccountAPIMockServer {
        val json = """
            {
              "given_name": "Jane",
              "profile_policy": {
                "/given_name": {
                  "access": "write_only",
                  "source": "partner",
                  "reason": "some_new_reason"
                }
              }
            }
        """.trimIndent()
        server.enqueue(responseWithJSON(json, 200))
        return this
    }

    fun willReturnFeatureNotEnabledError(): MyAccountAPIMockServer {
        val responseBody = """
            {
              "type": "https://auth0.com/api-errors/A0E-403-0003",
              "status": 403,
              "title": "Not Entitled",
              "detail": "This feature is currently not enabled"
            }
        """.trimIndent()
        server.enqueue(responseWithJSON(responseBody, 403))
        return this
    }

    fun willReturnProfileValidationError(): MyAccountAPIMockServer {
        val responseBody = """
            {
              "type": "https://auth0.com/api-errors/A0E-400-0008",
              "status": 400,
              "title": "read_only_field",
              "detail": "The field '/given_name' is read-only because it is managed by the identity provider.",
              "validation_errors": [
                {
                  "detail": "given_name is managed by the identity provider",
                  "pointer": "/given_name",
                  "source": "managed_by_identity_provider"
                }
              ]
            }
        """.trimIndent()
        server.enqueue(responseWithJSON(responseBody, 400))
        return this
    }

    private companion object {
        private const val SESSION_ID = "SESSION_ID"
        private const val CHALLENGE = "CHALLENGE"
        private const val PASSWORD_METHOD_ID = "password|new"
        private const val PASSWORD_VERIFIED_METHOD_ID = "password|pwd_a1b2c3d4e5f6"
    }
}