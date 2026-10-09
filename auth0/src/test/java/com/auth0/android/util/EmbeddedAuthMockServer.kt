package com.auth0.android.util

import okhttp3.mockwebserver.MockResponse

internal class EmbeddedAuthMockServer : APIMockServer() {

    fun willReturnPlainTextError(): EmbeddedAuthMockServer {
        server.enqueue(
            MockResponse()
                .setResponseCode(500)
                .addHeader("Content-Type", "text/plain")
                .setBody(PLAIN_TEXT_ERROR)
        )
        return this
    }

    fun willReturnJsonError(): EmbeddedAuthMockServer {
        val json = """
            {
              "error": "$ERROR_CODE",
              "error_description": "$ERROR_DESCRIPTION"
            }
        """.trimIndent()
        server.enqueue(responseWithJSON(json, 400))
        return this
    }

    /** The `403 insufficient_authorization` continuation that carries the rotated session and next step. */
    fun willReturnInsufficientAuthorization(
        authSession: String = AUTH_SESSION
    ): EmbeddedAuthMockServer {
        val json = """
            {
              "error": "insufficient_authorization",
              "error_description": "The flow is not complete.",
              "auth_session": "$authSession",
              "next": [
                { "action": "action:verify:otp:v1", "channel": "email", "identifier": "$IDENTIFIER" }
              ]
            }
        """.trimIndent()
        server.enqueue(responseWithJSON(json, 403))
        return this
    }

    fun willReturnContinuationWith(vararg actions: String, authSession: String = AUTH_SESSION): EmbeddedAuthMockServer {
        val actionsJson = actions.joinToString(",\n") { "        $it" }
        val json = """
            {
              "error": "insufficient_authorization",
              "error_description": "The flow is not complete.",
              "auth_session": "$authSession",
              "next": [
$actionsJson
              ]
            }
        """.trimIndent()
        server.enqueue(responseWithJSON(json, 403))
        return this
    }

    fun willReturnAccessDenied(): EmbeddedAuthMockServer {
        server.enqueue(responseWithJSON("""{ "error": "access_denied", "error_description": "Access denied." }""", 403))
        return this
    }

    fun willReturnInvalidCode(): EmbeddedAuthMockServer {
        server.enqueue(
            responseWithJSON(
                """{ "error": "insufficient_authorization", "error_description": "invalid_code", "auth_session": "$ROTATED_AUTH_SESSION", "next": [ $NEXT_VERIFY_OTP ] }""",
                403
            )
        )
        return this
    }

    fun willReturnInvalidPassword(): EmbeddedAuthMockServer {
        server.enqueue(
            responseWithJSON(
                """{ "error": "insufficient_authorization", "error_description": "invalid_identifier_or_password", "auth_session": "$ROTATED_AUTH_SESSION", "next": [ $NEXT_VERIFY_PASSWORD ] }""",
                403
            )
        )
        return this
    }

    fun willReturnTooManyWrongOtpAttempts(): EmbeddedAuthMockServer {
        server.enqueue(responseWithJSON("""{ "error": "access_denied", "error_description": "too_many_wrong_otp_attempts" }""", 403))
        return this
    }

    fun willReturnChallengeExpired(): EmbeddedAuthMockServer {
        server.enqueue(responseWithJSON("""{ "error": "access_denied", "error_description": "challenge_expired" }""", 403))
        return this
    }

    fun willReturnTooManyAttempts(): EmbeddedAuthMockServer {
        server.enqueue(responseWithJSON("""{ "error": "too_many_requests", "error_description": "too_many_attempts" }""", 429))
        return this
    }

    fun willReturnTooManyLogins(): EmbeddedAuthMockServer {
        server.enqueue(responseWithJSON("""{ "error": "too_many_requests", "error_description": "too_many_logins" }""", 429))
        return this
    }

    /** An `invalid_grant` returned by `/e/authorize` continuation (expired `auth_session`). */
    fun willReturnInvalidGrant(description: String = "The auth_session has expired."): EmbeddedAuthMockServer {
        server.enqueue(responseWithJSON("""{ "error": "invalid_grant", "error_description": "$description" }""", 400))
        return this
    }

    /** The `200` that ends `/e/authorize`, carrying the code to exchange for tokens. */
    fun willReturnAuthorizeCode(): EmbeddedAuthMockServer {
        server.enqueue(responseWithJSON("""{ "authorization_code": "$AUTHORIZATION_CODE" }""", 200))
        return this
    }

    /** A standard token response, including an `id_token`. */
    fun willReturnTokens(): EmbeddedAuthMockServer {
        val json = """
            {
              "access_token": "$ACCESS_TOKEN",
              "id_token": "$ID_TOKEN",
              "token_type": "Bearer",
              "expires_in": 86400,
              "scope": "openid profile email"
            }
        """.trimIndent()
        server.enqueue(responseWithJSON(json, 200))
        return this
    }

    /** A `200` token response missing `id_token` — reproduces the openid-less exchange failure. */
    fun willReturnTokensWithoutIdToken(): EmbeddedAuthMockServer {
        val json = """
            {
              "access_token": "$ACCESS_TOKEN",
              "token_type": "Bearer",
              "expires_in": 86400,
              "scope": "profile email"
            }
        """.trimIndent()
        server.enqueue(responseWithJSON(json, 200))
        return this
    }

    companion object {
        const val AUTHORIZE_CONNECTION = "google-oauth2"
        const val PLAIN_TEXT_ERROR = "Internal Server Error"
        const val ERROR_CODE = "invalid_request"
        const val ERROR_DESCRIPTION = "The connection was not found."
        const val AUTH_SESSION = "auth-session-token"
        const val ROTATED_AUTH_SESSION = "auth-session-token-rotated"

        // Prebuilt action JSON fragments for willReturnContinuationWith().
        const val NEXT_IDENTIFY_EMAIL = """{ "action": "action:identify:email:v1" }"""
        const val NEXT_IDENTIFY_PHONE = """{ "action": "action:identify:phone:v1" }"""
        const val NEXT_IDENTIFY_USERNAME = """{ "action": "action:identify:username:v1" }"""
        const val NEXT_VERIFY_PASSWORD = """{ "action": "action:verify:password:v1" }"""
        const val NEXT_CHALLENGE_EMAIL = """{ "action": "action:challenge:email:v1", "index": 1, "identifier": "jane@example.com" }"""
        const val NEXT_CHALLENGE_PHONE = """{ "action": "action:challenge:phone:v1", "index": 0, "identifier": "+1234567890", "delivery_methods": ["text", "voice"] }"""
        const val NEXT_CHALLENGE_PUSH = """{ "action": "action:challenge:push:v1", "index": 0, "name": "My Phone" }"""
        const val NEXT_VERIFY_OTP = """{ "action": "action:verify:otp:v1", "channel": "email", "identifier": "jane@example.com" }"""
        const val NEXT_VERIFY_OTP_SMS = """{ "action": "action:verify:otp:v1", "channel": "sms", "identifier": "+1234567890" }"""
        const val NEXT_VERIFY_OOB = """{ "action": "action:verify:oob:v1", "poll_in_ms": 5000 }"""
        const val NEXT_VERIFY_RECOVERY_CODE = """{ "action": "action:verify:recovery-code:v1" }"""
        const val NEXT_CONFIRM_RECOVERY_CODE = """{ "action": "action:confirm:recovery-code:v1", "new_code": "NEW-CODE-XYZ" }"""
        const val NEXT_VERIFY_OTP_UNKNOWN_CHANNEL = """{ "action": "action:verify:otp:v1", "channel": "carrier-pigeon", "identifier": "jane@example.com" }"""
        const val NEXT_VERIFY_OTP_NO_CHANNEL = """{ "action": "action:verify:otp:v1", "identifier": "jane@example.com" }"""
        const val NEXT_VERIFY_OTP_MIXED_CASE_CHANNEL = """{ "action": "action:verify:otp:v1", "channel": "SmS", "identifier": "jane@example.com" }"""
        const val NEXT_CHALLENGE_EMAIL_NO_IDENTIFIER = """{ "action": "action:challenge:email:v1", "index": 1 }"""
        const val NEXT_CHALLENGE_EMAIL_NO_INDEX = """{ "action": "action:challenge:email:v1", "identifier": "jane@example.com" }"""
        const val NEXT_UNKNOWN = """{ "action": "action:future:unknown:v1" }"""
        const val IDENTIFIER = "jane@example.com"
        const val AUTHORIZATION_CODE = "the-authorization-code"
        const val ACCESS_TOKEN = "the-access-token"
        const val ID_TOKEN = "the-id-token"
    }
}
