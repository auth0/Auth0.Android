package com.auth0.android.util

import okhttp3.mockwebserver.MockResponse

internal class EmbeddedAuthMockServer : APIMockServer() {

    fun willReturnFullDiscovery(): EmbeddedAuthMockServer {
        val json = """
            {
              "alternatives": [
                { "grant_type": "password" },
                {
                  "grant_type": "http://auth0.com/oauth/grant-type/password-realm",
                  "realm": "$PASSWORD_REALM"
                },
                {
                  "grant_type": "urn:okta:params:oauth:grant-type:webauthn",
                  "connection": "$PASSKEY_CONNECTION"
                },
                {
                  "grant_type": "http://auth0.com/oauth/grant-type/passwordless/otp",
                  "connection": "$OTP_EMAIL_CONNECTION",
                  "type": "auth0",
                  "identifier_types": ["email"]
                },
                {
                  "grant_type": "http://auth0.com/oauth/grant-type/passwordless/otp",
                  "connection": "$OTP_SMS_CONNECTION",
                  "identifier_types": ["phone_number"]
                },
                {
                  "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                  "subject_token_type": "$SUBJECT_TOKEN_TYPE"
                },
                {
                  "grant_type": "authorization_code",
                  "type": "embedded_authorize",
                  "connection": "$AUTHORIZE_CONNECTION"
                },
                {
                  "grant_type": "$UNKNOWN_GRANT",
                  "connection": "$UNKNOWN_CONNECTION"
                }
              ]
            }
        """.trimIndent()
        server.enqueue(responseWithJSON(json, 200))
        return this
    }

    fun willReturnEmptyDiscovery(): EmbeddedAuthMockServer {
        server.enqueue(responseWithJSON("""{ "alternatives": [] }""", 200))
        return this
    }

    /** The empty-body 404 returned when embedded authentication is not enabled for the tenant. */
    fun willReturnNotEnabled(): EmbeddedAuthMockServer {
        server.enqueue(MockResponse().setResponseCode(404))
        return this
    }

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
        const val PASSWORD_REALM = "Username-Password-Authentication"
        const val PASSKEY_CONNECTION = "passkey-connection"
        const val OTP_EMAIL_CONNECTION = "email"
        const val OTP_SMS_CONNECTION = "sms"
        const val SUBJECT_TOKEN_TYPE = "http://auth0.com/oauth/token-type/google-id-token"
        const val AUTHORIZE_CONNECTION = "google-oauth2"
        const val UNKNOWN_GRANT = "urn:example:params:oauth:grant-type:future"
        const val UNKNOWN_CONNECTION = "future-connection"
        const val PLAIN_TEXT_ERROR = "Internal Server Error"
        const val ERROR_CODE = "invalid_request"
        const val ERROR_DESCRIPTION = "The connection was not found."
        const val AUTH_SESSION = "auth-session-token"
        const val ROTATED_AUTH_SESSION = "auth-session-token-rotated"

        // Prebuilt action JSON fragments for willReturnContinuationWith().
        const val NEXT_IDENTIFY_EMAIL = """{ "action": "action:identify:email:v1" }"""
        const val NEXT_IDENTIFY_PHONE = """{ "action": "action:identify:phone:v1" }"""
        const val NEXT_CHALLENGE_EMAIL = """{ "action": "action:challenge:email:v1", "index": 1, "identifier": "jane@example.com" }"""
        const val NEXT_VERIFY_OTP = """{ "action": "action:verify:otp:v1", "channel": "email", "identifier": "jane@example.com" }"""
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
