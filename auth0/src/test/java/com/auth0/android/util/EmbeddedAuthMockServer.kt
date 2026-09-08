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

    /** A `403 insufficient_authorization` continuation carrying a fresh session and a `next` menu. */
    fun willReturnContinuation(
        session: String,
        next: String,
        description: String = "Another step is required."
    ): EmbeddedAuthMockServer {
        val json = """
            {
              "error": "insufficient_authorization",
              "error_description": "$description",
              "auth_session": "$session",
              "next": $next
            }
        """.trimIndent()
        server.enqueue(responseWithJSON(json, 403))
        return this
    }

    /** The `200` that ends `/e/authorize`: the code to exchange for tokens. */
    fun willReturnAuthorizationCode(code: String = AUTHORIZATION_CODE): EmbeddedAuthMockServer {
        server.enqueue(responseWithJSON("""{ "authorization_code": "$code" }""", 200))
        return this
    }

    /** The `/oauth/token` success exchanged for [com.auth0.android.result.Credentials]. */
    fun willReturnTokens(): EmbeddedAuthMockServer {
        val json = """
            {
              "id_token": "$ID_TOKEN",
              "access_token": "$ACCESS_TOKEN",
              "token_type": "$TOKEN_TYPE",
              "expires_in": 86000
            }
        """.trimIndent()
        server.enqueue(responseWithJSON(json, 200))
        return this
    }

    /** A terminal `403 access_denied` (no `next` menu). */
    fun willReturnAccessDenied(): EmbeddedAuthMockServer {
        val json = """
            {
              "error": "access_denied",
              "error_description": "The user was denied access."
            }
        """.trimIndent()
        server.enqueue(responseWithJSON(json, 403))
        return this
    }

    companion object {
        const val SESSION_IDENTIFY = "sess-identify"
        const val SESSION_CHALLENGE = "sess-challenge"
        const val SESSION_VERIFY = "sess-verify"
        const val AUTHORIZATION_CODE = "embedded-auth-code-abc123"
        const val ACCESS_TOKEN = "s6GS5FGJN2jfd4l6"
        const val TOKEN_TYPE = "Bearer"

        // A decodable HS256 JWT (from credentials_openid.json) so CredentialsDeserializer succeeds.
        const val ID_TOKEN =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL3NhbXBsZXMuYXV0aDAuY29tLyIsInN1YiI6ImF1dGgwfDUzYjk5NWY4YmNlNjhkOWZjOTAwMDk5YyIsImF1ZCI6Ikk5bWhVcmZrVEdGVldqbEVxWlNUQ0JVRkFCTGJKRkdMMyIsImV4cCI6MTQ2NTEwOTAzMywiaWF0IjoxNDY1MDczMDMzfQ.TdRc-lnVcX0LT7ZySzVysjVcYzAUIRnCPufTO8VV6g8"

        const val NEXT_IDENTIFY_EMAIL = """[{"action":"action:identify:email:v1"}]"""
        const val NEXT_CHALLENGE_EMAIL = """[{"action":"action:challenge:email:v1"}]"""
        const val NEXT_VERIFY_OTP =
            """[{"action":"action:verify:otp:v1","channel":"email","identifier":"a***@example.com"}]"""

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
    }
}
