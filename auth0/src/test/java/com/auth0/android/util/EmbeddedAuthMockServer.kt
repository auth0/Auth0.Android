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
    }
}
