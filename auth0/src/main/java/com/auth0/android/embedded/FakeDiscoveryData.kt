package com.auth0.android.embedded

/**
 * Canned `GET /e/discovery` response covering all six wire variants, served as a `200` body by
 * [FakeDiscoveryClient]. Remove both once the server populates the response.
 */
internal object FakeDiscoveryData {

    /**
     * In the emission order the RFD fixes: `authorization_code`, token-exchange, `password`,
     * `webauthn`, `passwordless/otp`, `password-realm`, then connection name ascending within a grant
     * type. That order matters — clients render in it and the server truncates from the end — so this
     * follows it rather than the ordering used by the OpenAPI sample.
     */
    const val SUCCESS_RESPONSE: String = """
{
  "alternatives": [
    {
      "grant_type": "authorization_code",
      "type": "embedded_authorize",
      "connection": "google-oauth2"
    },
    {
      "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
      "subject_token_type": "http://auth0.com/oauth/token-type/google-id-token"
    },
    { "grant_type": "password" },
    {
      "grant_type": "urn:okta:params:oauth:grant-type:webauthn",
      "connection": "Username-Password-Authentication"
    },
    {
      "grant_type": "http://auth0.com/oauth/grant-type/passwordless/otp",
      "type": "auth0",
      "connection": "Username-Password-Authentication",
      "identifier_types": ["email", "phone_number"]
    },
    {
      "grant_type": "http://auth0.com/oauth/grant-type/passwordless/otp",
      "type": "legacy",
      "connection": "email",
      "identifier_types": ["email"]
    },
    {
      "grant_type": "http://auth0.com/oauth/grant-type/password-realm",
      "realm": "Username-Password-Authentication"
    }
  ]
}
"""
}
