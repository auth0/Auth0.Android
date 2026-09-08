package com.auth0.sample.embedded

/**
 * Canned `/e/authorize` and `/oauth/token` payloads for the mocked embedded-authentication flow.
 *
 * The real endpoints are not live yet, so [FakeAuthorizeClient] replays these to drive the loop:
 * an initial `authorize()` and each continuation short of the last fail with HTTP 403
 * `insufficient_authorization` (carrying a fresh `auth_session` and the `next` menu); verifying the
 * expected code succeeds with an `authorization_code`, which the SDK then exchanges at
 * `/oauth/token` for the [credentialsBody] tokens.
 *
 * Per the spec (RFD "Embedded Authorize — Delivery 2", decision #10) `error_description` is **not** a
 * free-form message: it is an optional, server-owned, closed snake_case enum, and it is **absent** on
 * the normal progression responses. It only appears on recoverable/terminal outcomes:
 * `invalid_identifier_or_code`, `too_many_wrong_otp_attempts`, `consent_required`.
 */
internal object FakeAuthorizeData {

    /** The one code the mock accepts. Anything else re-offers the OTP step. */
    const val EXPECTED_OTP: String = "123456"

    /** Step 1 — the server asks the user to identify themselves by email. */
    val identifyBody: String = continuation(
        session = "sess-identify",
        next = """[{"action":"action:identify:email:v1"}]"""
    )

    /** Step 2 — the server offers to send an email challenge. */
    val challengeOfferBody: String = continuation(
        session = "sess-challenge",
        next = """[{"action":"action:challenge:email:v1"}]"""
    )

    /** Step 3 — the code has been sent; the server waits for it to be verified. */
    val verifyOtpBody: String = continuation(
        session = "sess-verify",
        next = VERIFY_OTP_NEXT
    )

    /**
     * Step 3 (retry) — the submitted code was wrong. The spec deliberately collapses "wrong code"
     * and "unknown user" into one recoverable code so the SDK cannot disambiguate them.
     */
    val invalidOtpBody: String = continuation(
        session = "sess-verify",
        next = VERIFY_OTP_NEXT,
        errorDescription = "invalid_identifier_or_code"
    )

    /** Terminal success of `/e/authorize`: the code to exchange for tokens. */
    val authorizationCodeBody: String = """{"authorization_code":"embedded-auth-code-abc123"}"""

    /**
     * `/oauth/token` success. Copied verbatim from `auth0/src/test/resources/credentials_openid.json`
     * so the SDK's `CredentialsDeserializer` produces a real [com.auth0.android.result.Credentials].
     */
    val credentialsBody: String = """
        {
          "id_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL3NhbXBsZXMuYXV0aDAuY29tLyIsInN1YiI6ImF1dGgwfDUzYjk5NWY4YmNlNjhkOWZjOTAwMDk5YyIsImF1ZCI6Ikk5bWhVcmZrVEdGVldqbEVxWlNUQ0JVRkFCTGJKRkdMMyIsImV4cCI6MTQ2NTEwOTAzMywiaWF0IjoxNDY1MDczMDMzfQ.TdRc-lnVcX0LT7ZySzVysjVcYzAUIRnCPufTO8VV6g8",
          "access_token": "s6GS5FGJN2jfd4l6",
          "token_type": "bearer",
          "expires_in": 86000
        }
    """.trimIndent()

    /** The `verify:otp` menu entry, including the spec's masked delivery destination. */
    private const val VERIFY_OTP_NEXT =
        """[{"action":"action:verify:otp:v1","channel":"email","identifier":"jame*@jame*****"}]"""

    /**
     * Builds an `insufficient_authorization` continuation. [errorDescription] is omitted entirely
     * unless given, mirroring the spec's optional, enum-only `error_description`.
     */
    private fun continuation(
        session: String,
        next: String,
        errorDescription: String? = null
    ): String {
        val descriptionLine =
            errorDescription?.let { """"error_description": "$it",""" + "\n          " }.orEmpty()
        return """
            {
              "error": "insufficient_authorization",
              $descriptionLine"auth_session": "$session",
              "next": $next
            }
        """.trimIndent()
    }
}
