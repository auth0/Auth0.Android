package com.auth0.sample.embedded

import com.auth0.android.request.NetworkingClient
import com.auth0.android.request.RequestOptions
import com.auth0.android.request.ServerResponse
import java.io.ByteArrayInputStream
import java.util.Collections

/**
 * A [NetworkingClient] that fakes the embedded-authentication endpoints so the sample runs with no
 * live tenant. Wired in via `Auth0.networkingClient`; the production `:auth0` code is untouched.
 *
 * The step is derived from the request itself — the `action` parameter the SDK attaches — so the
 * fake needs no state of its own:
 *
 * ```
 * authorize()      -> 403, offers identify:email
 * identifyEmail()  -> 403, offers challenge:email
 * challenge()      -> 403, offers verify:otp
 * verifyOtp("123456") -> 200 authorization_code -> /oauth/token -> Credentials
 * verifyOtp(other)    -> 403, offers verify:otp again
 * ```
 *
 * Every response carries `Content-Type: application/json` so the SDK routes the 403 bodies through
 * its JSON error parser (that is what surfaces the `next` menu on the exception).
 */
internal class FakeAuthorizeClient : NetworkingClient {

    /** One response the fake served, captured so the UI can display the raw mock data. */
    data class Exchange(val endpoint: String, val statusCode: Int, val body: String)

    // load() runs on the SDK's network executor; reads happen on the main thread — keep it safe.
    private val exchanges: MutableList<Exchange> = Collections.synchronizedList(mutableListOf())

    /** The responses served so far, oldest first. */
    val log: List<Exchange>
        get() = synchronized(exchanges) { exchanges.toList() }

    /** Drops the recorded responses, e.g. when the flow is restarted. */
    fun clearLog() {
        synchronized(exchanges) { exchanges.clear() }
    }

    override fun load(url: String, options: RequestOptions): ServerResponse {
        val isToken = url.endsWith(TOKEN_PATH)
        val (statusCode, body) = if (isToken) {
            200 to FakeAuthorizeData.credentialsBody
        } else {
            respondToAuthorize(options)
        }
        exchanges.add(Exchange(if (isToken) TOKEN_PATH else AUTHORIZE_PATH, statusCode, body))
        return jsonResponse(statusCode, body)
    }

    private fun respondToAuthorize(options: RequestOptions): Pair<Int, String> {
        return when (options.parameters[ACTION_KEY] as? String) {
            null -> 403 to FakeAuthorizeData.identifyBody
            ACTION_IDENTIFY_EMAIL -> 403 to FakeAuthorizeData.challengeOfferBody
            ACTION_CHALLENGE_EMAIL -> 403 to FakeAuthorizeData.verifyOtpBody
            ACTION_VERIFY_OTP ->
                if (options.parameters[OTP_KEY] == FakeAuthorizeData.EXPECTED_OTP) {
                    200 to FakeAuthorizeData.authorizationCodeBody
                } else {
                    403 to FakeAuthorizeData.invalidOtpBody
                }
            else -> 400 to UNSUPPORTED_ACTION_BODY
        }
    }

    private fun jsonResponse(statusCode: Int, body: String): ServerResponse = ServerResponse(
        statusCode,
        ByteArrayInputStream(body.toByteArray(Charsets.UTF_8)),
        mapOf(CONTENT_TYPE_HEADER to listOf(APPLICATION_JSON))
    )

    private companion object {
        private const val TOKEN_PATH = "/oauth/token"
        private const val AUTHORIZE_PATH = "/e/authorize"
        private const val ACTION_KEY = "action"
        private const val OTP_KEY = "otp"

        private const val ACTION_IDENTIFY_EMAIL = "action:identify:email:v1"
        private const val ACTION_CHALLENGE_EMAIL = "action:challenge:email:v1"
        private const val ACTION_VERIFY_OTP = "action:verify:otp:v1"

        private const val CONTENT_TYPE_HEADER = "Content-Type"
        private const val APPLICATION_JSON = "application/json"

        private const val UNSUPPORTED_ACTION_BODY =
            """{"error":"invalid_request","error_description":"Unsupported action."}"""
    }
}
